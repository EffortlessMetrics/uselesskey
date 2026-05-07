//! Effortless Metrics policy stack: no-panic, file-policy, lint-policy.
//!
//! See `docs/CLIPPY_POLICY.md`, `docs/NO_PANIC_POLICY.md`, `docs/FILE_POLICY.md`,
//! and `docs/POLICY_ALLOWLISTS.md`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use chrono::NaiveDate;
use regex::Regex;
use serde::{Deserialize, Serialize};

const NO_PANIC_TOML: &str = "policy/no-panic-allowlist.toml";
const NON_RUST_TOML: &str = "policy/non-rust-allowlist.toml";
const CLIPPY_LINTS_TOML: &str = "policy/clippy-lints.toml";
const CLIPPY_DEBT_TOML: &str = "policy/clippy-debt.toml";

const TARGET_DIR: &str = "target";
const PROPOSED_DIR: &str = "target/policy-proposed";

// =============================================================================
// Glob matching (forward-slash, supports **, *, ?)
// =============================================================================

fn glob_to_regex(glob: &str) -> Regex {
    let mut re = String::from("^");
    let mut chars = glob.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => {
                if chars.peek() == Some(&'*') {
                    chars.next();
                    // consume optional trailing '/'
                    if chars.peek() == Some(&'/') {
                        chars.next();
                        re.push_str("(?:.*/)?");
                    } else {
                        re.push_str(".*");
                    }
                } else {
                    re.push_str("[^/]*");
                }
            }
            '?' => re.push_str("[^/]"),
            '.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '[' | ']' | '\\' => {
                re.push('\\');
                re.push(c);
            }
            _ => re.push(c),
        }
    }
    re.push('$');
    Regex::new(&re).expect("valid generated regex")
}

fn glob_match(glob: &str, path: &str) -> bool {
    glob_to_regex(glob).is_match(path)
}

// =============================================================================
// Common helpers
// =============================================================================

fn read_toml<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    toml::from_str(&raw).with_context(|| format!("parse {path}"))
}

fn git_ls_files() -> Result<Vec<String>> {
    let out = Command::new("git")
        .args(["ls-files"])
        .output()
        .context("git ls-files")?;
    if !out.status.success() {
        bail!("git ls-files exited with {:?}", out.status);
    }
    let s = String::from_utf8(out.stdout).context("git ls-files: utf-8")?;
    Ok(s.lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

fn write_outputs(name: &str, json: &serde_json::Value, markdown: &str) -> Result<()> {
    fs::create_dir_all(TARGET_DIR).ok();
    let json_path = format!("{TARGET_DIR}/{name}.json");
    let md_path = format!("{TARGET_DIR}/{name}.md");
    fs::write(&json_path, serde_json::to_string_pretty(json)?)
        .with_context(|| format!("write {json_path}"))?;
    fs::write(&md_path, markdown).with_context(|| format!("write {md_path}"))?;
    Ok(())
}

fn today() -> NaiveDate {
    chrono::Utc::now().date_naive()
}

// =============================================================================
// no-panic allowlist
// =============================================================================

#[derive(Debug, Deserialize)]
struct NoPanicConfig {
    #[expect(
        dead_code,
        reason = "schema validation; surfaced in policy reports later"
    )]
    #[serde(default)]
    schema_version: Option<String>,
    #[serde(default)]
    policy: NoPanicPolicy,
    #[serde(default)]
    allow: Vec<NoPanicAllow>,
}

#[derive(Debug, Default, Deserialize)]
struct NoPanicPolicy {
    // `families` is part of the schema and parsed for validation; the scanner
    // currently scans all known families.
    #[expect(
        dead_code,
        reason = "schema validation; consumed once families become tunable"
    )]
    #[serde(default)]
    families: Vec<String>,
    #[serde(default = "default_no_panic_mode")]
    mode: String,
}

fn default_no_panic_mode() -> String {
    "advisory".into()
}

#[derive(Debug, Deserialize)]
#[expect(dead_code, reason = "schema fields preserved for surfacing in reports")]
struct NoPanicAllow {
    id: String,
    path: String,
    family: String,
    classification: String,
    owner: String,
    #[serde(default)]
    explanation: Option<String>,
    expires: String,
    selector: NoPanicSelector,
    #[serde(default)]
    last_seen: Option<NoPanicLastSeen>,
}

#[derive(Debug, Deserialize)]
#[expect(dead_code, reason = "schema fields used by the matching reducer")]
struct NoPanicSelector {
    kind: String,
    #[serde(default)]
    container: Option<String>,
    callee: String,
    #[serde(default)]
    receiver_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
#[expect(dead_code, reason = "advisory `last_seen` hints surface drift later")]
struct NoPanicLastSeen {
    #[serde(default)]
    line: Option<u32>,
    #[serde(default)]
    column: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PanicFinding {
    pub path: String,
    pub family: String,
    pub line: u32,
    pub column: u32,
    pub selector_kind: String,
    pub selector_callee: String,
    pub snippet: String,
}

pub fn check_no_panic_family() -> Result<()> {
    let config: NoPanicConfig = if Path::new(NO_PANIC_TOML).exists() {
        read_toml(NO_PANIC_TOML)?
    } else {
        bail!("missing {NO_PANIC_TOML}");
    };

    let findings = scan_panic_findings()?;
    let mut report = NoPanicReport::default();
    let mut matched = vec![false; config.allow.len()];
    let mut unallowlisted: Vec<&PanicFinding> = Vec::new();

    for finding in &findings {
        let mut matched_one = false;
        for (idx, entry) in config.allow.iter().enumerate() {
            if entry_matches(entry, finding) {
                matched[idx] = true;
                matched_one = true;
                break;
            }
        }
        if !matched_one {
            unallowlisted.push(finding);
        }
    }

    let mut stale: Vec<&NoPanicAllow> = Vec::new();
    let mut expired: Vec<&NoPanicAllow> = Vec::new();
    let now = today();
    for (idx, entry) in config.allow.iter().enumerate() {
        if !matched[idx] {
            stale.push(entry);
        }
        if let Ok(d) = NaiveDate::parse_from_str(&entry.expires, "%Y-%m-%d") {
            if d < now {
                expired.push(entry);
            }
        } else {
            bail!(
                "no-panic allowlist entry `{}`: invalid expires date `{}` (expected YYYY-MM-DD)",
                entry.id,
                entry.expires
            );
        }
    }

    report.total_findings = findings.len();
    report.allowlisted = findings.len().saturating_sub(unallowlisted.len());
    report.unallowlisted = unallowlisted.len();
    report.stale_entries = stale.len();
    report.expired_entries = expired.len();
    report.mode = config.policy.mode.clone();
    report.by_family = group_by_family(&findings);
    report.by_crate = group_by_crate(&findings);

    let markdown = render_no_panic_md(&report, &unallowlisted, &stale, &expired);
    write_outputs("no-panic", &serde_json::to_value(&report)?, &markdown)?;

    eprintln!(
        "no-panic: {} finding(s); {} unallowlisted; {} stale; {} expired (mode={})",
        report.total_findings,
        report.unallowlisted,
        report.stale_entries,
        report.expired_entries,
        report.mode
    );

    let blocking = config.policy.mode == "blocking";
    if blocking
        && (report.unallowlisted > 0 || report.stale_entries > 0 || report.expired_entries > 0)
    {
        bail!(
            "no-panic policy is blocking and there are {} unallowlisted, {} stale, {} expired",
            report.unallowlisted,
            report.stale_entries,
            report.expired_entries
        );
    }
    Ok(())
}

pub fn no_panic_propose() -> Result<()> {
    let findings = scan_panic_findings()?;
    fs::create_dir_all(PROPOSED_DIR).ok();
    let path = format!("{PROPOSED_DIR}/no-panic-proposed-allowlist.toml");

    let mut buf = String::new();
    buf.push_str("# Proposed no-panic allowlist (review before copying into\n");
    buf.push_str("# policy/no-panic-allowlist.toml). Add owner/reason/expiry per entry.\n");
    buf.push_str("schema_version = \"0.3\"\n\n");

    let stub_expires = stub_expiry();
    for (idx, f) in findings.iter().enumerate() {
        let id = format!("panic-proposed-{idx:05}");
        buf.push_str("[[allow]]\n");
        buf.push_str(&format!("id = \"{id}\"\n"));
        buf.push_str(&format!("path = \"{}\"\n", f.path));
        buf.push_str(&format!("family = \"{}\"\n", f.family));
        buf.push_str("classification = \"test_helper\"  # FIXME: classify\n");
        buf.push_str("owner = \"FIXME\"\n");
        buf.push_str(&format!(
            "explanation = \"FIXME: explain or migrate. Snippet: {}\"\n",
            escape_toml(&f.snippet)
        ));
        buf.push_str(&format!("expires = \"{stub_expires}\"\n"));
        buf.push_str("\n[allow.selector]\n");
        buf.push_str(&format!("kind = \"{}\"\n", f.selector_kind));
        buf.push_str(&format!("callee = \"{}\"\n", f.selector_callee));
        buf.push_str("\n[allow.last_seen]\n");
        buf.push_str(&format!("line = {}\n", f.line));
        buf.push_str(&format!("column = {}\n", f.column));
        buf.push('\n');
    }

    fs::write(&path, buf).with_context(|| format!("write {path}"))?;
    eprintln!(
        "no-panic propose: wrote {} ({} candidate entries)",
        path,
        findings.len()
    );
    Ok(())
}

fn stub_expiry() -> String {
    let d = today() + chrono::Duration::days(180);
    d.format("%Y-%m-%d").to_string()
}

fn escape_toml(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn entry_matches(entry: &NoPanicAllow, finding: &PanicFinding) -> bool {
    entry.path == finding.path
        && entry.family == finding.family
        && entry.selector.kind == finding.selector_kind
        && entry.selector.callee == finding.selector_callee
}

#[derive(Debug, Default, Serialize)]
struct NoPanicReport {
    total_findings: usize,
    allowlisted: usize,
    unallowlisted: usize,
    stale_entries: usize,
    expired_entries: usize,
    mode: String,
    by_family: BTreeMap<String, usize>,
    by_crate: BTreeMap<String, usize>,
}

fn group_by_family(findings: &[PanicFinding]) -> BTreeMap<String, usize> {
    let mut map = BTreeMap::new();
    for f in findings {
        *map.entry(f.family.clone()).or_default() += 1;
    }
    map
}

fn group_by_crate(findings: &[PanicFinding]) -> BTreeMap<String, usize> {
    let mut map = BTreeMap::new();
    for f in findings {
        let krate = f.path.split('/').take(2).collect::<Vec<_>>().join("/");
        *map.entry(krate).or_default() += 1;
    }
    map
}

fn render_no_panic_md(
    report: &NoPanicReport,
    unallowlisted: &[&PanicFinding],
    stale: &[&NoPanicAllow],
    expired: &[&NoPanicAllow],
) -> String {
    let mut s = String::new();
    s.push_str("# No-panic policy report\n\n");
    s.push_str(&format!("- Mode: `{}`\n", report.mode));
    s.push_str(&format!(
        "- Total findings: **{}**\n",
        report.total_findings
    ));
    s.push_str(&format!("- Allowlisted: {}\n", report.allowlisted));
    s.push_str(&format!("- Unallowlisted: **{}**\n", report.unallowlisted));
    s.push_str(&format!("- Stale entries: {}\n", report.stale_entries));
    s.push_str(&format!(
        "- Expired entries: {}\n\n",
        report.expired_entries
    ));

    s.push_str("## By family\n\n");
    for (k, v) in &report.by_family {
        s.push_str(&format!("- `{}`: {}\n", k, v));
    }
    s.push('\n');

    s.push_str("## By crate (top 20)\n\n");
    let mut by_crate: Vec<_> = report.by_crate.iter().collect();
    by_crate.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (k, v) in by_crate.iter().take(20) {
        s.push_str(&format!("- `{}`: {}\n", k, v));
    }
    s.push('\n');

    if !unallowlisted.is_empty() {
        s.push_str(&format!(
            "## Unallowlisted findings ({})\n\n",
            unallowlisted.len()
        ));
        s.push_str("First 50 shown.\n\n");
        for f in unallowlisted.iter().take(50) {
            s.push_str(&format!(
                "- `{}:{}:{}` — `{}` ({})\n",
                f.path, f.line, f.column, f.family, f.selector_callee
            ));
        }
        s.push('\n');
    }

    if !stale.is_empty() {
        s.push_str(&format!("## Stale allowlist entries ({})\n\n", stale.len()));
        for e in stale {
            s.push_str(&format!("- `{}` ({}, {})\n", e.id, e.path, e.family));
        }
        s.push('\n');
    }

    if !expired.is_empty() {
        s.push_str(&format!(
            "## Expired allowlist entries ({})\n\n",
            expired.len()
        ));
        for e in expired {
            s.push_str(&format!(
                "- `{}` expired {} ({}, {})\n",
                e.id, e.expires, e.path, e.family
            ));
        }
        s.push('\n');
    }

    s
}

// =============================================================================
// panic-family scanning (regex-based)
// =============================================================================

fn scan_panic_findings() -> Result<Vec<PanicFinding>> {
    let files = git_ls_files()?;
    let rust_files: Vec<&str> = files
        .iter()
        .filter(|p| p.ends_with(".rs"))
        .map(String::as_str)
        .collect();

    // Skip tests/build helpers under target, and ignore generated files.
    let unwrap_re = Regex::new(r"\.unwrap\s*\(\s*\)").expect("valid regex");
    let expect_re = Regex::new(r"\.expect\s*\(").expect("valid regex");
    let get_unwrap_re =
        Regex::new(r"\.get(?:_mut)?\s*\([^)]*\)\s*\.\s*unwrap\s*\(").expect("valid regex");
    let panic_macro_re = Regex::new(r"\bpanic!\s*\(").expect("valid regex");
    let todo_re = Regex::new(r"\btodo!\s*\(").expect("valid regex");
    let unimplemented_re = Regex::new(r"\bunimplemented!\s*\(").expect("valid regex");
    let unreachable_re = Regex::new(r"\bunreachable!\s*\(").expect("valid regex");

    let mut out = Vec::new();
    for file in &rust_files {
        let content = match fs::read_to_string(file) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for (idx, raw_line) in content.lines().enumerate() {
            // Skip pure-comment / doc lines as a fast first pass; this is not perfect
            // (block comments slip through) but is a reasonable signal-to-noise.
            let trimmed = raw_line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            // Strip the trailing `// ...` comment (if any) before regex matching, so
            // that `let x = foo(); // .unwrap()` does not produce a false positive.
            // This is a naive strip that ignores `//` inside string literals; for
            // panic-family detection in real code that is acceptable noise.
            let line = strip_line_comment(raw_line);

            // get_unwrap takes precedence over plain unwrap so we don't double-count.
            if let Some(m) = get_unwrap_re.find(line) {
                out.push(PanicFinding {
                    path: file.to_string(),
                    family: "get_unwrap".into(),
                    line: (idx + 1) as u32,
                    column: (m.start() + 1) as u32,
                    selector_kind: "method_call".into(),
                    selector_callee: "unwrap".into(),
                    snippet: line.trim().to_string(),
                });
                continue;
            }
            if let Some(m) = unwrap_re.find(line) {
                out.push(PanicFinding {
                    path: file.to_string(),
                    family: "unwrap".into(),
                    line: (idx + 1) as u32,
                    column: (m.start() + 1) as u32,
                    selector_kind: "method_call".into(),
                    selector_callee: "unwrap".into(),
                    snippet: line.trim().to_string(),
                });
            }
            if let Some(m) = expect_re.find(line) {
                out.push(PanicFinding {
                    path: file.to_string(),
                    family: "expect".into(),
                    line: (idx + 1) as u32,
                    column: (m.start() + 1) as u32,
                    selector_kind: "method_call".into(),
                    selector_callee: "expect".into(),
                    snippet: line.trim().to_string(),
                });
            }
            if let Some(m) = panic_macro_re.find(line) {
                out.push(PanicFinding {
                    path: file.to_string(),
                    family: "panic_macro".into(),
                    line: (idx + 1) as u32,
                    column: (m.start() + 1) as u32,
                    selector_kind: "macro".into(),
                    selector_callee: "panic".into(),
                    snippet: line.trim().to_string(),
                });
            }
            if let Some(m) = todo_re.find(line) {
                out.push(PanicFinding {
                    path: file.to_string(),
                    family: "todo".into(),
                    line: (idx + 1) as u32,
                    column: (m.start() + 1) as u32,
                    selector_kind: "macro".into(),
                    selector_callee: "todo".into(),
                    snippet: line.trim().to_string(),
                });
            }
            if let Some(m) = unimplemented_re.find(line) {
                out.push(PanicFinding {
                    path: file.to_string(),
                    family: "unimplemented".into(),
                    line: (idx + 1) as u32,
                    column: (m.start() + 1) as u32,
                    selector_kind: "macro".into(),
                    selector_callee: "unimplemented".into(),
                    snippet: line.trim().to_string(),
                });
            }
            if let Some(m) = unreachable_re.find(line) {
                out.push(PanicFinding {
                    path: file.to_string(),
                    family: "unreachable".into(),
                    line: (idx + 1) as u32,
                    column: (m.start() + 1) as u32,
                    selector_kind: "macro".into(),
                    selector_callee: "unreachable".into(),
                    snippet: line.trim().to_string(),
                });
            }
        }
    }
    Ok(out)
}

fn strip_line_comment(line: &str) -> &str {
    if let Some(idx) = line.find("//") {
        &line[..idx]
    } else {
        line
    }
}

// =============================================================================
// non-rust file policy
// =============================================================================

#[derive(Debug, Deserialize)]
struct FilePolicyConfig {
    #[expect(
        dead_code,
        reason = "schema validation; surfaced in policy reports later"
    )]
    #[serde(default)]
    schema_version: Option<String>,
    #[serde(default)]
    policy: FilePolicySettings,
    #[serde(default)]
    allow: Vec<FilePolicyAllow>,
}

#[derive(Debug, Default, Deserialize)]
struct FilePolicySettings {
    #[serde(default = "default_allowed_extensions")]
    default_allowed_extensions: Vec<String>,
    #[serde(default = "default_allowed_filenames")]
    default_allowed_filenames: Vec<String>,
}

fn default_allowed_extensions() -> Vec<String> {
    vec!["rs".into(), "toml".into(), "md".into()]
}

fn default_allowed_filenames() -> Vec<String> {
    vec![
        "LICENSE-APACHE".into(),
        "LICENSE-MIT".into(),
        "CODEOWNERS".into(),
        ".gitignore".into(),
        ".gitattributes".into(),
        ".editorconfig".into(),
    ]
}

#[derive(Debug, Deserialize)]
struct FilePolicyAllow {
    #[serde(default)]
    glob: Option<String>,
    #[serde(default)]
    path: Option<String>,
    kind: String,
    owner: String,
    surface: String,
    classification: String,
    #[expect(dead_code, reason = "human-readable, surfaced in reports later")]
    reason: String,
    #[serde(default)]
    covered_by: Vec<String>,
    #[expect(
        dead_code,
        reason = "documents regeneration command for `generated` entries"
    )]
    #[serde(default)]
    generated_by: Option<String>,
    #[serde(default)]
    expires: Option<String>,
    #[serde(default)]
    retired: bool,
}

pub fn check_file_policy() -> Result<()> {
    let config: FilePolicyConfig = read_toml(NON_RUST_TOML)?;
    let files = git_ls_files()?;
    let now = today();

    let mut unmatched: Vec<String> = Vec::new();
    let mut matched_count = 0usize;
    let mut entry_hits = vec![0usize; config.allow.len()];
    let mut expired: Vec<&FilePolicyAllow> = Vec::new();
    let mut missing_metadata: Vec<String> = Vec::new();

    for entry in &config.allow {
        if let Some(exp) = &entry.expires {
            match NaiveDate::parse_from_str(exp, "%Y-%m-%d") {
                Ok(d) if d < now => expired.push(entry),
                Err(e) => bail!(
                    "file-policy entry kind={} owner={}: invalid expires `{}`: {}",
                    entry.kind,
                    entry.owner,
                    exp,
                    e
                ),
                _ => {}
            }
        }
        if matches!(
            entry.classification.as_str(),
            "production" | "test" | "tooling"
        ) && entry.covered_by.is_empty()
        {
            missing_metadata.push(format!(
                "kind={} surface={} owner={}: covered_by required for classification={}",
                entry.kind, entry.surface, entry.owner, entry.classification
            ));
        }
    }

    for file in &files {
        // Allowlist entries claim ownership first; default-allowed is a
        // fallback for tracked files that have no explicit owner.
        let mut hit = false;
        for (idx, entry) in config.allow.iter().enumerate() {
            if entry_matches_file(entry, file) {
                entry_hits[idx] += 1;
                hit = true;
                break;
            }
        }
        if hit {
            matched_count += 1;
            continue;
        }
        if is_default_allowed(file, &config.policy) {
            matched_count += 1;
            continue;
        }
        unmatched.push(file.clone());
    }

    let mut unused: Vec<&FilePolicyAllow> = Vec::new();
    for (idx, entry) in config.allow.iter().enumerate() {
        if entry_hits[idx] == 0 && !entry.retired {
            unused.push(entry);
        }
    }

    let report = FilePolicyReport {
        total_files: files.len(),
        matched: matched_count,
        unmatched: unmatched.len(),
        unused_entries: unused.len(),
        expired_entries: expired.len(),
        unmatched_paths: unmatched.iter().take(50).cloned().collect(),
    };

    let md = render_file_policy_md(&report, &unmatched, &unused, &expired, &missing_metadata);
    write_outputs("file-policy", &serde_json::to_value(&report)?, &md)?;

    eprintln!(
        "file-policy: {} files; {} matched; {} unmatched; {} unused; {} expired",
        report.total_files,
        report.matched,
        report.unmatched,
        report.unused_entries,
        report.expired_entries
    );

    if !missing_metadata.is_empty() {
        for m in &missing_metadata {
            eprintln!("  policy schema error: {m}");
        }
        bail!(
            "file-policy: {} entries missing required metadata",
            missing_metadata.len()
        );
    }

    if !unmatched.is_empty() || !unused.is_empty() || !expired.is_empty() {
        bail!(
            "file-policy: {} unmatched, {} unused (retire or remove), {} expired",
            unmatched.len(),
            unused.len(),
            expired.len()
        );
    }
    Ok(())
}

fn is_default_allowed(path: &str, settings: &FilePolicySettings) -> bool {
    let p = Path::new(path);
    if let Some(ext) = p.extension().and_then(|s| s.to_str())
        && settings.default_allowed_extensions.iter().any(|x| x == ext)
    {
        return true;
    }
    let basename = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
    settings
        .default_allowed_filenames
        .iter()
        .any(|x| x == basename)
}

fn entry_matches_file(entry: &FilePolicyAllow, file: &str) -> bool {
    if let Some(p) = &entry.path
        && p == file
    {
        return true;
    }
    if let Some(g) = &entry.glob
        && glob_match(g, file)
    {
        return true;
    }
    false
}

#[derive(Debug, Serialize)]
struct FilePolicyReport {
    total_files: usize,
    matched: usize,
    unmatched: usize,
    unused_entries: usize,
    expired_entries: usize,
    unmatched_paths: Vec<String>,
}

fn render_file_policy_md(
    report: &FilePolicyReport,
    unmatched: &[String],
    unused: &[&FilePolicyAllow],
    expired: &[&FilePolicyAllow],
    missing_metadata: &[String],
) -> String {
    let mut s = String::new();
    s.push_str("# File-policy report\n\n");
    s.push_str(&format!("- Tracked files: {}\n", report.total_files));
    s.push_str(&format!("- Matched: {}\n", report.matched));
    s.push_str(&format!("- Unmatched: **{}**\n", report.unmatched));
    s.push_str(&format!("- Unused entries: {}\n", report.unused_entries));
    s.push_str(&format!(
        "- Expired entries: {}\n\n",
        report.expired_entries
    ));

    if !missing_metadata.is_empty() {
        s.push_str("## Missing metadata\n\n");
        for m in missing_metadata {
            s.push_str(&format!("- {m}\n"));
        }
        s.push('\n');
    }

    if !unmatched.is_empty() {
        s.push_str(&format!("## Unmatched files ({})\n\n", unmatched.len()));
        for p in unmatched.iter().take(50) {
            s.push_str(&format!("- `{p}`\n"));
        }
        s.push('\n');
    }
    if !unused.is_empty() {
        s.push_str(&format!("## Unused entries ({})\n\n", unused.len()));
        for e in unused {
            let pat = e.path.as_deref().or(e.glob.as_deref()).unwrap_or("?");
            s.push_str(&format!(
                "- `{}` (kind={}, owner={})\n",
                pat, e.kind, e.owner
            ));
        }
        s.push('\n');
    }
    if !expired.is_empty() {
        s.push_str(&format!("## Expired entries ({})\n\n", expired.len()));
        for e in expired {
            let pat = e.path.as_deref().or(e.glob.as_deref()).unwrap_or("?");
            s.push_str(&format!(
                "- `{}` expired {}\n",
                pat,
                e.expires.as_deref().unwrap_or("?")
            ));
        }
        s.push('\n');
    }
    s
}

// =============================================================================
// lint-policy checker
// =============================================================================

#[derive(Debug, Deserialize)]
struct LintPolicy {
    msrv: String,
    #[expect(dead_code, reason = "schema validation; surfaced in reports later")]
    #[serde(default)]
    policy: LintPolicySettings,
    #[serde(default)]
    planned: Vec<PlannedLint>,
    #[serde(default)]
    forbidden_carveouts: ForbiddenCarveouts,
}

#[derive(Debug, Default, Deserialize)]
#[expect(dead_code, reason = "schema validation; surfaced in reports later")]
struct LintPolicySettings {
    #[serde(default)]
    suppression_style: Option<String>,
    #[serde(default)]
    allow_test_carveouts: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct PlannedLint {
    name: String,
    #[allow(dead_code)]
    level: String,
    activate_when_msrv: String,
    #[allow(dead_code)]
    reason: String,
}

#[derive(Debug, Default, Deserialize)]
struct ForbiddenCarveouts {
    #[serde(default)]
    keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ClippyDebt {
    #[allow(dead_code)]
    schema_version: Option<String>,
    #[serde(default)]
    debt: Vec<DebtEntry>,
}

#[derive(Debug, Deserialize)]
struct DebtEntry {
    id: String,
    #[allow(dead_code)]
    lint: String,
    #[allow(dead_code)]
    scope: String,
    #[allow(dead_code)]
    owner: String,
    #[allow(dead_code)]
    reason: String,
    expires: String,
}

pub fn check_lint_policy() -> Result<()> {
    let lp: LintPolicy = read_toml(CLIPPY_LINTS_TOML)?;
    let mut errors: Vec<String> = Vec::new();

    // 1. MSRV alignment.
    let root_cargo = fs::read_to_string("Cargo.toml").context("read Cargo.toml")?;
    let root_msrv = parse_workspace_rust_version(&root_cargo);
    if let Some(rv) = &root_msrv {
        if rv != &lp.msrv {
            errors.push(format!(
                "MSRV mismatch: workspace `rust-version = \"{}\"` != policy msrv `\"{}\"`",
                rv, lp.msrv
            ));
        }
    } else {
        errors.push("could not find `[workspace.package].rust-version` in Cargo.toml".into());
    }

    // 2. clippy.toml carveouts.
    if let Ok(c) = fs::read_to_string("clippy.toml") {
        for key in &lp.forbidden_carveouts.keys {
            if c.contains(key) {
                errors.push(format!("clippy.toml contains forbidden key `{key}`"));
            }
        }
    }

    // 3. Every member crate has [lints] workspace = true.
    let members = list_workspace_members(&root_cargo);
    for m in &members {
        let cargo = format!("{m}/Cargo.toml");
        let raw = match fs::read_to_string(&cargo) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if !has_workspace_lints(&raw) {
            errors.push(format!("{cargo}: missing `[lints]\\nworkspace = true`"));
        }
    }

    // 4. Planned lints not yet activated.
    let active = parse_active_lints(&root_cargo);
    for pl in &lp.planned {
        if !msrv_reached(&lp.msrv, &pl.activate_when_msrv) && active.iter().any(|n| n == &pl.name) {
            errors.push(format!(
                "planned lint `{}` activated before MSRV {} (current {})",
                pl.name, pl.activate_when_msrv, lp.msrv
            ));
        }
    }

    // 5. clippy-debt entries valid.
    if Path::new(CLIPPY_DEBT_TOML).exists() {
        let debt: ClippyDebt = read_toml(CLIPPY_DEBT_TOML)?;
        let now = today();
        for e in &debt.debt {
            match NaiveDate::parse_from_str(&e.expires, "%Y-%m-%d") {
                Ok(d) if d < now => {
                    errors.push(format!("clippy-debt `{}` expired {}", e.id, e.expires))
                }
                Err(err) => errors.push(format!(
                    "clippy-debt `{}` invalid expires `{}`: {}",
                    e.id, e.expires, err
                )),
                _ => {}
            }
        }
    }

    // 6. Bare `#[allow(...)]` debt is advisory in Stage A; surfaced in the
    //    report and slated to flip to error once Clippy
    //    `allow_attributes_without_reason` is promoted. The
    //    `policy/clippy-lints.toml` `[stage].current` field tracks this.
    let bare_allow = scan_bare_allow_in_crates(&members)?;
    let bare_allow_total: usize = bare_allow.iter().map(|(_, n)| *n).sum();

    let report = LintPolicyReport {
        msrv: lp.msrv.clone(),
        members: members.len(),
        errors: errors.clone(),
        bare_allow_files: bare_allow.len(),
        bare_allow_total,
    };
    let md = render_lint_policy_md(&report);
    write_outputs("lint-policy", &serde_json::to_value(&report)?, &md)?;

    eprintln!(
        "lint-policy: msrv={} members={} errors={}",
        lp.msrv,
        members.len(),
        errors.len()
    );

    if !errors.is_empty() {
        for e in &errors {
            eprintln!("  {e}");
        }
        bail!("lint-policy: {} error(s)", errors.len());
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct LintPolicyReport {
    msrv: String,
    members: usize,
    errors: Vec<String>,
    bare_allow_files: usize,
    bare_allow_total: usize,
}

fn render_lint_policy_md(report: &LintPolicyReport) -> String {
    let mut s = String::new();
    s.push_str("# Lint-policy report\n\n");
    s.push_str(&format!("- MSRV: `{}`\n", report.msrv));
    s.push_str(&format!("- Workspace members: {}\n", report.members));
    s.push_str(&format!("- Errors: **{}**\n", report.errors.len()));
    s.push_str(&format!(
        "- Bare `#[allow(...)]` (advisory in Stage A): {} attribute(s) across {} file(s)\n\n",
        report.bare_allow_total, report.bare_allow_files,
    ));
    if !report.errors.is_empty() {
        s.push_str("## Errors\n\n");
        for e in &report.errors {
            s.push_str(&format!("- {e}\n"));
        }
    }
    s
}

fn parse_workspace_rust_version(cargo: &str) -> Option<String> {
    let in_pkg = cargo
        .split("[workspace.package]")
        .nth(1)
        .unwrap_or("")
        .split('\n');
    for line in in_pkg {
        let l = line.trim();
        if l.starts_with('[') {
            break;
        }
        if let Some(rest) = l.strip_prefix("rust-version") {
            // form: rust-version = "1.92"
            if let Some(eq) = rest.find('=') {
                let val = rest[eq + 1..].trim().trim_matches('"');
                return Some(val.to_string());
            }
        }
    }
    None
}

fn list_workspace_members(cargo: &str) -> Vec<String> {
    let mut out = Vec::new();
    let after = match cargo.split("members").nth(1) {
        Some(s) => s,
        None => return out,
    };
    let body = match after.split_once('[') {
        Some((_, b)) => b,
        None => return out,
    };
    let body = match body.split_once(']') {
        Some((b, _)) => b,
        None => return out,
    };
    for line in body.lines() {
        let l = line.trim().trim_end_matches(',').trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let l = l.trim_matches('"');
        out.push(l.to_string());
    }
    out
}

fn has_workspace_lints(cargo: &str) -> bool {
    // Match `[lints]` followed by `workspace = true` (within a few lines).
    let needle = "[lints]";
    let idx = match cargo.find(needle) {
        Some(i) => i + needle.len(),
        None => return false,
    };
    cargo[idx..]
        .lines()
        .take(8)
        .any(|l| l.trim() == "workspace = true")
}

fn parse_active_lints(cargo: &str) -> Vec<String> {
    // Collect lint keys under [workspace.lints.*] sections. Only keys that
    // appear before the next top-level `[` are part of the section.
    let mut active = Vec::new();
    for section in ["[workspace.lints.rust]", "[workspace.lints.clippy]"] {
        if let Some(rest) = cargo.split(section).nth(1) {
            let group = rest.split("\n[").next().unwrap_or("");
            let prefix = if section.ends_with("clippy]") {
                "clippy::"
            } else {
                ""
            };
            for line in group.lines() {
                let l = line.trim();
                if l.is_empty() || l.starts_with('#') {
                    continue;
                }
                if let Some(eq) = l.find('=') {
                    let k = l[..eq].trim();
                    if !k.is_empty() {
                        active.push(format!("{prefix}{k}"));
                    }
                }
            }
        }
    }
    active
}

fn msrv_reached(current: &str, target: &str) -> bool {
    fn parts(s: &str) -> Vec<u32> {
        s.split('.').filter_map(|p| p.parse::<u32>().ok()).collect()
    }
    let c = parts(current);
    let t = parts(target);
    let n = c.len().max(t.len());
    for i in 0..n {
        let ci = c.get(i).copied().unwrap_or(0);
        let ti = t.get(i).copied().unwrap_or(0);
        if ci > ti {
            return true;
        }
        if ci < ti {
            return false;
        }
    }
    true
}

fn scan_bare_allow_in_crates(_members: &[String]) -> Result<Vec<(String, usize)>> {
    let files = git_ls_files()?;
    // Match `#[allow(...)]` not preceded by `expect_` and not followed by quotes
    // implying a `reason = ...`. Bare allow on its own line is the common case.
    let bare = Regex::new(r#"#\[allow\([^)]*\)\]"#).unwrap();
    let mut hits: Vec<(String, usize)> = Vec::new();
    for f in files {
        if !f.ends_with(".rs") {
            continue;
        }
        let s = match fs::read_to_string(&f) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mut count = 0;
        for line in s.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if bare.is_match(line) {
                count += 1;
            }
        }
        if count > 0 {
            hits.push((f, count));
        }
    }
    Ok(hits)
}

// =============================================================================
// aggregate report
// =============================================================================

pub fn policy_report() -> Result<()> {
    let mut summary: BTreeMap<&'static str, serde_json::Value> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();
    for (name, run) in [
        ("no-panic", check_no_panic_family()),
        ("file-policy", check_file_policy()),
        ("lint-policy", check_lint_policy()),
    ] {
        if let Err(e) = &run {
            failures.push(format!("{name}: {e}"));
        }
        summary.insert(
            name,
            serde_json::json!({
                "ok": run.is_ok(),
                "error": run.err().map(|e| e.to_string()),
            }),
        );
    }

    let summary = serde_json::Value::Object(
        summary
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    );
    fs::create_dir_all(TARGET_DIR).ok();
    fs::write(
        format!("{TARGET_DIR}/policy-report.json"),
        serde_json::to_string_pretty(&summary)?,
    )?;

    let mut md = String::new();
    md.push_str("# Policy report (aggregate)\n\n");
    let obj = summary
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("policy-report summary was not an object"))?;
    for (k, v) in obj {
        let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
        let symbol = if ok { "OK" } else { "FAIL" };
        md.push_str(&format!("## {k} — {symbol}\n\n"));
        if !ok && let Some(err) = v.get("error").and_then(|x| x.as_str()) {
            md.push_str(&format!("Error: `{err}`\n\n"));
        }
        md.push_str(&format!("See `target/{k}.md` for the full report.\n\n"));
    }
    fs::write(format!("{TARGET_DIR}/policy-report.md"), md)?;

    eprintln!("policy-report: target/policy-report.{{md,json}}");
    if !failures.is_empty() {
        bail!("policy-report: {} check(s) failed", failures.len());
    }
    Ok(())
}

// =============================================================================
// tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_double_star_matches_nested() {
        assert!(glob_match("crates/**/Cargo.toml", "crates/a/b/Cargo.toml"));
        assert!(glob_match("crates/**/Cargo.toml", "crates/a/Cargo.toml"));
        assert!(!glob_match("crates/**/Cargo.toml", "Cargo.toml"));
    }

    #[test]
    fn glob_single_star_only_path_segment() {
        assert!(glob_match("crates/*/Cargo.toml", "crates/a/Cargo.toml"));
        assert!(!glob_match("crates/*/Cargo.toml", "crates/a/b/Cargo.toml"));
    }

    #[test]
    fn glob_extension_matches() {
        assert!(glob_match(
            ".github/workflows/*.yml",
            ".github/workflows/ci.yml"
        ));
        assert!(!glob_match(
            ".github/workflows/*.yml",
            ".github/dependabot.yml"
        ));
    }

    #[test]
    fn msrv_reached_compares_versions() {
        assert!(msrv_reached("1.94", "1.94"));
        assert!(msrv_reached("1.95", "1.94"));
        assert!(!msrv_reached("1.92", "1.94"));
        assert!(!msrv_reached("1.93", "1.94"));
    }

    #[test]
    fn workspace_lints_detection_works() {
        let cargo = "[lints]\nworkspace = true\n";
        assert!(has_workspace_lints(cargo));
        let cargo2 = "[lints]\n# no workspace\n";
        assert!(!has_workspace_lints(cargo2));
    }

    #[test]
    fn glob_escapes_dots_and_dashes_correctly() {
        // `.` in glob is a literal dot, not a regex any-char.
        assert!(!glob_match("foo.yml", "fooXyml"));
        assert!(glob_match("foo.yml", "foo.yml"));
    }

    #[test]
    fn glob_double_star_at_root_matches_anywhere() {
        assert!(glob_match("**/snapshots/**/*.snap", "x/snapshots/a/b.snap"));
        assert!(glob_match("**/snapshots/**/*.snap", "snapshots/a.snap"));
    }

    #[test]
    fn strip_line_comment_drops_trailing_comment() {
        assert_eq!(strip_line_comment("let x = 1; // .unwrap()"), "let x = 1; ");
        assert_eq!(strip_line_comment("plain code"), "plain code");
        assert_eq!(strip_line_comment("// only a comment"), "");
    }

    #[test]
    fn parse_workspace_rust_version_finds_value() {
        let cargo = "[workspace.package]\nrust-version = \"1.92\"\nedition = \"2024\"\n";
        assert_eq!(parse_workspace_rust_version(cargo).as_deref(), Some("1.92"));
    }

    #[test]
    fn parse_workspace_rust_version_returns_none_when_missing() {
        let cargo = "[workspace.package]\nedition = \"2024\"\n";
        assert!(parse_workspace_rust_version(cargo).is_none());
    }

    #[test]
    fn parse_active_lints_collects_from_clippy_section() {
        let cargo = "[workspace.lints.rust]\nfoo = \"deny\"\n\n[workspace.lints.clippy]\ndbg_macro = \"deny\"\n";
        let active = parse_active_lints(cargo);
        assert!(active.iter().any(|l| l == "foo"));
        assert!(active.iter().any(|l| l == "clippy::dbg_macro"));
    }
}
