use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Serialize)]
struct ClaimReport {
    status: String,
    filter: Option<String>,
    sources: ClaimReportSources,
    claims: Vec<ClaimReportEntry>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ClaimReportSources {
    ledger: String,
    public_claims: String,
    specs: String,
    adrs: String,
}

#[derive(Debug, Serialize)]
struct ClaimReportEntry {
    id: String,
    title: String,
    status: String,
    surfaces: Vec<String>,
    spec: Option<LinkedArtifact>,
    docs: Vec<String>,
    proof_commands: Vec<String>,
    artifacts: Vec<String>,
    release_lanes: Vec<String>,
    boundary: String,
    generated_evidence_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct LinkedArtifact {
    id: String,
    title: Option<String>,
    status: Option<String>,
    path: String,
}

#[derive(Debug, Deserialize)]
struct ClaimLedger {
    #[serde(default)]
    claim: Vec<ClaimLedgerEntry>,
}

#[derive(Debug, Deserialize)]
struct ClaimLedgerEntry {
    id: String,
    title: String,
    status: String,
    #[serde(default)]
    spec: Option<String>,
    #[serde(default)]
    surfaces: Vec<String>,
    #[serde(default)]
    proof_commands: Vec<String>,
    #[serde(default)]
    artifacts: Vec<String>,
    #[serde(default)]
    docs: Vec<String>,
    #[serde(default)]
    release_lanes: Vec<String>,
    boundary: String,
}

#[derive(Debug, Deserialize)]
struct ArtifactFrontMatter {
    id: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

pub fn run(
    root: &Path,
    format: OutputFormat,
    claim_filter: Option<&str>,
    check_public_claims: bool,
) -> Result<()> {
    if check_public_claims && claim_filter.is_some() {
        bail!("claim-report: --check-public-claims cannot be combined with --claim");
    }

    let report = build_report(root, claim_filter)?;
    let out_dir = root.join("target/claim-report");
    fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    let json_path = out_dir.join("public-claims.json");
    let md_path = out_dir.join("public-claims.md");
    write_json_pretty(&json_path, &report)?;
    fs::write(&md_path, render_markdown(&report))
        .with_context(|| format!("write {}", md_path.display()))?;

    if check_public_claims {
        check_public_claims_doc(root, &report)?;
    }

    match format {
        OutputFormat::Human => {
            println!("{}", render_markdown(&report));
            println!(
                "claim-report: wrote {} and {}",
                rel_path(root, &md_path),
                rel_path(root, &json_path)
            );
        }
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }

    Ok(())
}

pub(crate) fn write_release_receipt(root: &Path, out_dir: &Path) -> Result<()> {
    let report = build_report(root, None)?;
    let claims_dir = out_dir.join("claims");
    fs::create_dir_all(&claims_dir).with_context(|| format!("create {}", claims_dir.display()))?;

    let json_path = claims_dir.join("public-claims.json");
    let md_path = claims_dir.join("public-claims.md");
    write_json_pretty(&json_path, &report)?;
    fs::write(&md_path, render_markdown(&report))
        .with_context(|| format!("write {}", md_path.display()))?;

    Ok(())
}

pub(crate) fn write_target_receipt(root: &Path, claim_filter: Option<&str>) -> Result<()> {
    let report = build_report(root, claim_filter)?;
    let out_dir = root.join("target/claim-report");
    fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    let json_path = out_dir.join("public-claims.json");
    let md_path = out_dir.join("public-claims.md");
    write_json_pretty(&json_path, &report)?;
    fs::write(&md_path, render_markdown(&report))
        .with_context(|| format!("write {}", md_path.display()))?;

    Ok(())
}

fn check_public_claims_doc(root: &Path, report: &ClaimReport) -> Result<()> {
    let errors = public_claim_errors(root, report)?;
    if !errors.is_empty() {
        for error in &errors {
            eprintln!("claim-report: {error}");
        }
        bail!("claim-report: docs/status/PUBLIC_CLAIMS.md drifted from policy/claim-ledger.toml");
    }

    println!("claim-report: docs/status/PUBLIC_CLAIMS.md matches policy/claim-ledger.toml");
    Ok(())
}

fn build_report(root: &Path, claim_filter: Option<&str>) -> Result<ClaimReport> {
    let ledger_path = root.join("policy/claim-ledger.toml");
    let ledger_text = fs::read_to_string(&ledger_path)
        .with_context(|| format!("read {}", ledger_path.display()))?;
    let ledger: ClaimLedger =
        toml::from_str(&ledger_text).context("parse policy/claim-ledger.toml")?;

    let mut warnings = Vec::new();
    let public_claims_path = root.join("docs/status/PUBLIC_CLAIMS.md");
    if !public_claims_path.exists() {
        warnings.push("docs/status/PUBLIC_CLAIMS.md is missing".to_string());
    }

    let specs = collect_artifacts(root, &root.join("docs/specs"), "USELESSKEY-SPEC-")?;
    let adrs = collect_artifacts(root, &root.join("docs/adr"), "USELESSKEY-ADR-")?;
    let artifacts = specs
        .iter()
        .chain(adrs.iter())
        .map(|(id, artifact)| (id.clone(), artifact.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut claims = Vec::new();
    for claim in ledger.claim {
        if claim_filter.is_some_and(|filter| filter != claim.id) {
            continue;
        }

        let spec = claim.spec.as_ref().map(|id| {
            artifacts.get(id).cloned().unwrap_or_else(|| {
                warnings.push(format!("claim `{}` links missing spec `{id}`", claim.id));
                LinkedArtifact {
                    id: id.clone(),
                    title: None,
                    status: None,
                    path: String::new(),
                }
            })
        });

        for doc in &claim.docs {
            if !root
                .join(doc.replace('/', std::path::MAIN_SEPARATOR_STR))
                .exists()
            {
                warnings.push(format!("claim `{}` links missing doc `{doc}`", claim.id));
            }
        }

        let generated_evidence_paths = claim
            .artifacts
            .iter()
            .filter(|artifact| is_generated_evidence_path(artifact))
            .cloned()
            .collect();

        claims.push(ClaimReportEntry {
            id: claim.id,
            title: claim.title,
            status: claim.status,
            surfaces: claim.surfaces,
            spec,
            docs: claim.docs,
            proof_commands: claim.proof_commands,
            artifacts: claim.artifacts,
            release_lanes: claim.release_lanes,
            boundary: claim.boundary,
            generated_evidence_paths,
        });
    }

    if let Some(filter) = claim_filter
        && claims.is_empty()
    {
        bail!("claim-report: no claim found for `{filter}`");
    }

    let status = "pass".to_string();
    Ok(ClaimReport {
        status,
        filter: claim_filter.map(str::to_string),
        sources: ClaimReportSources {
            ledger: "policy/claim-ledger.toml".to_string(),
            public_claims: "docs/status/PUBLIC_CLAIMS.md".to_string(),
            specs: "docs/specs".to_string(),
            adrs: "docs/adr".to_string(),
        },
        claims,
        warnings,
    })
}

fn collect_artifacts(
    root: &Path,
    dir: &Path,
    prefix: &str,
) -> Result<BTreeMap<String, LinkedArtifact>> {
    let mut artifacts = BTreeMap::new();
    if !dir.exists() {
        return Ok(artifacts);
    }

    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !file_name.starts_with(prefix) {
            continue;
        }

        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let (front_matter, _) = split_toml_front_matter(&text)
            .with_context(|| format!("parse front matter from {}", rel_path(root, &path)))?;
        let parsed: ArtifactFrontMatter = toml::from_str(&front_matter)
            .with_context(|| format!("parse TOML front matter from {}", rel_path(root, &path)))?;
        artifacts.insert(
            parsed.id.clone(),
            LinkedArtifact {
                id: parsed.id,
                title: parsed.title,
                status: parsed.status,
                path: rel_path(root, &path),
            },
        );
    }

    Ok(artifacts)
}

fn split_toml_front_matter(text: &str) -> Result<(String, String)> {
    let mut lines = text.lines();
    let Some(first) = lines.next() else {
        bail!("empty document")
    };
    if first.trim() != "+++" {
        bail!("first line is not +++");
    }

    let mut front = Vec::new();
    for line in &mut lines {
        if line.trim() == "+++" {
            return Ok((front.join("\n"), lines.collect::<Vec<_>>().join("\n")));
        }
        front.push(line);
    }

    bail!("unterminated TOML front matter")
}

fn render_markdown(report: &ClaimReport) -> String {
    let mut md = String::new();
    md.push_str("# Public Claim Report\n\n");
    md.push_str(
        "This report indexes public `uselesskey` claims from `policy/claim-ledger.toml`.\n",
    );
    md.push_str("It does not run proof commands.\n\n");

    md.push_str("## Sources\n\n");
    md.push_str(&format!("- Ledger: `{}`\n", report.sources.ledger));
    md.push_str(&format!(
        "- Public claim docs: `{}`\n",
        report.sources.public_claims
    ));
    md.push_str(&format!("- Specs: `{}`\n", report.sources.specs));
    md.push_str(&format!("- ADRs: `{}`\n", report.sources.adrs));
    if let Some(filter) = &report.filter {
        md.push_str(&format!("- Filter: `{filter}`\n"));
    }

    md.push_str("\n## Summary\n\n");
    md.push_str("| Claim | Status | Release lanes | Spec |\n");
    md.push_str("| --- | --- | --- | --- |\n");
    for claim in &report.claims {
        let spec = claim
            .spec
            .as_ref()
            .map(|spec| format!("`{}`", spec.id))
            .unwrap_or_else(|| "n/a".to_string());
        md.push_str(&format!(
            "| `{}` | `{}` | {} | {} |\n",
            claim.id,
            claim.status,
            join_inline(&claim.release_lanes),
            spec
        ));
    }

    md.push_str("\n## Claims\n\n");
    for claim in &report.claims {
        md.push_str(&format!("### {}\n\n", claim.title));
        md.push_str(&format!("- ID: `{}`\n", claim.id));
        md.push_str(&format!("- Status: `{}`\n", claim.status));
        if let Some(spec) = &claim.spec {
            md.push_str(&format!("- Spec: `{}` ({})\n", spec.id, spec.path));
        }
        md.push_str(&format!("- Surfaces: {}\n", join_inline(&claim.surfaces)));
        md.push_str(&format!("- Docs: {}\n", join_inline(&claim.docs)));
        md.push_str(&format!(
            "- Release lanes: {}\n",
            join_inline(&claim.release_lanes)
        ));

        md.push_str("\nProof commands:\n\n");
        md.push_str("```bash\n");
        for command in &claim.proof_commands {
            md.push_str(command);
            md.push('\n');
        }
        md.push_str("```\n\n");

        md.push_str("Artifacts:\n\n");
        for artifact in &claim.artifacts {
            md.push_str(&format!("- `{artifact}`\n"));
        }

        if !claim.generated_evidence_paths.is_empty() {
            md.push_str("\nLast-known generated evidence paths:\n\n");
            for path in &claim.generated_evidence_paths {
                md.push_str(&format!("- `{path}`\n"));
            }
        }

        md.push_str("\nBoundary:\n\n");
        md.push_str(&claim.boundary);
        md.push_str("\n\n");
    }

    if !report.warnings.is_empty() {
        md.push_str("## Warnings\n\n");
        for warning in &report.warnings {
            md.push_str(&format!("- {warning}\n"));
        }
    }

    md
}

fn public_claim_errors(root: &Path, report: &ClaimReport) -> Result<Vec<String>> {
    let public_claims_path = root.join("docs/status/PUBLIC_CLAIMS.md");
    let markdown = fs::read_to_string(&public_claims_path)
        .with_context(|| format!("read {}", public_claims_path.display()))?;
    let rows = parse_public_claim_rows(&markdown);
    let mut errors = Vec::new();

    if rows.is_empty() {
        errors
            .push("docs/status/PUBLIC_CLAIMS.md has no parseable Current Claims rows".to_string());
        return Ok(errors);
    }

    let claims_by_id = report
        .claims
        .iter()
        .map(|claim| (claim.id.as_str(), claim))
        .collect::<BTreeMap<_, _>>();
    let row_ids = rows
        .iter()
        .map(|row| row.id.as_str())
        .collect::<BTreeSet<_>>();

    for claim in report
        .claims
        .iter()
        .filter(|claim| claim.status == "stable")
    {
        if !row_ids.contains(claim.id.as_str()) {
            errors.push(format!(
                "stable claim `{}` is missing from docs/status/PUBLIC_CLAIMS.md",
                claim.id
            ));
        }
    }

    for row in rows {
        let Some(claim) = claims_by_id.get(row.id.as_str()) else {
            errors.push(format!(
                "docs/status/PUBLIC_CLAIMS.md:{} references unknown claim `{}`",
                row.line, row.id
            ));
            continue;
        };

        if row.status != claim.status {
            errors.push(format!(
                "docs/status/PUBLIC_CLAIMS.md:{} claim `{}` has status `{}`, expected `{}`",
                row.line, row.id, row.status, claim.status
            ));
        }
        if row.boundary.trim().is_empty() {
            errors.push(format!(
                "docs/status/PUBLIC_CLAIMS.md:{} claim `{}` has an empty boundary",
                row.line, row.id
            ));
        }
        if row.proof.trim().is_empty() {
            errors.push(format!(
                "docs/status/PUBLIC_CLAIMS.md:{} claim `{}` has no visible proof commands",
                row.line, row.id
            ));
        }
        for command in &claim.proof_commands {
            if !row.proof.contains(command) {
                errors.push(format!(
                    "docs/status/PUBLIC_CLAIMS.md:{} claim `{}` omits proof command `{}`",
                    row.line, row.id, command
                ));
            }
        }
    }

    Ok(errors)
}

#[derive(Debug)]
struct PublicClaimRow {
    line: usize,
    id: String,
    status: String,
    proof: String,
    boundary: String,
}

fn parse_public_claim_rows(markdown: &str) -> Vec<PublicClaimRow> {
    let mut rows = Vec::new();
    let mut in_current_claims = false;

    for (idx, line) in markdown.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == "## Current Claims" {
            in_current_claims = true;
            continue;
        }
        if in_current_claims && trimmed.starts_with("## ") {
            break;
        }
        if !in_current_claims || !trimmed.starts_with('|') {
            continue;
        }

        let cells = trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect::<Vec<_>>();
        if cells.len() < 5 {
            continue;
        }
        if cells[0] == "Claim ID" || cells[0].starts_with("---") {
            continue;
        }

        rows.push(PublicClaimRow {
            line: idx + 1,
            id: strip_inline_code(cells[0]),
            status: strip_inline_code(cells[2]),
            proof: cells[3].to_string(),
            boundary: cells[4].to_string(),
        });
    }

    rows
}

fn strip_inline_code(value: &str) -> String {
    value.trim().trim_matches('`').trim().to_string()
}

fn join_inline(values: &[String]) -> String {
    if values.is_empty() {
        return "n/a".to_string();
    }
    values
        .iter()
        .map(|value| format!("`{value}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn is_generated_evidence_path(path: &str) -> bool {
    path.starts_with("badges/") || path.starts_with("target/")
}

fn write_json_pretty(path: &Path, value: &impl Serialize) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, json + "\n").with_context(|| format!("write {}", path.display()))
}

fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_includes_claim_ledger_fields() -> Result<()> {
        let dir = minimal_repo()?;
        let report = build_report(dir.path(), None)?;

        assert_eq!(report.claims.len(), 2);
        let claim = &report.claims[0];
        assert_eq!(claim.id, "scanner-safe-fixtures");
        assert_eq!(claim.status, "stable");
        assert_eq!(
            claim.spec.as_ref().map(|spec| spec.id.as_str()),
            Some("USELESSKEY-SPEC-0002")
        );
        assert_eq!(
            claim.generated_evidence_paths,
            vec![
                "badges/scanner-safe.json",
                "target/release-evidence/scanner-safe/proof.json"
            ]
        );
        assert!(
            report.warnings.is_empty(),
            "warnings: {:?}",
            report.warnings
        );
        Ok(())
    }

    #[test]
    fn claim_filter_selects_one_claim() -> Result<()> {
        let dir = minimal_repo()?;
        let report = build_report(dir.path(), Some("tls-contract-pack"))?;

        assert_eq!(report.claims.len(), 1);
        assert_eq!(report.claims[0].id, "tls-contract-pack");
        assert_eq!(report.filter.as_deref(), Some("tls-contract-pack"));
        Ok(())
    }

    #[test]
    fn unknown_claim_filter_fails() -> Result<()> {
        let dir = minimal_repo()?;
        let err = match build_report(dir.path(), Some("missing-claim")) {
            Ok(report) => bail!("unexpected claim report: {report:?}"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("no claim found"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[test]
    fn markdown_renders_proof_commands_and_boundaries() -> Result<()> {
        let dir = minimal_repo()?;
        let report = build_report(dir.path(), Some("scanner-safe-fixtures"))?;
        let markdown = render_markdown(&report);

        assert!(markdown.contains("# Public Claim Report"));
        assert!(markdown.contains("cargo xtask scanner-safe-reference --check"));
        assert!(markdown.contains("Scanner-safe fixture material"));
        Ok(())
    }

    #[test]
    fn public_claims_check_accepts_synced_markdown() -> Result<()> {
        let dir = minimal_repo()?;
        let report = build_report(dir.path(), None)?;
        let errors = public_claim_errors(dir.path(), &report)?;

        assert!(errors.is_empty(), "errors: {errors:?}");
        Ok(())
    }

    #[test]
    fn public_claims_check_requires_stable_claim_rows() -> Result<()> {
        let dir = minimal_repo()?;
        write_public_claims(dir.path(), "tls-contract-pack")?;
        let report = build_report(dir.path(), None)?;
        let errors = public_claim_errors(dir.path(), &report)?;

        assert!(
            errors
                .iter()
                .any(|error| error.contains("stable claim `tls-contract-pack` is missing")),
            "errors: {errors:?}"
        );
        Ok(())
    }

    #[test]
    fn public_claims_check_rejects_unknown_claim_ids() -> Result<()> {
        let dir = minimal_repo()?;
        let path = dir.path().join("docs/status/PUBLIC_CLAIMS.md");
        let mut markdown = fs::read_to_string(&path)?;
        markdown.push_str(
            "| `unknown-claim` | Unknown | `stable` | `cargo xtask unknown` | Boundary. |\n",
        );
        fs::write(&path, markdown)?;
        let report = build_report(dir.path(), None)?;
        let errors = public_claim_errors(dir.path(), &report)?;

        assert!(
            errors
                .iter()
                .any(|error| error.contains("references unknown claim `unknown-claim`")),
            "errors: {errors:?}"
        );
        Ok(())
    }

    #[test]
    fn public_claims_check_requires_all_proof_commands() -> Result<()> {
        let dir = minimal_repo()?;
        let path = dir.path().join("docs/status/PUBLIC_CLAIMS.md");
        let markdown = fs::read_to_string(&path)?.replace("; `cargo xtask badges --check`", "");
        fs::write(&path, markdown)?;
        let report = build_report(dir.path(), None)?;
        let errors = public_claim_errors(dir.path(), &report)?;

        assert!(
            errors.iter().any(|error| error.contains(
                "claim `scanner-safe-fixtures` omits proof command `cargo xtask badges --check`"
            )),
            "errors: {errors:?}"
        );
        Ok(())
    }

    fn minimal_repo() -> Result<tempfile::TempDir> {
        let dir = tempfile::tempdir()?;
        fs::create_dir_all(dir.path().join("policy"))?;
        fs::create_dir_all(dir.path().join("docs/status"))?;
        fs::create_dir_all(dir.path().join("docs/specs"))?;
        fs::create_dir_all(dir.path().join("docs/adr"))?;
        fs::create_dir_all(dir.path().join("docs/how-to"))?;

        fs::write(
            dir.path().join("policy/claim-ledger.toml"),
            r#"[[claim]]
id = "scanner-safe-fixtures"
title = "Scanner-safe fixtures"
status = "stable"
spec = "USELESSKEY-SPEC-0002"
surfaces = ["README badge"]
proof_commands = [
  "cargo xtask scanner-safe-reference --check",
  "cargo xtask badges --check",
]
artifacts = [
  "badges/scanner-safe.json",
  "target/release-evidence/scanner-safe/proof.json",
]
docs = ["docs/how-to/scanner-safe.md"]
release_lanes = ["pr", "patch"]
boundary = "Scanner-safe fixture material does not mean every derived export is safe to commit."

[[claim]]
id = "tls-contract-pack"
title = "TLS contract pack"
status = "stable"
spec = "USELESSKEY-SPEC-0002"
surfaces = ["README"]
proof_commands = ["cargo xtask bundle-proof --profile tls --out target/release-evidence/tls"]
artifacts = ["target/release-evidence/tls/proof.json"]
docs = ["docs/how-to/tls.md"]
release_lanes = ["minor"]
boundary = "TLS fixtures do not prove production PKI."
"#,
        )?;
        write_public_claims(dir.path(), "")?;
        fs::write(
            dir.path().join("docs/how-to/scanner-safe.md"),
            "# Scanner\n",
        )?;
        fs::write(dir.path().join("docs/how-to/tls.md"), "# TLS\n")?;
        fs::write(
            dir.path().join("docs/specs/USELESSKEY-SPEC-0002-claims.md"),
            r#"+++
id = "USELESSKEY-SPEC-0002"
kind = "spec"
title = "Public claim ledger"
status = "accepted"
+++

# Spec
"#,
        )?;
        fs::write(
            dir.path()
                .join("docs/adr/USELESSKEY-ADR-0001-contract-packs.md"),
            r#"+++
id = "USELESSKEY-ADR-0001"
kind = "adr"
title = "Contract packs"
status = "accepted"
+++

# ADR
"#,
        )?;

        Ok(dir)
    }

    fn write_public_claims(root: &Path, omit_id: &str) -> Result<()> {
        let mut rows = vec![
            "| `scanner-safe-fixtures` | Scanner-safe fixtures | `stable` | `cargo xtask scanner-safe-reference --check`; `cargo xtask badges --check` | Boundary. |",
            "| `tls-contract-pack` | TLS contract pack | `stable` | `cargo xtask bundle-proof --profile tls --out target/release-evidence/tls` | Boundary. |",
        ];
        rows.retain(|row| !row.contains(&format!("`{omit_id}`")));

        fs::write(
            root.join("docs/status/PUBLIC_CLAIMS.md"),
            format!(
                r#"# Public Claims

## Current Claims

| Claim ID | Claim | Status | Proof commands | Boundary |
| --- | --- | --- | --- | --- |
{}
"#,
                rows.join("\n")
            ),
        )?;
        Ok(())
    }
}
