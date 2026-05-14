use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use regex::Regex;
use serde::Serialize;

use crate::write_json_pretty;

const REPORT_JSON: &str = "target/ripr/reports/test-efficiency.json";
const REPORT_MD: &str = "target/ripr/reports/test-efficiency.md";

const REASON_KEYS: &[&str] = &[
    "assertion_may_not_match_detected_owner",
    "broad_oracle",
    "duplicate_activation_and_oracle_shape",
    "expected_value_computed_from_detected_owner_path",
    "no_assertion_detected",
    "opaque_helper_or_fixture_boundary",
    "relational_oracle",
    "smoke_oracle_only",
];

#[derive(Clone, Debug, Serialize)]
struct TestEfficiencyReport {
    schema_version: &'static str,
    status: &'static str,
    advisory: bool,
    counts: BTreeMap<&'static str, usize>,
    reason_counts: BTreeMap<&'static str, usize>,
    tests: Vec<TestEfficiencyEntry>,
    metrics: TestEfficiencyMetrics,
}

#[derive(Clone, Debug, Serialize)]
struct TestEfficiencyEntry {
    path: String,
    name: String,
    line: usize,
    class: &'static str,
    oracle_kind: &'static str,
    oracle_strength: &'static str,
    reached_owners: Vec<String>,
    reasons: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
struct TestEfficiencyMetrics {
    tests_scanned: usize,
    duplicate_discriminator_groups: usize,
    reason_counts: BTreeMap<&'static str, usize>,
}

#[derive(Clone, Debug)]
struct TestFunction {
    path: String,
    name: String,
    line: usize,
    body: String,
}

pub(crate) fn test_efficiency_report_cmd() -> Result<()> {
    let root = crate::workspace_root_path();
    write_test_efficiency_report(&root)
}

pub(crate) fn write_test_efficiency_report(root: &Path) -> Result<()> {
    let report = build_report(root)?;
    let json_path = root.join(REPORT_JSON);
    let md_path = root.join(REPORT_MD);

    write_json_pretty(&json_path, &report)?;
    fs::write(&md_path, render_markdown(&report))
        .with_context(|| format!("failed to write {}", md_path.display()))?;

    println!(
        "test-efficiency-report: scanned {} tests; wrote {} and {}",
        report.metrics.tests_scanned,
        json_path.display(),
        md_path.display()
    );
    Ok(())
}

fn build_report(root: &Path) -> Result<TestEfficiencyReport> {
    let mut tests = Vec::new();
    let fn_regex = Regex::new(r"\b(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
        .context("valid function regex")?;

    for path in rust_files(root)? {
        collect_tests_from_file(root, &path, &fn_regex, &mut tests)?;
    }

    tests.sort_by(|a, b| a.path.cmp(&b.path).then(a.line.cmp(&b.line)));

    let mut entries: Vec<TestEfficiencyEntry> = tests.iter().map(classify_test).collect();
    let duplicate_groups = mark_duplicate_entries(&mut entries);

    let mut counts = class_counts();
    let mut reason_counts = reason_counts();
    for entry in &entries {
        *counts.entry(entry.class).or_insert(0) += 1;
        for reason in &entry.reasons {
            *reason_counts.entry(reason).or_insert(0) += 1;
        }
    }

    Ok(TestEfficiencyReport {
        schema_version: "0.1",
        status: "warn",
        advisory: true,
        counts,
        reason_counts: reason_counts.clone(),
        metrics: TestEfficiencyMetrics {
            tests_scanned: entries.len(),
            duplicate_discriminator_groups: duplicate_groups,
            reason_counts,
        },
        tests: entries,
    })
}

fn rust_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_rust_files(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_rust_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry =
            entry.with_context(|| format!("failed to read entry under {}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if file_type.is_dir() {
            if should_skip_dir(root, &path) {
                continue;
            }
            collect_rust_files(root, &path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn should_skip_dir(root: &Path, path: &Path) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components().any(|component| {
        let name = component.as_os_str().to_string_lossy();
        matches!(
            name.as_ref(),
            ".git" | ".github" | ".idea" | ".vscode" | "target"
        )
    })
}

fn collect_tests_from_file(
    root: &Path,
    path: &Path,
    fn_regex: &Regex,
    out: &mut Vec<TestFunction>,
) -> Result<()> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let lines: Vec<&str> = text.lines().collect();
    let mut pending_test_attr = false;
    let mut idx = 0usize;
    while idx < lines.len() {
        let trimmed = lines[idx].trim();
        if trimmed.starts_with("#[") {
            if is_test_attr(trimmed) {
                pending_test_attr = true;
            }
            idx += 1;
            continue;
        }

        if pending_test_attr
            && let Some(caps) = fn_regex.captures(lines[idx])
            && let Some(name) = caps.get(1)
        {
            let (body, end_idx) = extract_function_body(&lines, idx);
            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            out.push(TestFunction {
                path: rel,
                name: name.as_str().to_string(),
                line: idx + 1,
                body,
            });
            pending_test_attr = false;
            idx = end_idx.saturating_add(1);
            continue;
        }

        if !trimmed.is_empty() && !trimmed.starts_with("//") {
            pending_test_attr = false;
        }
        idx += 1;
    }
    Ok(())
}

fn is_test_attr(trimmed: &str) -> bool {
    trimmed == "#[test]"
        || trimmed.starts_with("#[rstest")
        || trimmed.contains("::test")
        || trimmed.starts_with("#[tokio::test")
        || trimmed.starts_with("#[async_std::test")
}

fn extract_function_body(lines: &[&str], start: usize) -> (String, usize) {
    let mut body = String::new();
    let mut depth = 0isize;
    let mut saw_open = false;
    let mut end = start;
    for (idx, line) in lines.iter().enumerate().skip(start) {
        body.push_str(line);
        body.push('\n');
        for ch in line.chars() {
            match ch {
                '{' => {
                    saw_open = true;
                    depth += 1;
                }
                '}' if saw_open => depth -= 1,
                _ => {}
            }
        }
        end = idx;
        if saw_open && depth <= 0 {
            break;
        }
    }
    (body, end)
}

fn classify_test(test: &TestFunction) -> TestEfficiencyEntry {
    let body = test.body.as_str();
    let mut reasons = Vec::new();

    let (class, oracle_kind, oracle_strength) = if has_no_assertion(body) {
        reasons.push("no_assertion_detected");
        reasons.push("smoke_oracle_only");
        ("smoke_only", "no explicit assertion", "weak")
    } else if is_broad_assertion(body) {
        reasons.push("assertion_may_not_match_detected_owner");
        reasons.push("broad_oracle");
        ("useful_but_broad", "broad predicate", "weak")
    } else {
        ("strong_discriminator", "specific assertion", "strong")
    };

    TestEfficiencyEntry {
        path: test.path.clone(),
        name: test.name.clone(),
        line: test.line,
        class,
        oracle_kind,
        oracle_strength,
        reached_owners: reached_owners(test),
        reasons,
    }
}

fn has_no_assertion(body: &str) -> bool {
    ![
        "assert!",
        "assert_eq!",
        "assert_ne!",
        "debug_assert!",
        "matches!",
        "panic!",
        "should_panic",
        "insta::assert",
        "expect_err(",
    ]
    .iter()
    .any(|needle| body.contains(needle))
}

fn is_broad_assertion(body: &str) -> bool {
    body.contains("assert!(")
        && [
            ".contains(",
            ".starts_with(",
            ".ends_with(",
            ".is_empty(",
            ".is_some(",
            ".is_none(",
            ".is_ok(",
            ".is_err(",
            "> 0",
            ">= 1",
        ]
        .iter()
        .any(|needle| body.contains(needle))
}

fn reached_owners(test: &TestFunction) -> Vec<String> {
    let mut owners = BTreeSet::new();
    for segment in test.path.split('/') {
        if let Some(name) = segment.strip_prefix("uselesskey-") {
            owners.insert(format!("uselesskey-{name}"));
        }
    }
    if test.path.starts_with("xtask/") {
        owners.insert("xtask".to_string());
    }
    if test.path.starts_with("tests/") {
        owners.insert("workspace-tests".to_string());
    }
    owners.into_iter().collect()
}

fn mark_duplicate_entries(entries: &mut [TestEfficiencyEntry]) -> usize {
    let mut signatures: BTreeMap<(String, Vec<String>), Vec<usize>> = BTreeMap::new();
    for (idx, entry) in entries.iter().enumerate() {
        if entry.class == "strong_discriminator" || entry.class == "useful_but_broad" {
            signatures
                .entry((entry.name.clone(), entry.reached_owners.clone()))
                .or_default()
                .push(idx);
        }
    }

    let mut duplicate_groups = 0usize;
    for indexes in signatures.values() {
        if indexes.len() <= 1 {
            continue;
        }
        duplicate_groups += 1;
        for idx in indexes.iter().skip(1) {
            let entry = &mut entries[*idx];
            entry.class = "duplicative";
            entry.oracle_kind = "duplicative assertion";
            entry.oracle_strength = "weak";
            if !entry
                .reasons
                .contains(&"duplicate_activation_and_oracle_shape")
            {
                entry.reasons.push("duplicate_activation_and_oracle_shape");
            }
        }
    }
    duplicate_groups
}

fn class_counts() -> BTreeMap<&'static str, usize> {
    [
        "strong_discriminator",
        "useful_but_broad",
        "smoke_only",
        "likely_vacuous",
        "possibly_circular",
        "duplicative",
        "opaque",
    ]
    .into_iter()
    .map(|key| (key, 0))
    .collect()
}

fn reason_counts() -> BTreeMap<&'static str, usize> {
    REASON_KEYS.iter().copied().map(|key| (key, 0)).collect()
}

fn render_markdown(report: &TestEfficiencyReport) -> String {
    let mut out = String::new();
    out.push_str("# ripr test efficiency report\n\n");
    out.push_str(&format!("Status: {}\n\n", report.status));
    out.push_str("Mode: advisory\n\n");
    out.push_str(
        "This report is generated by `cargo xtask test-efficiency-report` for the public `ripr+` badge. It is static evidence for test-oracle efficiency and is not a runtime proof.\n\n",
    );
    out.push_str("## Summary\n\n");
    for (class, count) in &report.counts {
        out.push_str(&format!("- `{class}`: {count}\n"));
    }
    out.push_str(&format!(
        "- Tests scanned: {}\n",
        report.metrics.tests_scanned
    ));
    out.push_str(&format!(
        "- Duplicate discriminator groups: {}\n\n",
        report.metrics.duplicate_discriminator_groups
    ));
    out.push_str("## Signal Reasons\n\n");
    for (reason, count) in &report.reason_counts {
        out.push_str(&format!("- `{reason}`: {count}\n"));
    }
    out.push('\n');
    out.push_str("## Static Limitations\n\n");
    for entry in report.tests.iter().filter(|entry| {
        matches!(
            entry.class,
            "smoke_only" | "likely_vacuous" | "possibly_circular" | "duplicative" | "opaque"
        )
    }) {
        out.push_str(&format!(
            "- `{}`:{} `{}` classified `{}`\n",
            entry.path, entry.line, entry.name, entry.class
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifier_counts_smoke_tests_as_actionable() {
        let test = TestFunction {
            path: "crates/uselesskey-core/src/lib.rs".to_string(),
            name: "smoke".to_string(),
            line: 10,
            body: "#[test]\nfn smoke() { build_fixture(); }\n".to_string(),
        };

        let entry = classify_test(&test);

        assert_eq!(entry.class, "smoke_only");
        assert!(entry.reasons.contains(&"no_assertion_detected"));
    }

    #[test]
    fn classifier_keeps_specific_assertions_strong() {
        let test = TestFunction {
            path: "tests/facade.rs".to_string(),
            name: "specific".to_string(),
            line: 7,
            body: "#[test]\nfn specific() { assert_eq!(value(), 42); }\n".to_string(),
        };

        let entry = classify_test(&test);

        assert_eq!(entry.class, "strong_discriminator");
        assert_eq!(entry.reached_owners, vec!["workspace-tests"]);
    }

    #[test]
    fn broad_assertions_are_visible_but_not_actionable() {
        let test = TestFunction {
            path: "xtask/src/main.rs".to_string(),
            name: "broad".to_string(),
            line: 12,
            body: "#[test]\nfn broad() { assert!(markdown.contains(\"Header\")); }\n".to_string(),
        };

        let entry = classify_test(&test);

        assert_eq!(entry.class, "useful_but_broad");
        assert!(entry.reasons.contains(&"broad_oracle"));
    }
}
