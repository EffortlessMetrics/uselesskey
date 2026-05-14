use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Serialize)]
struct SpecCheckReport {
    status: String,
    strict: bool,
    artifacts: Vec<ArtifactSummary>,
    claims: Vec<ClaimSummary>,
    warnings: Vec<String>,
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ArtifactSummary {
    id: String,
    kind: String,
    status: String,
    path: String,
}

#[derive(Debug, Serialize)]
struct ClaimSummary {
    id: String,
    status: String,
}

#[derive(Debug)]
struct Artifact {
    id: String,
    kind: String,
    status: String,
    path: PathBuf,
    linked_proposal: Option<String>,
    linked_specs: Vec<String>,
    linked_adrs: Vec<String>,
    linked_plan: Option<String>,
    body: String,
}

#[derive(Debug, Deserialize)]
struct ArtifactFrontMatter {
    id: String,
    kind: String,
    status: String,
    #[serde(default)]
    linked_proposal: Option<String>,
    #[serde(default)]
    linked_specs: Vec<String>,
    #[serde(default)]
    linked_adrs: Vec<String>,
    #[serde(default)]
    linked_plan: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ActiveGoal {
    id: String,
    title: String,
    status: String,
    owner: String,
    created: String,
    objective: String,
    #[serde(default)]
    end_state: Vec<String>,
    #[serde(default, rename = "work_item")]
    work_items: Vec<ActiveWorkItem>,
}

#[derive(Debug, Deserialize)]
struct ActiveWorkItem {
    id: String,
    status: String,
    proposal: Option<String>,
    spec: Option<String>,
    plan: Option<String>,
    #[serde(default)]
    commands: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ClaimLedger {
    #[serde(default)]
    claim: Vec<ClaimEntry>,
}

#[derive(Debug, Deserialize)]
struct ClaimEntry {
    id: String,
    status: String,
    spec: Option<String>,
    #[serde(default)]
    proof_commands: Vec<String>,
    boundary: Option<String>,
}

const VALID_ARTIFACT_STATUSES: &[&str] = &[
    "proposed",
    "accepted",
    "implemented",
    "superseded",
    "archived",
];

const VALID_CLAIM_STATUSES: &[&str] = &["stable", "release-proof", "advisory"];
const VALID_GOAL_STATUSES: &[&str] = &["active", "archived"];
const VALID_WORK_ITEM_STATUSES: &[&str] = &["planned", "ready", "active", "done", "blocked"];

const REQUIRED_ACCEPTED_SPEC_SECTIONS: &[&str] = &[
    "Problem",
    "Behavior",
    "Non-goals",
    "Required Evidence",
    "Acceptance",
    "Test Mapping",
    "Implementation Mapping",
    "CI Proof",
];

pub fn run(root: &Path, strict: bool, format: OutputFormat) -> Result<()> {
    let report = build_report(root, strict)?;
    match format {
        OutputFormat::Human => print_human_report(&report),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }

    if report.errors.is_empty() {
        Ok(())
    } else {
        bail!("spec-check failed with {} error(s)", report.errors.len())
    }
}

fn build_report(root: &Path, strict: bool) -> Result<SpecCheckReport> {
    let mut artifacts = Vec::new();
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    for source in artifact_sources(root)? {
        match parse_artifact(root, &source.path, source.expected_kind) {
            Ok(artifact) => artifacts.push(artifact),
            Err(err) => errors.push(format!("{}: {err}", rel_path(root, &source.path))),
        }
    }

    let mut id_to_kind = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for artifact in &artifacts {
        if !seen.insert(artifact.id.clone()) {
            errors.push(format!("duplicate artifact id `{}`", artifact.id));
        }
        id_to_kind.insert(artifact.id.clone(), artifact.kind.clone());
    }

    for artifact in &artifacts {
        validate_artifact(root, artifact, &id_to_kind, &mut errors);
    }

    let claim_summaries = validate_claim_ledger(root, &id_to_kind, &mut errors)?;
    validate_active_goal(root, &id_to_kind, &mut errors, &mut warnings)?;

    if strict && !warnings.is_empty() {
        errors.extend(warnings.iter().map(|warning| format!("strict: {warning}")));
    }

    let status = if errors.is_empty() { "pass" } else { "fail" }.to_string();
    let artifact_summaries = artifacts
        .iter()
        .map(|artifact| ArtifactSummary {
            id: artifact.id.clone(),
            kind: artifact.kind.clone(),
            status: artifact.status.clone(),
            path: rel_path(root, &artifact.path),
        })
        .collect();

    Ok(SpecCheckReport {
        status,
        strict,
        artifacts: artifact_summaries,
        claims: claim_summaries,
        warnings,
        errors,
    })
}

#[derive(Debug)]
struct ArtifactSource {
    path: PathBuf,
    expected_kind: &'static str,
}

fn artifact_sources(root: &Path) -> Result<Vec<ArtifactSource>> {
    let mut sources = Vec::new();
    collect_prefixed_markdown(
        &root.join("docs/proposals"),
        "USELESSKEY-PROP-",
        "proposal",
        &mut sources,
    )?;
    collect_prefixed_markdown(
        &root.join("docs/specs"),
        "USELESSKEY-SPEC-",
        "spec",
        &mut sources,
    )?;
    collect_prefixed_markdown(
        &root.join("docs/adr"),
        "USELESSKEY-ADR-",
        "adr",
        &mut sources,
    )?;
    collect_plan_markdown(&root.join("plans"), &mut sources)?;
    sources.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(sources)
}

fn collect_prefixed_markdown(
    dir: &Path,
    prefix: &str,
    expected_kind: &'static str,
    sources: &mut Vec<ArtifactSource>,
) -> Result<()> {
    if !dir.exists() {
        return Ok(());
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
        if file_name.starts_with(prefix) {
            sources.push(ArtifactSource {
                path,
                expected_kind,
            });
        }
    }
    Ok(())
}

fn collect_plan_markdown(dir: &Path, sources: &mut Vec<ArtifactSource>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|name| name.to_str()) != Some("templates") {
                collect_plan_markdown(&path, sources)?;
            }
            continue;
        }
        if path.file_name().and_then(|name| name.to_str()) == Some("README.md") {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) == Some("md") {
            sources.push(ArtifactSource {
                path,
                expected_kind: "plan",
            });
        }
    }
    Ok(())
}

fn parse_artifact(root: &Path, path: &Path, expected_kind: &str) -> Result<Artifact> {
    let content = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let (front_matter, body) = split_toml_front_matter(&content)
        .with_context(|| "missing TOML front matter delimited by +++")?;
    let parsed: ArtifactFrontMatter =
        toml::from_str(&front_matter).with_context(|| "invalid TOML front matter".to_string())?;
    if parsed.kind != expected_kind {
        bail!(
            "kind `{}` does not match expected `{expected_kind}`",
            parsed.kind
        );
    }
    let rel = rel_path(root, path);
    if parsed.id.trim().is_empty() {
        bail!("empty id in {rel}");
    }
    Ok(Artifact {
        id: parsed.id,
        kind: parsed.kind,
        status: parsed.status,
        path: path.to_path_buf(),
        linked_proposal: parsed.linked_proposal,
        linked_specs: parsed.linked_specs,
        linked_adrs: parsed.linked_adrs,
        linked_plan: parsed.linked_plan,
        body,
    })
}

fn split_toml_front_matter(content: &str) -> Result<(String, String)> {
    let mut lines = content.lines();
    let Some(first) = lines.next() else {
        bail!("empty document");
    };
    if first.trim() != "+++" {
        bail!("first line is not +++");
    }

    let mut front = Vec::new();
    for line in &mut lines {
        if line.trim() == "+++" {
            let body = lines.collect::<Vec<_>>().join("\n");
            return Ok((front.join("\n"), body));
        }
        front.push(line);
    }
    bail!("unterminated TOML front matter")
}

fn validate_artifact(
    root: &Path,
    artifact: &Artifact,
    id_to_kind: &BTreeMap<String, String>,
    errors: &mut Vec<String>,
) {
    let path = rel_path(root, &artifact.path);
    if !VALID_ARTIFACT_STATUSES.contains(&artifact.status.as_str()) {
        errors.push(format!(
            "{path}: invalid status `{}` for `{}`",
            artifact.status, artifact.id
        ));
    }

    if let Some(linked_proposal) = &artifact.linked_proposal {
        validate_link(
            &path,
            &artifact.id,
            "proposal",
            linked_proposal,
            id_to_kind,
            errors,
        );
    }
    for linked_spec in &artifact.linked_specs {
        validate_link(&path, &artifact.id, "spec", linked_spec, id_to_kind, errors);
    }
    for linked_adr in &artifact.linked_adrs {
        validate_link(&path, &artifact.id, "adr", linked_adr, id_to_kind, errors);
    }
    if let Some(linked_plan) = &artifact.linked_plan {
        let linked_plan_path = root.join(linked_plan.replace('/', std::path::MAIN_SEPARATOR_STR));
        if !linked_plan_path.exists() {
            errors.push(format!(
                "{path}: `{}` links missing plan `{linked_plan}`",
                artifact.id
            ));
        }
    }

    if artifact.kind == "spec" && artifact.status == "accepted" {
        for section in REQUIRED_ACCEPTED_SPEC_SECTIONS {
            if !has_heading(&artifact.body, section) {
                errors.push(format!(
                    "{path}: accepted spec `{}` missing `## {section}`",
                    artifact.id
                ));
            }
        }
    }
}

fn validate_link(
    path: &str,
    source_id: &str,
    expected_kind: &str,
    linked_id: &str,
    id_to_kind: &BTreeMap<String, String>,
    errors: &mut Vec<String>,
) {
    match id_to_kind.get(linked_id) {
        Some(kind) if kind == expected_kind => {}
        Some(kind) => errors.push(format!(
            "{path}: `{source_id}` links `{linked_id}` as {expected_kind}, but it is {kind}"
        )),
        None => errors.push(format!(
            "{path}: `{source_id}` links missing {expected_kind} `{linked_id}`"
        )),
    }
}

fn has_heading(body: &str, expected: &str) -> bool {
    let expected = format!("## {}", expected).to_ascii_lowercase();
    body.lines()
        .map(|line| line.trim().to_ascii_lowercase())
        .any(|line| line == expected)
}

fn validate_claim_ledger(
    root: &Path,
    id_to_kind: &BTreeMap<String, String>,
    errors: &mut Vec<String>,
) -> Result<Vec<ClaimSummary>> {
    let path = root.join("policy/claim-ledger.toml");
    if !path.exists() {
        errors.push("policy/claim-ledger.toml is missing".to_string());
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let ledger: ClaimLedger = toml::from_str(&text).context("parse policy/claim-ledger.toml")?;
    let mut seen = BTreeSet::new();
    let mut summaries = Vec::new();

    for claim in ledger.claim {
        if !seen.insert(claim.id.clone()) {
            errors.push(format!(
                "policy/claim-ledger.toml: duplicate claim `{}`",
                claim.id
            ));
        }
        if !VALID_CLAIM_STATUSES.contains(&claim.status.as_str()) {
            errors.push(format!(
                "policy/claim-ledger.toml: claim `{}` has invalid status `{}`",
                claim.id, claim.status
            ));
        }
        if claim.proof_commands.is_empty() {
            errors.push(format!(
                "policy/claim-ledger.toml: claim `{}` has no proof_commands",
                claim.id
            ));
        }
        if claim
            .boundary
            .as_ref()
            .is_none_or(|boundary| boundary.trim().is_empty())
        {
            errors.push(format!(
                "policy/claim-ledger.toml: claim `{}` has an empty boundary",
                claim.id
            ));
        }
        if let Some(spec) = &claim.spec {
            validate_link(
                "policy/claim-ledger.toml",
                &claim.id,
                "spec",
                spec,
                id_to_kind,
                errors,
            );
        }
        summaries.push(ClaimSummary {
            id: claim.id,
            status: claim.status,
        });
    }

    Ok(summaries)
}

fn validate_active_goal(
    root: &Path,
    id_to_kind: &BTreeMap<String, String>,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let path = root.join(".uselesskey/goals/active.toml");
    if !path.exists() {
        warnings.push(".uselesskey/goals/active.toml is missing".to_string());
        return Ok(());
    }
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let active: ActiveGoal =
        toml::from_str(&text).context("parse .uselesskey/goals/active.toml")?;

    for (field, value) in [
        ("id", &active.id),
        ("title", &active.title),
        ("owner", &active.owner),
        ("created", &active.created),
        ("objective", &active.objective),
    ] {
        if value.trim().is_empty() {
            errors.push(format!(".uselesskey/goals/active.toml: empty {field}"));
        }
    }
    if !VALID_GOAL_STATUSES.contains(&active.status.as_str()) {
        errors.push(format!(
            ".uselesskey/goals/active.toml: invalid status `{}`",
            active.status
        ));
    }
    if active.end_state.is_empty() {
        errors.push(".uselesskey/goals/active.toml: end_state is empty".to_string());
    }
    if active.work_items.is_empty() {
        errors.push(".uselesskey/goals/active.toml: no work_item entries".to_string());
    }

    for item in active.work_items {
        if item.id.trim().is_empty() {
            errors.push(".uselesskey/goals/active.toml: work_item with empty id".to_string());
        }
        if !VALID_WORK_ITEM_STATUSES.contains(&item.status.as_str()) {
            errors.push(format!(
                ".uselesskey/goals/active.toml: work_item `{}` has invalid status `{}`",
                item.id, item.status
            ));
        }
        match item.proposal.as_deref() {
            Some(proposal) => validate_link(
                ".uselesskey/goals/active.toml",
                &item.id,
                "proposal",
                proposal,
                id_to_kind,
                errors,
            ),
            None => errors.push(format!(
                ".uselesskey/goals/active.toml: work_item `{}` missing proposal",
                item.id
            )),
        }
        match item.spec.as_deref() {
            Some(spec) => validate_link(
                ".uselesskey/goals/active.toml",
                &item.id,
                "spec",
                spec,
                id_to_kind,
                errors,
            ),
            None => errors.push(format!(
                ".uselesskey/goals/active.toml: work_item `{}` missing spec",
                item.id
            )),
        }
        match item.plan.as_deref() {
            Some(plan) => {
                let plan_path = root.join(plan.replace('/', std::path::MAIN_SEPARATOR_STR));
                if !plan_path.exists() {
                    errors.push(format!(
                        ".uselesskey/goals/active.toml: work_item `{}` links missing plan `{plan}`",
                        item.id
                    ));
                }
            }
            None => errors.push(format!(
                ".uselesskey/goals/active.toml: work_item `{}` missing plan",
                item.id
            )),
        }
        if item.commands.is_empty() {
            errors.push(format!(
                ".uselesskey/goals/active.toml: work_item `{}` has no commands",
                item.id
            ));
        }
    }

    Ok(())
}

fn print_human_report(report: &SpecCheckReport) {
    println!(
        "spec-check: {} (artifacts={}, claims={}, warnings={}, errors={})",
        report.status,
        report.artifacts.len(),
        report.claims.len(),
        report.warnings.len(),
        report.errors.len()
    );
    println!("{:<22} {:<10} {:<12} path", "id", "kind", "status");
    for artifact in &report.artifacts {
        println!(
            "{:<22} {:<10} {:<12} {}",
            artifact.id, artifact.kind, artifact.status, artifact.path
        );
    }
    if !report.claims.is_empty() {
        println!("\nclaims:");
        for claim in &report.claims {
            println!("- {} ({})", claim.id, claim.status);
        }
    }
    if !report.warnings.is_empty() {
        println!("\nwarnings:");
        for warning in &report.warnings {
            println!("- {warning}");
        }
    }
    if !report.errors.is_empty() {
        println!("\nerrors:");
        for error in &report.errors {
            println!("- {error}");
        }
    }
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
    fn split_toml_front_matter_extracts_body() -> Result<()> {
        let input = "+++\nid = \"X\"\n+++\n# Title\n";
        let (front, body) = split_toml_front_matter(input)?;
        assert_eq!(front, "id = \"X\"");
        assert_eq!(body, "# Title");
        Ok(())
    }

    #[test]
    fn heading_match_is_case_insensitive() -> Result<()> {
        let body = "## Problem\n\n## Required Evidence\n";
        assert!(has_heading(body, "problem"));
        assert!(has_heading(body, "required evidence"));
        assert!(!has_heading(body, "CI Proof"));
        Ok(())
    }

    #[test]
    fn minimal_spec_system_passes() -> Result<()> {
        let dir = tempfile::tempdir()?;
        write_minimal_repo(dir.path(), full_spec_body())?;
        let report = build_report(dir.path(), false)?;
        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
        assert_eq!(report.artifacts.len(), 4);
        assert_eq!(report.claims.len(), 1);
        Ok(())
    }

    #[test]
    fn accepted_spec_requires_required_sections() -> Result<()> {
        let dir = tempfile::tempdir()?;
        write_minimal_repo(dir.path(), "## Problem\n\n## Behavior\n")?;
        let report = build_report(dir.path(), false)?;
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("missing `## CI Proof`")),
            "errors: {:?}",
            report.errors
        );
        Ok(())
    }

    fn write_minimal_repo(root: &Path, spec_body: &str) -> Result<()> {
        fs::create_dir_all(root.join("docs/proposals"))?;
        fs::create_dir_all(root.join("docs/specs"))?;
        fs::create_dir_all(root.join("docs/adr"))?;
        fs::create_dir_all(root.join("plans/example"))?;
        fs::create_dir_all(root.join(".uselesskey/goals"))?;
        fs::create_dir_all(root.join("policy"))?;

        fs::write(
            root.join("docs/proposals/USELESSKEY-PROP-0001-test.md"),
            r#"+++
id = "USELESSKEY-PROP-0001"
kind = "proposal"
status = "proposed"
linked_specs = ["USELESSKEY-SPEC-0001"]
linked_adrs = ["USELESSKEY-ADR-0001"]
linked_plan = "plans/example/implementation-plan.md"
+++

# Proposal
"#,
        )?;
        fs::write(
            root.join("docs/specs/USELESSKEY-SPEC-0001-test.md"),
            format!(
                r#"+++
id = "USELESSKEY-SPEC-0001"
kind = "spec"
status = "accepted"
linked_proposal = "USELESSKEY-PROP-0001"
linked_adrs = ["USELESSKEY-ADR-0001"]
linked_plan = "plans/example/implementation-plan.md"
+++

# Spec

{spec_body}
"#
            ),
        )?;
        fs::write(
            root.join("docs/adr/USELESSKEY-ADR-0001-test.md"),
            r#"+++
id = "USELESSKEY-ADR-0001"
kind = "adr"
status = "accepted"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = ["USELESSKEY-SPEC-0001"]
+++

# ADR
"#,
        )?;
        fs::write(
            root.join("plans/example/implementation-plan.md"),
            r#"+++
id = "USELESSKEY-PLAN-0001"
kind = "plan"
status = "accepted"
linked_proposal = "USELESSKEY-PROP-0001"
linked_specs = ["USELESSKEY-SPEC-0001"]
linked_adrs = ["USELESSKEY-ADR-0001"]
+++

# Plan
"#,
        )?;
        fs::write(
            root.join(".uselesskey/goals/active.toml"),
            r#"id = "test"
title = "Test"
status = "active"
owner = "EffortlessMetrics"
created = "2026-05-13"
objective = "Test."
end_state = ["done"]

[[work_item]]
id = "work"
status = "active"
proposal = "USELESSKEY-PROP-0001"
spec = "USELESSKEY-SPEC-0001"
plan = "plans/example/implementation-plan.md"
commands = ["cargo xtask spec-check"]
"#,
        )?;
        fs::write(
            root.join("policy/claim-ledger.toml"),
            r#"[[claim]]
id = "claim"
status = "stable"
spec = "USELESSKEY-SPEC-0001"
proof_commands = ["cargo xtask spec-check"]
boundary = "Boundary."
"#,
        )?;
        Ok(())
    }

    fn full_spec_body() -> &'static str {
        r#"## Problem

## Behavior

## Non-goals

## Required Evidence

## Acceptance

## Test Mapping

## Implementation Mapping

## CI Proof
"#
    }
}
