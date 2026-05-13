use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::bundle_proof::BUNDLE_PROOF_SUPPORTED_PROFILES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Serialize)]
struct ContractPackReport {
    status: String,
    packs: Vec<ContractPackSummary>,
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ContractPackSummary {
    id: String,
    title: String,
    status: String,
    profile: String,
    spec: String,
    claim: String,
    proof_command: String,
    how_to: String,
    release_lane: String,
    boundary: String,
}

#[derive(Debug, Deserialize)]
struct ContractPackRegistry {
    #[serde(default)]
    pack: Vec<ContractPackEntry>,
}

#[derive(Debug, Deserialize)]
struct ContractPackEntry {
    id: String,
    title: String,
    status: String,
    profile: String,
    spec: String,
    claim: String,
    proof_command: String,
    how_to: String,
    release_lane: String,
    boundary: String,
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
    #[serde(default)]
    proof_commands: Vec<String>,
    #[serde(default)]
    docs: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ArtifactFrontMatter {
    id: String,
}

const VALID_PACK_STATUSES: &[&str] = &["proposed", "stable", "archived"];
const VALID_RELEASE_LANES: &[&str] = &["pr", "patch", "minor", "main", "scheduled"];

pub fn run(root: &Path, check: bool, format: OutputFormat) -> Result<()> {
    let report = build_report(root)?;

    match format {
        OutputFormat::Human => print_human_report(&report),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
    }

    if check && !report.errors.is_empty() {
        bail!(
            "contract-packs: policy/contract-packs.toml failed with {} error(s)",
            report.errors.len()
        );
    }

    Ok(())
}

fn build_report(root: &Path) -> Result<ContractPackReport> {
    let registry_path = root.join("policy/contract-packs.toml");
    let registry_text = fs::read_to_string(&registry_path)
        .with_context(|| format!("read {}", registry_path.display()))?;
    let registry: ContractPackRegistry =
        toml::from_str(&registry_text).context("parse policy/contract-packs.toml")?;

    let spec_ids = collect_spec_ids(root)?;
    let claims = collect_claims(root)?;
    let mut seen = BTreeSet::new();
    let mut errors = Vec::new();
    let mut packs = Vec::new();

    for pack in registry.pack {
        if !seen.insert(pack.id.clone()) {
            errors.push(format!("duplicate contract pack `{}`", pack.id));
        }
        validate_pack(root, &pack, &spec_ids, &claims, &mut errors);
        packs.push(ContractPackSummary {
            id: pack.id,
            title: pack.title,
            status: pack.status,
            profile: pack.profile,
            spec: pack.spec,
            claim: pack.claim,
            proof_command: pack.proof_command,
            how_to: pack.how_to,
            release_lane: pack.release_lane,
            boundary: pack.boundary,
        });
    }

    let status = if errors.is_empty() { "pass" } else { "fail" }.to_string();
    Ok(ContractPackReport {
        status,
        packs,
        errors,
    })
}

fn validate_pack(
    root: &Path,
    pack: &ContractPackEntry,
    spec_ids: &BTreeSet<String>,
    claims: &BTreeMap<String, ClaimEntry>,
    errors: &mut Vec<String>,
) {
    for (field, value) in [
        ("id", &pack.id),
        ("title", &pack.title),
        ("profile", &pack.profile),
        ("spec", &pack.spec),
        ("claim", &pack.claim),
        ("proof_command", &pack.proof_command),
        ("how_to", &pack.how_to),
        ("release_lane", &pack.release_lane),
        ("boundary", &pack.boundary),
    ] {
        if value.trim().is_empty() {
            errors.push(format!("pack `{}` has empty {field}", pack.id));
        }
    }

    if !VALID_PACK_STATUSES.contains(&pack.status.as_str()) {
        errors.push(format!(
            "pack `{}` has invalid status `{}`",
            pack.id, pack.status
        ));
    }
    if !BUNDLE_PROOF_SUPPORTED_PROFILES.contains(&pack.profile.as_str()) {
        errors.push(format!(
            "pack `{}` uses unsupported bundle-proof profile `{}`",
            pack.id, pack.profile
        ));
    }
    if !VALID_RELEASE_LANES.contains(&pack.release_lane.as_str()) {
        errors.push(format!(
            "pack `{}` has invalid release_lane `{}`",
            pack.id, pack.release_lane
        ));
    }
    if !spec_ids.contains(&pack.spec) {
        errors.push(format!(
            "pack `{}` links missing spec `{}`",
            pack.id, pack.spec
        ));
    }
    if !root
        .join(pack.how_to.replace('/', std::path::MAIN_SEPARATOR_STR))
        .exists()
    {
        errors.push(format!(
            "pack `{}` links missing how-to `{}`",
            pack.id, pack.how_to
        ));
    }
    let expected_profile_arg = format!("--profile {}", pack.profile);
    if !pack.proof_command.contains("cargo xtask bundle-proof")
        || !pack.proof_command.contains(&expected_profile_arg)
    {
        errors.push(format!(
            "pack `{}` proof_command must call bundle-proof with `{}`",
            pack.id, expected_profile_arg
        ));
    }

    let Some(claim) = claims.get(&pack.claim) else {
        errors.push(format!(
            "pack `{}` links missing claim `{}`",
            pack.id, pack.claim
        ));
        return;
    };

    if pack.status == "stable" && claim.status != "stable" {
        errors.push(format!(
            "stable pack `{}` links non-stable claim `{}` ({})",
            pack.id, pack.claim, claim.status
        ));
    }
    if !claim.proof_commands.contains(&pack.proof_command) {
        errors.push(format!(
            "pack `{}` proof_command is not listed on claim `{}`",
            pack.id, pack.claim
        ));
    }
    if !claim.docs.contains(&pack.how_to) {
        errors.push(format!(
            "pack `{}` how_to is not listed on claim `{}` docs",
            pack.id, pack.claim
        ));
    }
}

fn collect_spec_ids(root: &Path) -> Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    let dir = root.join("docs/specs");
    if !dir.exists() {
        return Ok(ids);
    }

    for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !file_name.starts_with("USELESSKEY-SPEC-") {
            continue;
        }

        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let (front, _) = split_toml_front_matter(&text)
            .with_context(|| format!("parse front matter from {}", path.display()))?;
        let parsed: ArtifactFrontMatter = toml::from_str(&front)
            .with_context(|| format!("parse TOML front matter from {}", path.display()))?;
        ids.insert(parsed.id);
    }

    Ok(ids)
}

fn collect_claims(root: &Path) -> Result<BTreeMap<String, ClaimEntry>> {
    let path = root.join("policy/claim-ledger.toml");
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let ledger: ClaimLedger = toml::from_str(&text).context("parse policy/claim-ledger.toml")?;
    Ok(ledger
        .claim
        .into_iter()
        .map(|claim| (claim.id.clone(), claim))
        .collect())
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

fn print_human_report(report: &ContractPackReport) {
    println!(
        "contract-packs: {} (packs={}, errors={})",
        report.status,
        report.packs.len(),
        report.errors.len()
    );
    println!(
        "{:<10} {:<8} {:<8} {:<28} how-to",
        "id", "status", "profile", "claim"
    );
    for pack in &report.packs {
        println!(
            "{:<10} {:<8} {:<8} {:<28} {}",
            pack.id, pack.status, pack.profile, pack.claim, pack.how_to
        );
    }
    if !report.errors.is_empty() {
        println!("\nerrors:");
        for error in &report.errors {
            println!("- {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_passes_for_supported_pack() {
        let dir = minimal_repo();
        let report = build_report(dir.path()).unwrap();

        assert_eq!(report.status, "pass");
        assert_eq!(report.packs.len(), 1);
        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
    }

    #[test]
    fn registry_rejects_unsupported_profile() {
        let dir = minimal_repo();
        replace_registry(dir.path(), "profile = \"tls\"", "profile = \"bad\"").unwrap();
        let report = build_report(dir.path()).unwrap();

        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("unsupported bundle-proof profile `bad`")),
            "errors: {:?}",
            report.errors
        );
    }

    #[test]
    fn registry_rejects_missing_how_to() {
        let dir = minimal_repo();
        fs::remove_file(dir.path().join("docs/how-to/test.md")).unwrap();
        let report = build_report(dir.path()).unwrap();

        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("links missing how-to")),
            "errors: {:?}",
            report.errors
        );
    }

    #[test]
    fn registry_rejects_unregistered_claim_proof_command() {
        let dir = minimal_repo();
        replace_registry(
            dir.path(),
            "cargo xtask bundle-proof --profile tls --out target/release-evidence/tls",
            "cargo xtask bundle-proof --profile tls --out target/other",
        )
        .unwrap();
        let report = build_report(dir.path()).unwrap();

        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("proof_command is not listed on claim")),
            "errors: {:?}",
            report.errors
        );
    }

    fn minimal_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("policy")).unwrap();
        fs::create_dir_all(dir.path().join("docs/specs")).unwrap();
        fs::create_dir_all(dir.path().join("docs/how-to")).unwrap();
        fs::write(dir.path().join("docs/how-to/test.md"), "# Test\n").unwrap();
        fs::write(
            dir.path().join("docs/specs/USELESSKEY-SPEC-0003-pack.md"),
            r#"+++
id = "USELESSKEY-SPEC-0003"
kind = "spec"
title = "Contract packs"
status = "accepted"
+++

# Spec
"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("policy/claim-ledger.toml"),
            r#"[[claim]]
id = "test-pack"
status = "stable"
proof_commands = ["cargo xtask bundle-proof --profile tls --out target/release-evidence/tls"]
docs = ["docs/how-to/test.md"]
"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("policy/contract-packs.toml"),
            r#"[[pack]]
id = "test"
title = "Test pack"
status = "stable"
profile = "tls"
spec = "USELESSKEY-SPEC-0003"
claim = "test-pack"
proof_command = "cargo xtask bundle-proof --profile tls --out target/release-evidence/tls"
how_to = "docs/how-to/test.md"
release_lane = "minor"
boundary = "Boundary."
"#,
        )
        .unwrap();
        dir
    }

    fn replace_registry(root: &Path, from: &str, to: &str) -> Result<()> {
        let path = root.join("policy/contract-packs.toml");
        let text = fs::read_to_string(&path)?;
        fs::write(path, text.replace(from, to))?;
        Ok(())
    }
}
