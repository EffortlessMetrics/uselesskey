use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::{claim_proof, claim_report, contract_packs, git_head_sha};

#[derive(Debug, Deserialize)]
struct ClaimLedger {
    #[serde(default)]
    claim: Vec<ClaimEntry>,
    #[serde(default)]
    claim_proof: Vec<ClaimProofPolicy>,
}

#[derive(Debug, Deserialize)]
struct ClaimEntry {
    id: String,
    title: String,
    status: String,
    boundary: String,
}

#[derive(Debug, Deserialize)]
struct ClaimProofPolicy {
    claim: String,
    #[serde(default)]
    include_in_all_stable: bool,
}

pub(crate) fn run(root: &Path, out: &Path, claim: Option<&str>) -> Result<()> {
    if let Some(claim) = claim {
        validate_claim_id(claim)?;
    }

    let out_dir = prepare_out_dir(root, out)?;
    let ledger = read_ledger(root)?;
    let selected_claims = selected_claims(&ledger, claim)?;

    claim_report::write_target_receipt(root, claim)?;
    contract_packs::write_target_receipt(root)?;
    if let Some(claim) = claim {
        claim_proof::run(root, Some(claim), false)?;
    } else {
        claim_proof::run(root, None, true)?;
    }

    copy_receipt_file(
        root,
        "target/claim-report/public-claims.json",
        &out_dir.join("public-claims.json"),
    )?;
    copy_receipt_file(
        root,
        "target/claim-report/public-claims.md",
        &out_dir.join("public-claims.md"),
    )?;
    copy_receipt_file(
        root,
        "target/contract-packs/contract-packs.json",
        &out_dir.join("contract-packs.json"),
    )?;
    copy_receipt_file(
        root,
        "target/contract-packs/contract-packs.md",
        &out_dir.join("contract-packs.md"),
    )?;
    copy_receipt_file(
        root,
        "badges/ripr-plus.json",
        &out_dir.join("badges/ripr-plus.json"),
    )?;
    copy_receipt_file(
        root,
        "badges/scanner-safe.json",
        &out_dir.join("badges/scanner-safe.json"),
    )?;

    for claim in &selected_claims {
        copy_claim_proof_receipt(root, &claim.id, &out_dir)?;
    }

    fs::write(
        out_dir.join("README.md"),
        render_readme(&out_dir, &selected_claims),
    )
    .with_context(|| format!("write {}", out_dir.join("README.md").display()))?;

    ensure_no_forbidden_payload_paths(&out_dir)?;
    println!("verification-pack: wrote {}", rel_path(root, &out_dir));
    Ok(())
}

fn read_ledger(root: &Path) -> Result<ClaimLedger> {
    let path = root.join("policy/claim-ledger.toml");
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    toml::from_str(&text).context("parse policy/claim-ledger.toml")
}

fn selected_claims(ledger: &ClaimLedger, claim_filter: Option<&str>) -> Result<Vec<ClaimEntry>> {
    let claims = ledger
        .claim
        .iter()
        .map(|claim| (claim.id.as_str(), claim))
        .collect::<BTreeMap<_, _>>();

    if let Some(claim_id) = claim_filter {
        let claim = claims
            .get(claim_id)
            .with_context(|| format!("unknown claim `{claim_id}`"))?;
        return Ok(vec![ClaimEntry {
            id: claim.id.clone(),
            title: claim.title.clone(),
            status: claim.status.clone(),
            boundary: claim.boundary.clone(),
        }]);
    }

    let proof_policies = ledger
        .claim_proof
        .iter()
        .map(|policy| (policy.claim.as_str(), policy))
        .collect::<BTreeMap<_, _>>();
    let mut selected = Vec::new();
    for claim in ledger.claim.iter().filter(|claim| claim.status == "stable") {
        let Some(policy) = proof_policies.get(claim.id.as_str()) else {
            bail!("stable claim `{}` has no claim-proof policy", claim.id);
        };
        if policy.include_in_all_stable {
            selected.push(ClaimEntry {
                id: claim.id.clone(),
                title: claim.title.clone(),
                status: claim.status.clone(),
                boundary: claim.boundary.clone(),
            });
        }
    }

    if selected.is_empty() {
        bail!("verification-pack: no stable claims selected");
    }

    Ok(selected)
}

fn prepare_out_dir(root: &Path, out: &Path) -> Result<PathBuf> {
    let out_dir = if out.is_absolute() {
        out.to_path_buf()
    } else {
        root.join(out)
    };

    let target_root = root.join("target");
    fs::create_dir_all(&target_root)
        .with_context(|| format!("create {}", target_root.display()))?;

    if out_dir.exists() {
        let out_canonical = out_dir
            .canonicalize()
            .with_context(|| format!("canonicalize {}", out_dir.display()))?;
        let target_canonical = target_root
            .canonicalize()
            .with_context(|| format!("canonicalize {}", target_root.display()))?;
        if out_canonical == target_canonical {
            bail!("verification-pack: refusing to use target root as output directory");
        }
        if is_within_existing_dir(&out_dir, &target_root)? {
            fs::remove_dir_all(&out_dir)
                .with_context(|| format!("remove {}", out_dir.display()))?;
        } else if fs::read_dir(&out_dir)
            .with_context(|| format!("read {}", out_dir.display()))?
            .next()
            .is_some()
        {
            bail!(
                "verification-pack: non-target output directory must be empty: {}",
                out_dir.display()
            );
        }
    }

    fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    Ok(out_dir)
}

fn is_within_existing_dir(path: &Path, parent: &Path) -> Result<bool> {
    let path = path
        .canonicalize()
        .with_context(|| format!("canonicalize {}", path.display()))?;
    let parent = parent
        .canonicalize()
        .with_context(|| format!("canonicalize {}", parent.display()))?;
    Ok(path.starts_with(parent))
}

fn copy_receipt_file(root: &Path, src_rel: &str, dst: &Path) -> Result<()> {
    if forbidden_payload_path(src_rel) {
        bail!("verification-pack: refusing to copy payload path `{src_rel}`");
    }

    let src = root.join(src_rel.replace('/', std::path::MAIN_SEPARATOR_STR));
    if !src.exists() {
        bail!("verification-pack: missing receipt `{src_rel}`");
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::copy(&src, dst).with_context(|| format!("copy {} to {}", src.display(), dst.display()))?;
    Ok(())
}

fn copy_claim_proof_receipt(root: &Path, claim: &str, out_dir: &Path) -> Result<()> {
    validate_claim_id(claim)?;
    let dst_dir = out_dir.join("claim-proof").join(claim);
    copy_receipt_file(
        root,
        &format!("target/claim-proof/{claim}/receipt.json"),
        &dst_dir.join("receipt.json"),
    )?;
    copy_receipt_file(
        root,
        &format!("target/claim-proof/{claim}/receipt.md"),
        &dst_dir.join("receipt.md"),
    )?;
    Ok(())
}

fn render_readme(out_dir: &Path, claims: &[ClaimEntry]) -> String {
    let mut md = String::new();
    md.push_str("# `uselesskey` Verification Pack\n\n");
    md.push_str("This pack contains public-claim receipts and metadata only.\n");
    md.push_str("It intentionally excludes generated fixture payloads.\n\n");
    md.push_str("## Generation\n\n");
    md.push_str(&format!("- Output: `{}`\n", out_dir.display()));
    if let Ok(sha) = git_head_sha() {
        md.push_str(&format!("- Git SHA: `{sha}`\n"));
    }

    md.push_str("\n## Commands\n\n");
    md.push_str("```bash\n");
    md.push_str("cargo xtask claim-report\n");
    md.push_str("cargo xtask contract-packs --check\n");
    md.push_str("cargo xtask badges --check\n");
    if claims.len() == 1 {
        md.push_str(&format!(
            "cargo xtask claim-proof --claim {}\n",
            claims[0].id
        ));
    } else {
        md.push_str("cargo xtask claim-proof --all-stable\n");
    }
    md.push_str("```\n\n");

    md.push_str("## Contents\n\n");
    md.push_str("- `public-claims.md` and `public-claims.json`\n");
    md.push_str("- `contract-packs.md` and `contract-packs.json`\n");
    md.push_str("- `badges/*.json`\n");
    md.push_str("- `claim-proof/<claim>/receipt.md` and `.json`\n\n");

    md.push_str("## Included Claims\n\n");
    md.push_str("| Claim | Status | Boundary |\n");
    md.push_str("| --- | --- | --- |\n");
    for claim in claims {
        md.push_str(&format!(
            "| `{}` | `{}` | {} |\n",
            claim.id, claim.status, claim.boundary
        ));
    }

    md.push_str("\n## Exclusions\n\n");
    md.push_str("This pack must not include generated fixture payloads such as PEM, DER, ");
    md.push_str("private-key files, JWT-shaped payloads, Kubernetes secrets, Vault exports, ");
    md.push_str("or bundle materialization directories.\n");

    md
}

fn ensure_no_forbidden_payload_paths(out_dir: &Path) -> Result<()> {
    for path in walk_files(out_dir)? {
        let rel = path
            .strip_prefix(out_dir)
            .unwrap_or(path.as_path())
            .to_string_lossy()
            .replace('\\', "/");
        if forbidden_payload_path(&rel) {
            bail!("verification-pack: forbidden payload path in pack `{rel}`");
        }
    }
    Ok(())
}

fn walk_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if !dir.exists() {
        return Ok(files);
    }
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            files.extend(walk_files(&path)?);
        } else {
            files.push(path);
        }
    }
    Ok(files)
}

fn forbidden_payload_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    if normalized.contains("/bundle/") || normalized.ends_with("/bundle") {
        return true;
    }
    if normalized.contains("secret.yaml") || normalized.contains("vault") {
        return true;
    }
    matches!(
        Path::new(&normalized)
            .extension()
            .and_then(|ext| ext.to_str()),
        Some("pem" | "der" | "key" | "pkcs8" | "jwt")
    )
}

fn validate_claim_id(claim_id: &str) -> Result<()> {
    if claim_id.is_empty()
        || !claim_id
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        bail!("invalid claim id `{claim_id}`");
    }
    Ok(())
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
    fn default_selection_uses_stable_all_stable_claims() {
        let ledger = minimal_ledger();
        let selected = selected_claims(&ledger, None).unwrap();

        assert_eq!(
            selected
                .iter()
                .map(|claim| claim.id.as_str())
                .collect::<Vec<_>>(),
            vec!["scanner-safe-fixtures", "tls-contract-pack"]
        );
    }

    #[test]
    fn claim_selection_rejects_unknown_claim() {
        let ledger = minimal_ledger();
        let err = selected_claims(&ledger, Some("missing")).unwrap_err();

        assert!(
            err.to_string().contains("unknown claim `missing`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn readme_records_boundaries_and_commands() {
        let claims = vec![ClaimEntry {
            id: "scanner-safe-fixtures".to_string(),
            title: "Scanner-safe fixtures".to_string(),
            status: "stable".to_string(),
            boundary: "Not every export is safe to commit.".to_string(),
        }];

        let markdown = render_readme(Path::new("target/uselesskey-verification"), &claims);

        assert!(markdown.contains("cargo xtask claim-proof --claim scanner-safe-fixtures"));
        assert!(markdown.contains("Not every export is safe to commit."));
        assert!(markdown.contains("intentionally excludes generated fixture payloads"));
    }

    #[test]
    fn forbidden_payload_paths_are_rejected() {
        for path in [
            "certs/valid-leaf.pem",
            "payload.der",
            "private.key",
            "secret.yaml",
            "target/release-evidence/tls/bundle/manifest.json",
            "vault-kv.json",
        ] {
            assert!(forbidden_payload_path(path), "{path} should be forbidden");
        }

        for path in [
            "public-claims.json",
            "badges/scanner-safe.json",
            "claim-proof/tls-contract-pack/receipt.md",
        ] {
            assert!(!forbidden_payload_path(path), "{path} should be allowed");
        }
    }

    #[test]
    fn target_output_dir_can_be_recreated() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("target/uselesskey-verification");
        fs::create_dir_all(&out).unwrap();
        fs::write(out.join("old.txt"), "old").unwrap();

        let prepared =
            prepare_out_dir(dir.path(), Path::new("target/uselesskey-verification")).unwrap();

        assert_eq!(prepared, out);
        assert!(!prepared.join("old.txt").exists());
    }

    #[test]
    fn non_target_nonempty_output_dir_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("review-pack");
        fs::create_dir_all(&out).unwrap();
        fs::write(out.join("old.txt"), "old").unwrap();

        let err = prepare_out_dir(dir.path(), &out).unwrap_err();

        assert!(
            err.to_string()
                .contains("non-target output directory must be empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn target_root_output_dir_is_rejected() {
        let dir = tempfile::tempdir().unwrap();

        let err = prepare_out_dir(dir.path(), Path::new("target")).unwrap_err();

        assert!(
            err.to_string()
                .contains("refusing to use target root as output directory"),
            "unexpected error: {err}"
        );
    }

    fn minimal_ledger() -> ClaimLedger {
        ClaimLedger {
            claim: vec![
                ClaimEntry {
                    id: "scanner-safe-fixtures".to_string(),
                    title: "Scanner-safe fixtures".to_string(),
                    status: "stable".to_string(),
                    boundary: "Boundary.".to_string(),
                },
                ClaimEntry {
                    id: "tls-contract-pack".to_string(),
                    title: "TLS contract pack".to_string(),
                    status: "stable".to_string(),
                    boundary: "Boundary.".to_string(),
                },
                ClaimEntry {
                    id: "external-cratesio-install-smoke".to_string(),
                    title: "Crates.io smoke".to_string(),
                    status: "release-proof".to_string(),
                    boundary: "Boundary.".to_string(),
                },
            ],
            claim_proof: vec![
                ClaimProofPolicy {
                    claim: "scanner-safe-fixtures".to_string(),
                    include_in_all_stable: true,
                },
                ClaimProofPolicy {
                    claim: "tls-contract-pack".to_string(),
                    include_in_all_stable: true,
                },
                ClaimProofPolicy {
                    claim: "external-cratesio-install-smoke".to_string(),
                    include_in_all_stable: false,
                },
            ],
        }
    }
}
