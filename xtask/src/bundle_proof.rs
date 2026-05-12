use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::{
    ReleaseEvidenceCommandReceipt, git_head_sha, json_u64, read_json_file, run as run_command,
    write_json_pretty,
};

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct BundleProofManifest {
    pub(crate) profile: String,
    pub(crate) files: Vec<String>,
    pub(crate) artifacts: Vec<BundleProofArtifactRecord>,
    #[serde(default)]
    pub(crate) receipts: Vec<BundleProofReceiptRecord>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub(crate) struct BundleProofArtifactRecord {
    pub(crate) path: String,
    pub(crate) kind: String,
    pub(crate) format: String,
    #[serde(default)]
    pub(crate) lanes: Vec<String>,
    pub(crate) scanner_safe: bool,
    pub(crate) description: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct BundleProofReceiptRecord {
    pub(crate) path: String,
    pub(crate) kind: String,
    pub(crate) profile: String,
    pub(crate) description: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct BundleProofExportReceipt {
    pub(crate) target: String,
    pub(crate) path: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct BundleProofContractCheck {
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) description: String,
    pub(crate) present: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct BundleProofExpectedArtifact {
    pub(crate) name: &'static str,
    pub(crate) path: &'static str,
    pub(crate) description: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct BundleProofReceipt {
    pub(crate) schema_version: u32,
    pub(crate) lane: String,
    pub(crate) profile: String,
    pub(crate) generated_at: String,
    pub(crate) git_sha: Option<String>,
    pub(crate) bundle_dir: String,
    pub(crate) manifest_path: String,
    pub(crate) inspect_summary_path: String,
    pub(crate) artifact_count: usize,
    pub(crate) verified_file_count: usize,
    pub(crate) scanner_safe: bool,
    pub(crate) scanner_safe_artifact_count: usize,
    pub(crate) runtime_material_count: usize,
    pub(crate) private_key_material: bool,
    pub(crate) symmetric_secret_material: bool,
    pub(crate) receipts_present: Vec<String>,
    pub(crate) exports_generated: Vec<BundleProofExportReceipt>,
    pub(crate) contract_pack_checks: Vec<BundleProofContractCheck>,
    pub(crate) commands: Vec<ReleaseEvidenceCommandReceipt>,
    pub(crate) artifacts: Vec<BundleProofArtifactRecord>,
    pub(crate) claim_boundary: Vec<&'static str>,
}

pub(crate) struct BundleProofReceiptInput<'a> {
    pub(crate) profile: &'a str,
    pub(crate) bundle_dir: &'a Path,
    pub(crate) manifest_path: &'a Path,
    pub(crate) inspect_summary_path: &'a Path,
    pub(crate) manifest: &'a BundleProofManifest,
    pub(crate) audit_surface: &'a serde_json::Value,
    pub(crate) expected_artifacts: Vec<BundleProofExpectedArtifact>,
    pub(crate) commands: Vec<ReleaseEvidenceCommandReceipt>,
    pub(crate) exports_generated: Vec<BundleProofExportReceipt>,
}

pub(crate) fn run(profile: &str, out_dir: Option<&Path>) -> Result<()> {
    let profile = profile.trim();
    profile::ensure_supported(profile)?;
    let default_out_dir;
    let out_dir = match out_dir {
        Some(path) => path,
        None => {
            default_out_dir = profile::default_out_dir(profile)?;
            &default_out_dir
        }
    };
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;

    let layout = BundleProofLayout::new(out_dir);
    let mut commands = command::run_core_bundle_steps(profile, &layout)?;
    let mut exports_generated = Vec::new();

    if profile == "scanner-safe" {
        command::run_scanner_safe_exports(&layout, &mut commands, &mut exports_generated)?;
    }
    if profile == "oidc" {
        command::run_oidc_contract_checks(&mut commands)?;
    }
    command::run_no_blob_check(&mut commands)?;

    let manifest: BundleProofManifest = read_json_file(&layout.manifest_path)?;
    let audit_surface: serde_json::Value = read_json_file(&layout.audit_surface_path)?;
    let receipt = receipt::build(BundleProofReceiptInput {
        profile,
        bundle_dir: &layout.bundle_dir,
        manifest_path: &layout.manifest_path,
        inspect_summary_path: &layout.inspect_summary_path,
        manifest: &manifest,
        audit_surface: &audit_surface,
        expected_artifacts: profile::expected_artifacts(profile)?,
        commands,
        exports_generated,
    })?;

    write_artifacts(out_dir, &receipt)?;
    println!(
        "bundle-proof: wrote {} and {}",
        out_dir.join(profile::json_filename(profile)?).display(),
        out_dir.join(profile::markdown_filename(profile)?).display()
    );
    Ok(())
}

struct BundleProofLayout {
    bundle_dir: PathBuf,
    inspect_summary_path: PathBuf,
    k8s_path: PathBuf,
    vault_path: PathBuf,
    manifest_path: PathBuf,
    audit_surface_path: PathBuf,
}

impl BundleProofLayout {
    fn new(out_dir: &Path) -> Self {
        let bundle_dir = out_dir.join("bundle");
        Self {
            inspect_summary_path: out_dir.join("inspect-bundle.txt"),
            k8s_path: out_dir.join("secret.yaml"),
            vault_path: out_dir.join("kv-v2.json"),
            manifest_path: bundle_dir.join("manifest.json"),
            audit_surface_path: bundle_dir.join("receipts/audit-surface.json"),
            bundle_dir,
        }
    }
}

fn write_artifacts(out_dir: &Path, receipt: &BundleProofReceipt) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;
    let markdown_filename = profile::markdown_filename(&receipt.profile)?;
    write_json_pretty(
        &out_dir.join(profile::json_filename(&receipt.profile)?),
        receipt,
    )?;
    fs::write(out_dir.join(markdown_filename), markdown::render(receipt)?).with_context(|| {
        format!(
            "failed to write {}",
            out_dir.join(markdown_filename).display()
        )
    })?;
    Ok(())
}

mod profile {
    use super::*;

    const SCANNER_SAFE_BUNDLE_PROOF_CLAIM_BOUNDARY: &[&str] = &[
        "scanner-safe bundle proof covers the generated release-candidate bundle, not every possible future invocation",
        "scanner-safe means no usable private or symmetric fixture material is emitted by this profile",
        "bundle proof verifies deterministic regeneration, export shape generation, and no-blob scanning",
        "bundle proof is fixture-platform evidence, not production key management or scanner evasion",
    ];

    const OIDC_CONTRACT_PACK_PROOF_CLAIM_BOUNDARY: &[&str] = &[
        "OIDC contract-pack proof covers the generated release-candidate OIDC profile, not every downstream validator",
        "OIDC proof verifies pack shape and fixture presence, not downstream validator correctness",
        "OIDC profile artifacts remain scanner-safe and do not include usable private or symmetric fixture material",
        "bundle proof is fixture-platform evidence, not production key management or scanner evasion",
    ];

    pub(super) fn ensure_supported(profile: &str) -> Result<()> {
        if matches!(profile, "scanner-safe" | "oidc") {
            Ok(())
        } else {
            bail!("bundle-proof currently supports --profile scanner-safe and --profile oidc");
        }
    }

    pub(super) fn default_out_dir(profile: &str) -> Result<PathBuf> {
        Ok(PathBuf::from(match profile {
            "scanner-safe" => "target/release-evidence/scanner-safe",
            "oidc" => "target/release-evidence/oidc",
            _ => bail!("bundle-proof currently supports --profile scanner-safe and --profile oidc"),
        }))
    }

    pub(super) fn json_filename(profile: &str) -> Result<&'static str> {
        Ok(match profile {
            "scanner-safe" => "scanner-safe-bundle-proof.json",
            "oidc" => "oidc-contract-pack-proof.json",
            _ => bail!("bundle-proof currently supports --profile scanner-safe and --profile oidc"),
        })
    }

    pub(super) fn markdown_filename(profile: &str) -> Result<&'static str> {
        Ok(match profile {
            "scanner-safe" => "scanner-safe-bundle-proof.md",
            "oidc" => "oidc-contract-pack-proof.md",
            _ => bail!("bundle-proof currently supports --profile scanner-safe and --profile oidc"),
        })
    }

    pub(super) fn markdown_title(profile: &str) -> Result<&'static str> {
        Ok(match profile {
            "scanner-safe" => "Scanner-Safe Bundle Proof",
            "oidc" => "OIDC Contract-Pack Proof",
            _ => bail!("bundle-proof currently supports --profile scanner-safe and --profile oidc"),
        })
    }

    pub(super) fn claim_boundary(profile: &str) -> Result<Vec<&'static str>> {
        Ok(match profile {
            "scanner-safe" => SCANNER_SAFE_BUNDLE_PROOF_CLAIM_BOUNDARY.to_vec(),
            "oidc" => OIDC_CONTRACT_PACK_PROOF_CLAIM_BOUNDARY.to_vec(),
            _ => bail!("bundle-proof currently supports --profile scanner-safe and --profile oidc"),
        })
    }

    pub(crate) fn expected_artifacts(profile: &str) -> Result<Vec<BundleProofExpectedArtifact>> {
        Ok(match profile {
            "scanner-safe" => Vec::new(),
            "oidc" => vec![
                BundleProofExpectedArtifact {
                    name: "valid_jwks",
                    path: "jwks/valid.json",
                    description: "OIDC valid JWKS fixture",
                },
                BundleProofExpectedArtifact {
                    name: "negative_duplicate_kid",
                    path: "jwks/negative-duplicate-kid.json",
                    description: "OIDC negative JWKS with duplicate kid values",
                },
                BundleProofExpectedArtifact {
                    name: "negative_missing_kid",
                    path: "jwks/negative-missing-kid.json",
                    description: "OIDC negative JWKS with missing kid",
                },
                BundleProofExpectedArtifact {
                    name: "valid_rs256_token_shape",
                    path: "tokens/valid-rs256.json",
                    description: "OIDC valid RS256 JWT-shaped token fixture",
                },
                BundleProofExpectedArtifact {
                    name: "negative_alg_none",
                    path: "tokens/negative-alg-none.json",
                    description: "OIDC negative token with alg none",
                },
                BundleProofExpectedArtifact {
                    name: "negative_bad_audience",
                    path: "tokens/negative-bad-audience.json",
                    description: "OIDC negative token with bad audience",
                },
            ],
            _ => bail!("bundle-proof currently supports --profile scanner-safe and --profile oidc"),
        })
    }
}

mod command {
    use super::*;

    pub(super) fn run_core_bundle_steps(
        profile: &str,
        layout: &BundleProofLayout,
    ) -> Result<Vec<ReleaseEvidenceCommandReceipt>> {
        Ok(vec![
            run_step(
                "bundle",
                vec![
                    "cargo",
                    "run",
                    "-p",
                    "uselesskey-cli",
                    "--",
                    "bundle",
                    "--profile",
                    profile,
                    "--out",
                ],
                vec![layout.bundle_dir.display().to_string()],
                vec![
                    layout.manifest_path.display().to_string(),
                    layout
                        .bundle_dir
                        .join("receipts/materialization.json")
                        .display()
                        .to_string(),
                    layout.audit_surface_path.display().to_string(),
                ],
            )?,
            run_step(
                "verify-bundle",
                vec![
                    "cargo",
                    "run",
                    "-p",
                    "uselesskey-cli",
                    "--",
                    "verify-bundle",
                    "--path",
                ],
                vec![layout.bundle_dir.display().to_string()],
                Vec::new(),
            )?,
            run_step(
                "inspect-bundle",
                vec![
                    "cargo",
                    "run",
                    "-p",
                    "uselesskey-cli",
                    "--",
                    "inspect-bundle",
                    "--path",
                ],
                vec![
                    layout.bundle_dir.display().to_string(),
                    "--out".to_string(),
                    layout.inspect_summary_path.display().to_string(),
                ],
                vec![layout.inspect_summary_path.display().to_string()],
            )?,
        ])
    }

    pub(super) fn run_scanner_safe_exports(
        layout: &BundleProofLayout,
        commands: &mut Vec<ReleaseEvidenceCommandReceipt>,
        exports_generated: &mut Vec<BundleProofExportReceipt>,
    ) -> Result<()> {
        commands.push(run_step(
            "export-k8s",
            vec![
                "cargo",
                "run",
                "-p",
                "uselesskey-cli",
                "--",
                "export",
                "k8s",
                "--bundle-dir",
            ],
            vec![
                layout.bundle_dir.display().to_string(),
                "--name".to_string(),
                "uselesskey-fixtures".to_string(),
                "--namespace".to_string(),
                "tests".to_string(),
                "--out".to_string(),
                layout.k8s_path.display().to_string(),
            ],
            vec![layout.k8s_path.display().to_string()],
        )?);
        exports_generated.push(BundleProofExportReceipt {
            target: "k8s".to_string(),
            path: layout.k8s_path.display().to_string(),
        });

        commands.push(run_step(
            "export-vault-kv-json",
            vec![
                "cargo",
                "run",
                "-p",
                "uselesskey-cli",
                "--",
                "export",
                "vault-kv-json",
                "--bundle-dir",
            ],
            vec![
                layout.bundle_dir.display().to_string(),
                "--out".to_string(),
                layout.vault_path.display().to_string(),
            ],
            vec![layout.vault_path.display().to_string()],
        )?);
        exports_generated.push(BundleProofExportReceipt {
            target: "vault-kv-json".to_string(),
            path: layout.vault_path.display().to_string(),
        });
        Ok(())
    }

    pub(super) fn run_oidc_contract_checks(
        commands: &mut Vec<ReleaseEvidenceCommandReceipt>,
    ) -> Result<()> {
        commands.push(run_step(
            "cli-oidc-contract-pack-test",
            vec![
                "cargo",
                "test",
                "-p",
                "uselesskey-cli",
                "bundle_profile_oidc_writes_contract_pack",
                "--all-features",
            ],
            Vec::new(),
            Vec::new(),
        )?);
        commands.push(run_step(
            "jwk-owner-tests",
            vec!["cargo", "test", "-p", "uselesskey-jwk", "--all-features"],
            Vec::new(),
            Vec::new(),
        )?);
        commands.push(run_step(
            "token-owner-tests",
            vec!["cargo", "test", "-p", "uselesskey-token", "--all-features"],
            Vec::new(),
            Vec::new(),
        )?);
        Ok(())
    }

    pub(super) fn run_no_blob_check(
        commands: &mut Vec<ReleaseEvidenceCommandReceipt>,
    ) -> Result<()> {
        commands.push(run_step(
            "no-blob",
            vec!["cargo", "xtask", "no-blob"],
            Vec::new(),
            Vec::new(),
        )?);
        Ok(())
    }

    fn run_step(
        name: &str,
        fixed_parts: Vec<&str>,
        dynamic_parts: Vec<String>,
        artifacts: Vec<String>,
    ) -> Result<ReleaseEvidenceCommandReceipt> {
        let command = fixed_parts
            .into_iter()
            .map(str::to_string)
            .chain(dynamic_parts)
            .collect::<Vec<_>>();
        let Some((program, args)) = command.split_first() else {
            bail!("bundle proof command {name} has no program");
        };
        let mut cmd = Command::new(program);
        cmd.args(args);
        run_command(&mut cmd).with_context(|| format!("bundle proof step failed: {name}"))?;
        Ok(ReleaseEvidenceCommandReceipt {
            name: name.to_string(),
            command,
            status: "ok".to_string(),
            artifacts,
        })
    }
}

pub(crate) mod receipt {
    use super::*;

    pub(crate) fn build(input: BundleProofReceiptInput<'_>) -> Result<BundleProofReceipt> {
        let profile = input.profile;
        let manifest = input.manifest;
        let audit_surface = input.audit_surface;
        let posture = ScannerSafePosture::from_manifest(manifest);
        let receipts_present = manifest
            .receipts
            .iter()
            .map(|receipt| receipt.kind.clone())
            .collect::<Vec<_>>();
        let contract_pack_checks = contract_pack_checks(manifest, &input.expected_artifacts);

        validate_profile(profile, manifest)?;
        validate_scanner_safe_posture(&posture)?;
        validate_receipts(&receipts_present)?;
        validate_contract_pack(&contract_pack_checks)?;
        validate_audit_surface(audit_surface)?;

        Ok(BundleProofReceipt {
            schema_version: 1,
            lane: "bundle-proof".to_string(),
            profile: profile.to_string(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            git_sha: git_head_sha().ok(),
            bundle_dir: input.bundle_dir.display().to_string(),
            manifest_path: input.manifest_path.display().to_string(),
            inspect_summary_path: input.inspect_summary_path.display().to_string(),
            artifact_count: manifest.artifacts.len(),
            verified_file_count: manifest.files.len(),
            scanner_safe: posture.scanner_safe,
            scanner_safe_artifact_count: posture.scanner_safe_artifact_count,
            runtime_material_count: posture.runtime_material_count,
            private_key_material: posture.private_key_material,
            symmetric_secret_material: posture.symmetric_secret_material,
            receipts_present,
            exports_generated: input.exports_generated,
            contract_pack_checks,
            commands: input.commands,
            artifacts: manifest.artifacts.clone(),
            claim_boundary: profile::claim_boundary(profile)?,
        })
    }

    struct ScannerSafePosture {
        scanner_safe: bool,
        scanner_safe_artifact_count: usize,
        runtime_material_count: usize,
        private_key_material: bool,
        symmetric_secret_material: bool,
    }

    impl ScannerSafePosture {
        fn from_manifest(manifest: &BundleProofManifest) -> Self {
            let scanner_safe_artifact_count = manifest
                .artifacts
                .iter()
                .filter(|artifact| artifact.scanner_safe)
                .count();
            Self {
                scanner_safe: scanner_safe_artifact_count == manifest.artifacts.len(),
                scanner_safe_artifact_count,
                runtime_material_count: manifest.artifacts.len() - scanner_safe_artifact_count,
                private_key_material: manifest
                    .artifacts
                    .iter()
                    .any(artifact_contains_private_key_material),
                symmetric_secret_material: manifest
                    .artifacts
                    .iter()
                    .any(artifact_contains_symmetric_secret_material),
            }
        }
    }

    fn validate_profile(profile: &str, manifest: &BundleProofManifest) -> Result<()> {
        if manifest.profile != profile {
            bail!(
                "bundle proof expected profile `{profile}`, found `{}`",
                manifest.profile
            );
        }
        if manifest.artifacts.is_empty() {
            bail!("bundle proof expected artifact metadata");
        }
        Ok(())
    }

    fn validate_scanner_safe_posture(posture: &ScannerSafePosture) -> Result<()> {
        if !posture.scanner_safe {
            bail!("bundle proof expected all artifacts to be scanner-safe");
        }
        if posture.runtime_material_count != 0 {
            bail!("bundle proof expected zero runtime material artifacts");
        }
        if posture.private_key_material {
            bail!("bundle proof found private key material");
        }
        if posture.symmetric_secret_material {
            bail!("bundle proof found symmetric secret material");
        }
        Ok(())
    }

    fn validate_receipts(receipts_present: &[String]) -> Result<()> {
        for expected in ["materialization", "audit-surface"] {
            if !receipts_present.iter().any(|kind| kind == expected) {
                bail!("bundle proof missing `{expected}` receipt");
            }
        }
        Ok(())
    }

    fn validate_contract_pack(contract_pack_checks: &[BundleProofContractCheck]) -> Result<()> {
        if let Some(missing) = contract_pack_checks.iter().find(|check| !check.present) {
            bail!(
                "bundle proof missing expected artifact `{}` at `{}`",
                missing.name,
                missing.path
            );
        }
        Ok(())
    }

    fn validate_audit_surface(audit_surface: &serde_json::Value) -> Result<()> {
        if audit_surface
            .get("scanner_safe")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        {
            bail!("bundle proof expected audit-surface scanner_safe=true");
        }
        if json_u64(audit_surface, "runtime_material_count") != 0 {
            bail!("bundle proof expected audit-surface runtime_material_count=0");
        }
        Ok(())
    }

    fn contract_pack_checks(
        manifest: &BundleProofManifest,
        expected_artifacts: &[BundleProofExpectedArtifact],
    ) -> Vec<BundleProofContractCheck> {
        expected_artifacts
            .iter()
            .map(|expected| {
                let present = manifest.files.iter().any(|path| path == expected.path)
                    && manifest.artifacts.iter().any(|artifact| {
                        artifact.path == expected.path
                            && artifact.description == expected.description
                    });
                BundleProofContractCheck {
                    name: expected.name.to_string(),
                    path: expected.path.to_string(),
                    description: expected.description.to_string(),
                    present,
                }
            })
            .collect()
    }

    fn artifact_contains_private_key_material(artifact: &BundleProofArtifactRecord) -> bool {
        matches!(artifact.kind.as_str(), "rsa" | "ecdsa" | "ed25519")
            && matches!(artifact.format.as_str(), "pem" | "der")
            && !artifact.scanner_safe
    }

    fn artifact_contains_symmetric_secret_material(artifact: &BundleProofArtifactRecord) -> bool {
        artifact.kind == "hmac" && !artifact.scanner_safe
    }
}

pub(crate) mod markdown {
    use super::*;

    pub(crate) fn render(receipt: &BundleProofReceipt) -> Result<String> {
        let mut md = String::new();
        push_summary(&mut md, receipt)?;
        push_exports(&mut md, receipt);
        push_contract_pack_checks(&mut md, receipt);
        push_commands(&mut md, receipt);
        push_claim_boundary(&mut md, receipt);
        Ok(md)
    }

    fn push_summary(md: &mut String, receipt: &BundleProofReceipt) -> Result<()> {
        md.push_str(&format!(
            "# {}\n\n",
            profile::markdown_title(&receipt.profile)?
        ));
        md.push_str(&format!("- Lane: `{}`\n", receipt.lane));
        md.push_str(&format!("- Profile: `{}`\n", receipt.profile));
        md.push_str(&format!("- Bundle dir: `{}`\n", receipt.bundle_dir));
        md.push_str(&format!("- Manifest: `{}`\n", receipt.manifest_path));
        md.push_str(&format!(
            "- Inspect summary: `{}`\n",
            receipt.inspect_summary_path
        ));
        md.push_str(&format!("- Artifact count: `{}`\n", receipt.artifact_count));
        md.push_str(&format!(
            "- Verified files: `{}`\n",
            receipt.verified_file_count
        ));
        md.push_str(&format!("- Scanner-safe: `{}`\n", receipt.scanner_safe));
        md.push_str(&format!(
            "- Runtime material count: `{}`\n",
            receipt.runtime_material_count
        ));
        md.push_str(&format!(
            "- Private key material: `{}`\n",
            receipt.private_key_material
        ));
        md.push_str(&format!(
            "- Symmetric secret material: `{}`\n",
            receipt.symmetric_secret_material
        ));
        Ok(())
    }

    fn push_exports(md: &mut String, receipt: &BundleProofReceipt) {
        md.push_str("\n## Exports\n\n");
        md.push_str("| Target | Path |\n");
        md.push_str("| --- | --- |\n");
        if receipt.exports_generated.is_empty() {
            md.push_str("| - | - |\n");
        } else {
            for export in &receipt.exports_generated {
                md.push_str(&format!("| `{}` | `{}` |\n", export.target, export.path));
            }
        }
    }

    fn push_contract_pack_checks(md: &mut String, receipt: &BundleProofReceipt) {
        if receipt.contract_pack_checks.is_empty() {
            return;
        }
        md.push_str("\n## Contract Pack Checks\n\n");
        md.push_str("| Check | Path | Present |\n");
        md.push_str("| --- | --- | --- |\n");
        for check in &receipt.contract_pack_checks {
            md.push_str(&format!(
                "| `{}` | `{}` | `{}` |\n",
                check.name, check.path, check.present
            ));
        }
    }

    fn push_commands(md: &mut String, receipt: &BundleProofReceipt) {
        md.push_str("\n## Commands\n\n");
        md.push_str("| Step | Status | Command | Artifacts |\n");
        md.push_str("| --- | --- | --- | --- |\n");
        for command in &receipt.commands {
            let artifacts = if command.artifacts.is_empty() {
                "-".to_string()
            } else {
                command
                    .artifacts
                    .iter()
                    .map(|artifact| format!("`{artifact}`"))
                    .collect::<Vec<_>>()
                    .join("<br>")
            };
            md.push_str(&format!(
                "| `{}` | `{}` | `{}` | {} |\n",
                command.name,
                command.status,
                command.command.join(" "),
                artifacts
            ));
        }
    }

    fn push_claim_boundary(md: &mut String, receipt: &BundleProofReceipt) {
        md.push_str("\n## Claim Boundary\n\n");
        for claim in &receipt.claim_boundary {
            md.push_str(&format!("- {claim}\n"));
        }
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    pub(crate) use super::markdown::render as render_bundle_proof_markdown;
    pub(crate) use super::profile::expected_artifacts as bundle_proof_expected_artifacts;
    pub(crate) use super::receipt::build as bundle_proof_receipt;
    pub(crate) use super::{
        BundleProofArtifactRecord, BundleProofExportReceipt, BundleProofManifest,
        BundleProofReceiptInput, BundleProofReceiptRecord,
    };
}
