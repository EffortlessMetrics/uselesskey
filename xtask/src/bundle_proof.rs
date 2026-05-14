use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::{
    ReleaseEvidenceCommandReceipt, git_head_sha, json_u64, read_json_file, run as run_command,
    write_json_pretty,
};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub(crate) struct BundleProofManifest {
    pub(crate) profile: String,
    pub(crate) files: Vec<String>,
    #[serde(default)]
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

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
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

const TLS_CONTRACT_PACK_PROOF_CLAIM_BOUNDARY: &[&str] = &[
    "TLS contract-pack proof covers the generated release-candidate TLS profile, not every downstream TLS verifier",
    "TLS proof verifies pack shape and fixture presence (valid chain + four negative-class leaves), not downstream verifier correctness",
    "TLS proof does not cover revocation (CRL/OCSP), certificate transparency, mTLS client chains, browser trust stores, or production CA custody",
    "TLS profile artifacts remain scanner-safe and do not include usable private or symmetric fixture material",
    "bundle proof is fixture-platform evidence, not production key management or scanner evasion",
];

const WEBHOOK_CONTRACT_PACK_PROOF_CLAIM_BOUNDARY: &[&str] = &[
    "Webhook contract-pack proof covers deterministic HMAC verifier fixtures, not production webhook provider compatibility",
    "Webhook proof verifies pack shape and fixture presence (valid request + five negative classes), not downstream verifier correctness",
    "Webhook proof does not cover secret rotation, delivery retries, replay protection completeness, transport security, or production secret management",
    "Webhook request artifacts intentionally contain runtime signing material and belong under target/ or other generated-output paths, not committed fixture paths",
    "bundle proof is fixture-platform evidence, not production key management or scanner evasion",
];

pub(crate) fn run(profile: &str, out_dir: Option<&Path>) -> Result<()> {
    let profile = profile.trim();
    ensure_supported_bundle_proof_profile(profile)?;
    let paths = prepare_bundle_proof_paths(profile, out_dir)?;
    let execution = run_profile_commands(profile, &paths)?;
    let receipt = build_receipt(profile, &paths, execution)?;

    write_bundle_proof_artifacts(&paths.out_dir, &receipt)?;
    println!(
        "bundle-proof: wrote {} and {}",
        paths
            .out_dir
            .join(bundle_proof_json_filename(profile)?)
            .display(),
        paths
            .out_dir
            .join(bundle_proof_markdown_filename(profile)?)
            .display()
    );
    Ok(())
}

struct BundleProofPaths {
    out_dir: PathBuf,
    bundle_dir: PathBuf,
    inspect_summary_path: PathBuf,
    k8s_path: PathBuf,
    vault_path: PathBuf,
}

struct BundleProofExecution {
    commands: Vec<ReleaseEvidenceCommandReceipt>,
    exports_generated: Vec<BundleProofExportReceipt>,
}

fn prepare_bundle_proof_paths(profile: &str, out_dir: Option<&Path>) -> Result<BundleProofPaths> {
    let out_dir = out_dir
        .map(Path::to_path_buf)
        .map(Ok)
        .unwrap_or_else(|| default_bundle_proof_out_dir(profile))?;
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;

    Ok(BundleProofPaths {
        bundle_dir: out_dir.join("bundle"),
        inspect_summary_path: out_dir.join("inspect-bundle.txt"),
        k8s_path: out_dir.join("secret.yaml"),
        vault_path: out_dir.join("kv-v2.json"),
        out_dir,
    })
}

fn run_profile_commands(profile: &str, paths: &BundleProofPaths) -> Result<BundleProofExecution> {
    let mut execution = BundleProofExecution {
        commands: run_bundle_lifecycle_commands(profile, paths)?,
        exports_generated: Vec::new(),
    };

    match profile {
        "scanner-safe" => run_scanner_safe_exports(paths, &mut execution)?,
        "oidc" => run_oidc_contract_pack_checks(&mut execution)?,
        "tls" => run_tls_contract_pack_checks(&mut execution)?,
        "webhook" => run_webhook_contract_pack_checks(&mut execution)?,
        _ => ensure_supported_bundle_proof_profile(profile)?,
    }
    append_no_blob_check(&mut execution)?;
    Ok(execution)
}

fn run_bundle_lifecycle_commands(
    profile: &str,
    paths: &BundleProofPaths,
) -> Result<Vec<ReleaseEvidenceCommandReceipt>> {
    Ok(vec![
        run_bundle_proof_command(
            "bundle",
            cli_command([
                "bundle".to_string(),
                "--profile".to_string(),
                profile.to_string(),
                "--out".to_string(),
                paths.bundle_dir.display().to_string(),
            ]),
            vec![
                paths.bundle_dir.join("manifest.json").display().to_string(),
                paths
                    .bundle_dir
                    .join("receipts/materialization.json")
                    .display()
                    .to_string(),
                paths
                    .bundle_dir
                    .join("receipts/audit-surface.json")
                    .display()
                    .to_string(),
            ],
        )?,
        run_bundle_proof_command(
            "verify-bundle",
            cli_command([
                "verify-bundle".to_string(),
                "--path".to_string(),
                paths.bundle_dir.display().to_string(),
            ]),
            Vec::new(),
        )?,
        run_bundle_proof_command(
            "inspect-bundle",
            cli_command([
                "inspect-bundle".to_string(),
                "--path".to_string(),
                paths.bundle_dir.display().to_string(),
                "--out".to_string(),
                paths.inspect_summary_path.display().to_string(),
            ]),
            vec![paths.inspect_summary_path.display().to_string()],
        )?,
    ])
}

fn run_scanner_safe_exports(
    paths: &BundleProofPaths,
    execution: &mut BundleProofExecution,
) -> Result<()> {
    execution.commands.push(run_bundle_proof_command(
        "export-k8s",
        cli_command([
            "export".to_string(),
            "k8s".to_string(),
            "--bundle-dir".to_string(),
            paths.bundle_dir.display().to_string(),
            "--name".to_string(),
            "uselesskey-fixtures".to_string(),
            "--namespace".to_string(),
            "tests".to_string(),
            "--out".to_string(),
            paths.k8s_path.display().to_string(),
        ]),
        vec![paths.k8s_path.display().to_string()],
    )?);
    execution.exports_generated.push(BundleProofExportReceipt {
        target: "k8s".to_string(),
        path: paths.k8s_path.display().to_string(),
    });

    execution.commands.push(run_bundle_proof_command(
        "export-vault-kv-json",
        cli_command([
            "export".to_string(),
            "vault-kv-json".to_string(),
            "--bundle-dir".to_string(),
            paths.bundle_dir.display().to_string(),
            "--out".to_string(),
            paths.vault_path.display().to_string(),
        ]),
        vec![paths.vault_path.display().to_string()],
    )?);
    execution.exports_generated.push(BundleProofExportReceipt {
        target: "vault-kv-json".to_string(),
        path: paths.vault_path.display().to_string(),
    });
    Ok(())
}

fn run_oidc_contract_pack_checks(execution: &mut BundleProofExecution) -> Result<()> {
    execution.commands.push(run_bundle_proof_command(
        "cli-oidc-contract-pack-test",
        vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "uselesskey-cli".to_string(),
            "bundle_profile_oidc_writes_contract_pack".to_string(),
            "--all-features".to_string(),
        ],
        Vec::new(),
    )?);
    execution.commands.push(run_bundle_proof_command(
        "jwk-owner-tests",
        vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "uselesskey-jwk".to_string(),
            "--all-features".to_string(),
        ],
        Vec::new(),
    )?);
    execution.commands.push(run_bundle_proof_command(
        "token-owner-tests",
        vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "uselesskey-token".to_string(),
            "--all-features".to_string(),
        ],
        Vec::new(),
    )?);
    Ok(())
}

fn run_tls_contract_pack_checks(execution: &mut BundleProofExecution) -> Result<()> {
    execution.commands.push(run_bundle_proof_command(
        "cli-tls-contract-pack-test",
        vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "uselesskey-cli".to_string(),
            "tls".to_string(),
            "--all-features".to_string(),
        ],
        Vec::new(),
    )?);
    execution.commands.push(run_bundle_proof_command(
        "x509-owner-tests",
        vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "uselesskey-x509".to_string(),
            "--all-features".to_string(),
        ],
        Vec::new(),
    )?);
    Ok(())
}

fn run_webhook_contract_pack_checks(execution: &mut BundleProofExecution) -> Result<()> {
    execution.commands.push(run_bundle_proof_command(
        "cli-webhook-contract-pack-test",
        vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "uselesskey-cli".to_string(),
            "webhook".to_string(),
            "--all-features".to_string(),
        ],
        Vec::new(),
    )?);
    execution.commands.push(run_bundle_proof_command(
        "webhook-owner-tests",
        vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "uselesskey-webhook".to_string(),
            "--all-features".to_string(),
        ],
        Vec::new(),
    )?);
    Ok(())
}

fn append_no_blob_check(execution: &mut BundleProofExecution) -> Result<()> {
    execution.commands.push(run_bundle_proof_command(
        "no-blob",
        vec![
            "cargo".to_string(),
            "xtask".to_string(),
            "no-blob".to_string(),
        ],
        Vec::new(),
    )?);
    Ok(())
}

fn build_receipt(
    profile: &str,
    paths: &BundleProofPaths,
    execution: BundleProofExecution,
) -> Result<BundleProofReceipt> {
    let manifest_path = paths.bundle_dir.join("manifest.json");
    let manifest: BundleProofManifest = read_json_file(&manifest_path)?;
    let audit_surface_path = paths.bundle_dir.join("receipts/audit-surface.json");
    let audit_surface: serde_json::Value = read_json_file(&audit_surface_path)?;

    bundle_proof_receipt(BundleProofReceiptInput {
        profile,
        bundle_dir: &paths.bundle_dir,
        manifest_path: &manifest_path,
        inspect_summary_path: &paths.inspect_summary_path,
        manifest: &manifest,
        audit_surface: &audit_surface,
        expected_artifacts: bundle_proof_expected_artifacts(profile)?,
        commands: execution.commands,
        exports_generated: execution.exports_generated,
    })
}

fn cli_command(args: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut command = vec![
        "cargo".to_string(),
        "run".to_string(),
        "-p".to_string(),
        "uselesskey-cli".to_string(),
        "--".to_string(),
    ];
    command.extend(args);
    command
}

pub(crate) fn ensure_supported_bundle_proof_profile(profile: &str) -> Result<()> {
    if BUNDLE_PROOF_SUPPORTED_PROFILES.contains(&profile) {
        Ok(())
    } else {
        bail!("{}", unsupported_bundle_proof_profile_message());
    }
}

/// Profiles supported by `cargo xtask bundle-proof --profile <name>`.
///
/// Order matches the v0.7.0 -> v0.8.0 release lane introduction order:
/// scanner-safe (v0.7.0), oidc (v0.7.0), tls (v0.8.0 PR-C),
/// webhook (v0.9.0 lane).
pub(crate) const BUNDLE_PROOF_SUPPORTED_PROFILES: &[&str] =
    &["scanner-safe", "oidc", "tls", "webhook"];

fn unsupported_bundle_proof_profile_message() -> String {
    format!(
        "bundle-proof currently supports --profile {}",
        BUNDLE_PROOF_SUPPORTED_PROFILES.join(", "),
    )
}

pub(crate) fn default_bundle_proof_out_dir(profile: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(match profile {
        "scanner-safe" => "target/release-evidence/scanner-safe",
        "oidc" => "target/release-evidence/oidc",
        "tls" => "target/release-evidence/tls",
        "webhook" => "target/release-evidence/webhook",
        _ => bail!("{}", unsupported_bundle_proof_profile_message()),
    }))
}

pub(crate) fn bundle_proof_json_filename(profile: &str) -> Result<&'static str> {
    Ok(match profile {
        "scanner-safe" => "scanner-safe-bundle-proof.json",
        "oidc" => "oidc-contract-pack-proof.json",
        "tls" => "tls-contract-pack-proof.json",
        "webhook" => "webhook-contract-pack-proof.json",
        _ => bail!("{}", unsupported_bundle_proof_profile_message()),
    })
}

pub(crate) fn bundle_proof_markdown_filename(profile: &str) -> Result<&'static str> {
    Ok(match profile {
        "scanner-safe" => "scanner-safe-bundle-proof.md",
        "oidc" => "oidc-contract-pack-proof.md",
        "tls" => "tls-contract-pack-proof.md",
        "webhook" => "webhook-contract-pack-proof.md",
        _ => bail!("{}", unsupported_bundle_proof_profile_message()),
    })
}

pub(crate) fn bundle_proof_markdown_title(profile: &str) -> Result<&'static str> {
    Ok(match profile {
        "scanner-safe" => "Scanner-Safe Bundle Proof",
        "oidc" => "OIDC Contract-Pack Proof",
        "tls" => "TLS Contract-Pack Proof",
        "webhook" => "Webhook Contract-Pack Proof",
        _ => bail!("{}", unsupported_bundle_proof_profile_message()),
    })
}

fn bundle_proof_claim_boundary(profile: &str) -> Result<Vec<&'static str>> {
    Ok(match profile {
        "scanner-safe" => SCANNER_SAFE_BUNDLE_PROOF_CLAIM_BOUNDARY.to_vec(),
        "oidc" => OIDC_CONTRACT_PACK_PROOF_CLAIM_BOUNDARY.to_vec(),
        "tls" => TLS_CONTRACT_PACK_PROOF_CLAIM_BOUNDARY.to_vec(),
        "webhook" => WEBHOOK_CONTRACT_PACK_PROOF_CLAIM_BOUNDARY.to_vec(),
        _ => bail!("{}", unsupported_bundle_proof_profile_message()),
    })
}

pub(crate) fn bundle_proof_expected_artifacts(
    profile: &str,
) -> Result<Vec<BundleProofExpectedArtifact>> {
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
        "tls" => vec![
            BundleProofExpectedArtifact {
                name: "valid_leaf",
                path: "certs/valid-leaf.pem",
                description: "TLS valid leaf certificate (PEM)",
            },
            BundleProofExpectedArtifact {
                name: "valid_chain",
                path: "certs/valid-chain.pem",
                description: "TLS valid full chain: leaf + intermediate + root (PEM)",
            },
            BundleProofExpectedArtifact {
                name: "negative_expired_leaf",
                path: "certs/negative-expired-leaf.pem",
                description: "TLS negative chain with expired leaf (notAfter in past)",
            },
            BundleProofExpectedArtifact {
                name: "negative_not_yet_valid",
                path: "certs/negative-not-yet-valid.pem",
                description: "TLS negative chain with not-yet-valid leaf (notBefore in future)",
            },
            BundleProofExpectedArtifact {
                name: "negative_wrong_hostname",
                path: "certs/negative-wrong-hostname.pem",
                description: "TLS negative chain with leaf SAN/CN mismatch against expected hostname",
            },
            BundleProofExpectedArtifact {
                name: "negative_untrusted_root",
                path: "certs/negative-untrusted-root.pem",
                description: "TLS negative chain anchored to an untrusted root CA",
            },
            BundleProofExpectedArtifact {
                name: "tls_evidence_doc",
                path: "evidence/tls-profile.md",
                description: "TLS profile per-fixture rejection-expectation evidence",
            },
        ],
        "webhook" => vec![
            BundleProofExpectedArtifact {
                name: "valid_request",
                path: "requests/valid.json",
                description: "Webhook valid HMAC request",
            },
            BundleProofExpectedArtifact {
                name: "negative_tampered_body",
                path: "requests/negative-tampered-body.json",
                description: "Webhook negative request with modified body",
            },
            BundleProofExpectedArtifact {
                name: "negative_wrong_secret",
                path: "requests/negative-wrong-secret.json",
                description: "Webhook negative request signed with the wrong secret",
            },
            BundleProofExpectedArtifact {
                name: "negative_stale_timestamp",
                path: "requests/negative-stale-timestamp.json",
                description: "Webhook negative request outside timestamp tolerance",
            },
            BundleProofExpectedArtifact {
                name: "negative_missing_signature",
                path: "requests/negative-missing-signature.json",
                description: "Webhook negative request missing the signature header",
            },
            BundleProofExpectedArtifact {
                name: "negative_malformed_signature",
                path: "requests/negative-malformed-signature.json",
                description: "Webhook negative request with malformed signature",
            },
            BundleProofExpectedArtifact {
                name: "webhook_evidence_doc",
                path: "evidence/webhook-profile.md",
                description: "Webhook profile verifier expectation evidence",
            },
        ],
        _ => bail!("{}", unsupported_bundle_proof_profile_message()),
    })
}

fn run_bundle_proof_command(
    name: &str,
    command: Vec<String>,
    artifacts: Vec<String>,
) -> Result<ReleaseEvidenceCommandReceipt> {
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

pub(crate) fn bundle_proof_receipt(
    input: BundleProofReceiptInput<'_>,
) -> Result<BundleProofReceipt> {
    let profile = input.profile;
    let manifest = input.manifest;
    let audit_surface = input.audit_surface;
    let scanner_safe_artifact_count = manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.scanner_safe)
        .count();
    let runtime_material_count = manifest.artifacts.len() - scanner_safe_artifact_count;
    let private_key_material = manifest
        .artifacts
        .iter()
        .any(bundle_proof_artifact_contains_private_key_material);
    let symmetric_secret_material = manifest
        .artifacts
        .iter()
        .any(bundle_proof_artifact_contains_symmetric_secret_material);
    let receipts_present = manifest
        .receipts
        .iter()
        .map(|receipt| receipt.kind.clone())
        .collect::<Vec<_>>();
    let contract_pack_checks = input
        .expected_artifacts
        .iter()
        .map(|expected| {
            let present = manifest.files.iter().any(|path| path == expected.path)
                && manifest.artifacts.iter().any(|artifact| {
                    artifact.path == expected.path && artifact.description == expected.description
                });
            BundleProofContractCheck {
                name: expected.name.to_string(),
                path: expected.path.to_string(),
                description: expected.description.to_string(),
                present,
            }
        })
        .collect::<Vec<_>>();
    let scanner_safe = scanner_safe_artifact_count == manifest.artifacts.len();

    if manifest.profile != profile {
        bail!(
            "bundle proof expected profile `{profile}`, found `{}`",
            manifest.profile
        );
    }
    if manifest.artifacts.is_empty() {
        bail!("bundle proof expected artifact metadata");
    }
    if private_key_material {
        bail!("bundle proof found private key material");
    }
    for expected in ["materialization", "audit-surface"] {
        if !receipts_present.iter().any(|kind| kind == expected) {
            bail!("bundle proof missing `{expected}` receipt");
        }
    }
    if let Some(missing) = contract_pack_checks.iter().find(|check| !check.present) {
        bail!(
            "bundle proof missing expected artifact `{}` at `{}`",
            missing.name,
            missing.path
        );
    }

    match profile {
        "webhook" => enforce_webhook_proof_posture(
            scanner_safe,
            runtime_material_count,
            symmetric_secret_material,
            audit_surface,
        )?,
        _ => enforce_scanner_safe_proof_posture(
            scanner_safe,
            runtime_material_count,
            symmetric_secret_material,
            audit_surface,
        )?,
    }

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
        scanner_safe,
        scanner_safe_artifact_count,
        runtime_material_count,
        private_key_material,
        symmetric_secret_material,
        receipts_present,
        exports_generated: input.exports_generated,
        contract_pack_checks,
        commands: input.commands,
        artifacts: manifest.artifacts.clone(),
        claim_boundary: bundle_proof_claim_boundary(profile)?,
    })
}

fn enforce_scanner_safe_proof_posture(
    scanner_safe: bool,
    runtime_material_count: usize,
    symmetric_secret_material: bool,
    audit_surface: &serde_json::Value,
) -> Result<()> {
    if !scanner_safe {
        bail!("bundle proof expected all artifacts to be scanner-safe");
    }
    if runtime_material_count != 0 {
        bail!("bundle proof expected zero runtime material artifacts");
    }
    if symmetric_secret_material {
        bail!("bundle proof found symmetric secret material");
    }
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

fn enforce_webhook_proof_posture(
    scanner_safe: bool,
    runtime_material_count: usize,
    symmetric_secret_material: bool,
    audit_surface: &serde_json::Value,
) -> Result<()> {
    if scanner_safe {
        bail!("webhook bundle proof expected runtime webhook material");
    }
    if runtime_material_count != 6 {
        bail!("webhook bundle proof expected six runtime request artifacts");
    }
    if !symmetric_secret_material {
        bail!("webhook bundle proof expected symmetric signing material metadata");
    }
    if audit_surface
        .get("scanner_safe")
        .and_then(serde_json::Value::as_bool)
        != Some(false)
    {
        bail!("webhook bundle proof expected audit-surface scanner_safe=false");
    }
    if json_u64(audit_surface, "runtime_material_count") != 6 {
        bail!("webhook bundle proof expected audit-surface runtime_material_count=6");
    }
    Ok(())
}

fn bundle_proof_artifact_contains_private_key_material(
    artifact: &BundleProofArtifactRecord,
) -> bool {
    matches!(artifact.kind.as_str(), "rsa" | "ecdsa" | "ed25519")
        && matches!(artifact.format.as_str(), "pem" | "der")
        && !artifact.scanner_safe
}

fn bundle_proof_artifact_contains_symmetric_secret_material(
    artifact: &BundleProofArtifactRecord,
) -> bool {
    matches!(artifact.kind.as_str(), "hmac" | "webhook") && !artifact.scanner_safe
}

fn write_bundle_proof_artifacts(out_dir: &Path, receipt: &BundleProofReceipt) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;
    let markdown_filename = bundle_proof_markdown_filename(&receipt.profile)?;
    write_json_pretty(
        &out_dir.join(bundle_proof_json_filename(&receipt.profile)?),
        receipt,
    )?;
    fs::write(
        out_dir.join(markdown_filename),
        render_bundle_proof_markdown(receipt)?,
    )
    .with_context(|| {
        format!(
            "failed to write {}",
            out_dir.join(markdown_filename).display()
        )
    })?;
    Ok(())
}

pub(crate) fn render_bundle_proof_markdown(receipt: &BundleProofReceipt) -> Result<String> {
    let mut md = String::new();
    md.push_str(&format!(
        "# {}\n\n",
        bundle_proof_markdown_title(&receipt.profile)?
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
    if !receipt.contract_pack_checks.is_empty() {
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
    md.push_str("\n## Claim Boundary\n\n");
    for claim in &receipt.claim_boundary {
        md.push_str(&format!("- {claim}\n"));
    }
    Ok(md)
}
