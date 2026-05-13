use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::git_head_sha;

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
    #[serde(default)]
    artifacts: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ClaimProofPolicy {
    claim: String,
    #[serde(default)]
    include_in_all_stable: bool,
    #[serde(default)]
    requires_explicit_version: bool,
    #[serde(default)]
    handlers: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ClaimProofReceipt {
    schema_version: u32,
    claim: String,
    title: String,
    claim_status: String,
    status: String,
    generated_at: String,
    git_sha: Option<String>,
    boundary: String,
    handlers: Vec<HandlerReceipt>,
    artifacts: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HandlerReceipt {
    handler: String,
    command: Vec<String>,
    status: String,
    artifacts: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HandlerSpec {
    id: &'static str,
    argv: Vec<&'static str>,
    artifacts: Vec<&'static str>,
}

pub(crate) fn run(root: &Path, claim: Option<&str>, all_stable: bool) -> Result<()> {
    if claim.is_some() == all_stable {
        bail!("claim-proof: pass exactly one of --claim <id> or --all-stable");
    }

    let ledger = read_ledger(root)?;
    let selected = if all_stable {
        stable_claims_with_policy(&ledger)?
    } else {
        vec![claim.expect("checked above").to_string()]
    };

    let mut failures = Vec::new();
    for claim_id in selected {
        match run_claim(root, &ledger, &claim_id) {
            Ok(receipt) => {
                println!("claim-proof: {} {}", receipt.claim, receipt.status);
            }
            Err(err) => {
                failures.push(format!("{claim_id}: {err:#}"));
            }
        }
    }

    if !failures.is_empty() {
        for failure in &failures {
            eprintln!("claim-proof: {failure}");
        }
        bail!("claim-proof: {} claim(s) failed", failures.len());
    }

    Ok(())
}

fn run_claim(root: &Path, ledger: &ClaimLedger, claim_id: &str) -> Result<ClaimProofReceipt> {
    validate_claim_id(claim_id)?;
    let claim = ledger
        .claim
        .iter()
        .find(|claim| claim.id == claim_id)
        .with_context(|| format!("unknown claim `{claim_id}`"))?;
    let policy = policy_for_claim(ledger, claim_id)?;
    if policy.requires_explicit_version {
        bail!("claim `{claim_id}` requires an explicit version and is not supported yet");
    }
    if policy.handlers.is_empty() {
        bail!("claim `{claim_id}` has no claim-proof handlers");
    }

    let mut receipt = ClaimProofReceipt {
        schema_version: 1,
        claim: claim.id.clone(),
        title: claim.title.clone(),
        claim_status: claim.status.clone(),
        status: "running".to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        git_sha: git_head_sha().ok(),
        boundary: claim.boundary.clone(),
        handlers: Vec::new(),
        artifacts: claim.artifacts.clone(),
    };

    for handler in &policy.handlers {
        match run_handler(root, handler) {
            Ok(handler_receipt) => receipt.handlers.push(handler_receipt),
            Err(err) => {
                receipt.handlers.push(HandlerReceipt {
                    handler: handler.clone(),
                    command: handler_spec(handler).map(command_strings).unwrap_or_default(),
                    status: "failed".to_string(),
                    artifacts: handler_spec(handler)
                        .map(|spec| {
                            spec.artifacts
                                .into_iter()
                                .map(str::to_string)
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default(),
                });
                receipt.status = "failed".to_string();
                write_receipt(root, &receipt)?;
                return Err(err).with_context(|| format!("handler `{handler}` failed"));
            }
        }
    }

    receipt.status = "pass".to_string();
    write_receipt(root, &receipt)?;
    Ok(receipt)
}

fn run_handler(root: &Path, handler: &str) -> Result<HandlerReceipt> {
    let spec = handler_spec(handler)?;
    let Some((program, args)) = spec.argv.split_first() else {
        bail!("handler `{handler}` has no command");
    };

    let mut command = Command::new(program);
    command.args(args).current_dir(root);
    let status = command
        .status()
        .with_context(|| format!("run handler `{handler}`"))?;
    if !status.success() {
        bail!("handler `{handler}` exited with {status}");
    }

    Ok(HandlerReceipt {
        handler: spec.id.to_string(),
        command: command_strings(spec.clone()),
        status: "ok".to_string(),
        artifacts: spec
            .artifacts
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>(),
    })
}

fn read_ledger(root: &Path) -> Result<ClaimLedger> {
    let path = root.join("policy/claim-ledger.toml");
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    toml::from_str(&text).context("parse policy/claim-ledger.toml")
}

fn stable_claims_with_policy(ledger: &ClaimLedger) -> Result<Vec<String>> {
    let policies = ledger
        .claim_proof
        .iter()
        .map(|policy| (policy.claim.as_str(), policy))
        .collect::<BTreeMap<_, _>>();
    let mut selected = Vec::new();

    for claim in ledger.claim.iter().filter(|claim| claim.status == "stable") {
        let Some(policy) = policies.get(claim.id.as_str()) else {
            bail!("stable claim `{}` has no claim-proof policy", claim.id);
        };
        if policy.include_in_all_stable {
            selected.push(claim.id.clone());
        }
    }

    if selected.is_empty() {
        bail!("claim-proof: no stable claims selected");
    }

    Ok(selected)
}

fn policy_for_claim<'a>(ledger: &'a ClaimLedger, claim_id: &str) -> Result<&'a ClaimProofPolicy> {
    ledger
        .claim_proof
        .iter()
        .find(|policy| policy.claim == claim_id)
        .with_context(|| format!("claim `{claim_id}` has no claim-proof policy"))
}

fn handler_spec(handler: &str) -> Result<HandlerSpec> {
    let spec = match handler {
        "scanner_safe_reference_check" => HandlerSpec {
            id: "scanner_safe_reference_check",
            argv: vec!["cargo", "xtask", "scanner-safe-reference", "--check"],
            artifacts: vec![],
        },
        "no_blob" => HandlerSpec {
            id: "no_blob",
            argv: vec!["cargo", "xtask", "no-blob"],
            artifacts: vec![],
        },
        "badges_check" => HandlerSpec {
            id: "badges_check",
            argv: vec!["cargo", "xtask", "badges", "--check"],
            artifacts: vec!["badges/ripr-plus.json", "badges/scanner-safe.json"],
        },
        "test_efficiency_report" => HandlerSpec {
            id: "test_efficiency_report",
            argv: vec!["cargo", "xtask", "test-efficiency-report"],
            artifacts: vec![
                "target/ripr/reports/test-efficiency.json",
                "target/ripr/reports/test-efficiency.md",
            ],
        },
        "bundle_proof_tls" => HandlerSpec {
            id: "bundle_proof_tls",
            argv: vec![
                "cargo",
                "xtask",
                "bundle-proof",
                "--profile",
                "tls",
                "--out",
                "target/release-evidence/tls",
            ],
            artifacts: vec![
                "target/release-evidence/tls/tls-contract-pack-proof.json",
                "target/release-evidence/tls/tls-contract-pack-proof.md",
            ],
        },
        "bundle_proof_oidc" => HandlerSpec {
            id: "bundle_proof_oidc",
            argv: vec![
                "cargo",
                "xtask",
                "bundle-proof",
                "--profile",
                "oidc",
                "--out",
                "target/release-evidence/oidc",
            ],
            artifacts: vec![
                "target/release-evidence/oidc/oidc-contract-pack-proof.json",
                "target/release-evidence/oidc/oidc-contract-pack-proof.md",
            ],
        },
        "public_surface" => HandlerSpec {
            id: "public_surface",
            argv: vec!["cargo", "xtask", "public-surface"],
            artifacts: vec![],
        },
        "publish_check" => HandlerSpec {
            id: "publish_check",
            argv: vec!["cargo", "xtask", "publish-check"],
            artifacts: vec![],
        },
        "publish_preflight" => HandlerSpec {
            id: "publish_preflight",
            argv: vec!["cargo", "xtask", "publish-preflight"],
            artifacts: vec!["target/xtask/receipt.json"],
        },
        "cratesio_smoke_version" => {
            bail!("handler `cratesio_smoke_version` requires an explicit version")
        }
        other => bail!("unknown claim-proof handler `{other}`"),
    };

    Ok(spec)
}

fn command_strings(spec: HandlerSpec) -> Vec<String> {
    spec.argv.into_iter().map(str::to_string).collect()
}

fn write_receipt(root: &Path, receipt: &ClaimProofReceipt) -> Result<()> {
    let out_dir = claim_out_dir(root, &receipt.claim);
    fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    write_json_pretty(&out_dir.join("receipt.json"), receipt)?;
    fs::write(out_dir.join("receipt.md"), render_receipt_markdown(receipt))
        .with_context(|| format!("write {}", out_dir.join("receipt.md").display()))?;
    Ok(())
}

fn claim_out_dir(root: &Path, claim: &str) -> PathBuf {
    root.join("target/claim-proof").join(claim)
}

fn render_receipt_markdown(receipt: &ClaimProofReceipt) -> String {
    let mut md = String::new();
    md.push_str("# Claim Proof Receipt\n\n");
    md.push_str(&format!("- Claim: `{}`\n", receipt.claim));
    md.push_str(&format!("- Title: {}\n", receipt.title));
    md.push_str(&format!("- Claim status: `{}`\n", receipt.claim_status));
    md.push_str(&format!("- Status: `{}`\n", receipt.status));
    md.push_str(&format!("- Generated at: `{}`\n", receipt.generated_at));
    if let Some(git_sha) = &receipt.git_sha {
        md.push_str(&format!("- Git SHA: `{git_sha}`\n"));
    }

    md.push_str("\n## Handlers\n\n");
    md.push_str("| Handler | Status | Command |\n");
    md.push_str("| --- | --- | --- |\n");
    for handler in &receipt.handlers {
        md.push_str(&format!(
            "| `{}` | `{}` | `{}` |\n",
            handler.handler,
            handler.status,
            handler.command.join(" ")
        ));
    }

    md.push_str("\n## Boundary\n\n");
    md.push_str(&receipt.boundary);
    md.push('\n');

    md
}

fn write_json_pretty(path: &Path, value: &impl Serialize) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, json + "\n").with_context(|| format!("write {}", path.display()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_claim_selection_uses_include_in_all_stable() {
        let ledger = minimal_ledger();
        let selected = stable_claims_with_policy(&ledger).unwrap();

        assert_eq!(
            selected,
            vec![
                "scanner-safe-fixtures".to_string(),
                "tls-contract-pack".to_string()
            ]
        );
    }

    #[test]
    fn stable_claim_selection_rejects_missing_policy() {
        let mut ledger = minimal_ledger();
        ledger.claim.push(ClaimEntry {
            id: "generated-badge-endpoints".to_string(),
            title: "Generated badges".to_string(),
            status: "stable".to_string(),
            boundary: "Boundary.".to_string(),
            artifacts: Vec::new(),
        });

        let err = stable_claims_with_policy(&ledger).unwrap_err();

        assert!(
            err.to_string()
                .contains("stable claim `generated-badge-endpoints` has no claim-proof policy"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn handler_specs_construct_argv_without_shell() {
        let spec = handler_spec("scanner_safe_reference_check").unwrap();

        assert_eq!(
            spec.argv,
            vec!["cargo", "xtask", "scanner-safe-reference", "--check"]
        );
        assert!(!spec.argv.iter().any(|part| part.contains("&&")));
    }

    #[test]
    fn unknown_handler_is_rejected() {
        let err = handler_spec("cargo xtask no-blob").unwrap_err();

        assert!(
            err.to_string()
                .contains("unknown claim-proof handler `cargo xtask no-blob`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn explicit_version_handler_is_not_implicit() {
        let err = handler_spec("cratesio_smoke_version").unwrap_err();

        assert!(
            err.to_string().contains("requires an explicit version"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn receipt_markdown_includes_boundary() {
        let receipt = ClaimProofReceipt {
            schema_version: 1,
            claim: "scanner-safe-fixtures".to_string(),
            title: "Scanner-safe fixtures".to_string(),
            claim_status: "stable".to_string(),
            status: "pass".to_string(),
            generated_at: "2026-05-13T00:00:00Z".to_string(),
            git_sha: Some("abc123".to_string()),
            boundary: "Not production key management.".to_string(),
            handlers: vec![HandlerReceipt {
                handler: "no_blob".to_string(),
                command: vec!["cargo".to_string(), "xtask".to_string(), "no-blob".to_string()],
                status: "ok".to_string(),
                artifacts: Vec::new(),
            }],
            artifacts: Vec::new(),
        };

        let markdown = render_receipt_markdown(&receipt);

        assert!(markdown.contains("scanner-safe-fixtures"));
        assert!(markdown.contains("Not production key management."));
    }

    #[test]
    fn invalid_claim_ids_are_rejected() {
        for claim_id in ["", "../bad", "BadClaim", "bad_claim"] {
            assert!(
                validate_claim_id(claim_id).is_err(),
                "{claim_id} should be invalid"
            );
        }
    }

    fn minimal_ledger() -> ClaimLedger {
        ClaimLedger {
            claim: vec![
                ClaimEntry {
                    id: "scanner-safe-fixtures".to_string(),
                    title: "Scanner-safe fixtures".to_string(),
                    status: "stable".to_string(),
                    boundary: "Boundary.".to_string(),
                    artifacts: Vec::new(),
                },
                ClaimEntry {
                    id: "tls-contract-pack".to_string(),
                    title: "TLS contract pack".to_string(),
                    status: "stable".to_string(),
                    boundary: "Boundary.".to_string(),
                    artifacts: Vec::new(),
                },
                ClaimEntry {
                    id: "external-cratesio-install-smoke".to_string(),
                    title: "Crates.io smoke".to_string(),
                    status: "release-proof".to_string(),
                    boundary: "Boundary.".to_string(),
                    artifacts: Vec::new(),
                },
            ],
            claim_proof: vec![
                ClaimProofPolicy {
                    claim: "scanner-safe-fixtures".to_string(),
                    include_in_all_stable: true,
                    requires_explicit_version: false,
                    handlers: vec!["no_blob".to_string()],
                },
                ClaimProofPolicy {
                    claim: "tls-contract-pack".to_string(),
                    include_in_all_stable: true,
                    requires_explicit_version: false,
                    handlers: vec!["bundle_proof_tls".to_string()],
                },
                ClaimProofPolicy {
                    claim: "external-cratesio-install-smoke".to_string(),
                    include_in_all_stable: false,
                    requires_explicit_version: true,
                    handlers: vec!["cratesio_smoke_version".to_string()],
                },
            ],
        }
    }
}
