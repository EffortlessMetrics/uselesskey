use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::{bundle_proof, external_adoption_smoke, git_head_sha, no_blob_gate, user_path_smoke};

const OUT_DIR: &str = "target/adoption-regression";
const BUNDLE_PROOF_DIR: &str = "target/adoption-regression/bundle-proof";
const RUNTIME_MATRIX_DIR: &str = "target/adoption-regression/runtime-matrix";

const BOUNDARIES: &[&str] = &[
    "adoption-regression checks copied user paths; it is not release evidence",
    "scanner-safe metadata is checked for fixture sensitivity, not scanner evasion",
    "contract-pack proofs do not prove downstream verifier correctness",
    "generated fixture payloads stay under target/",
    "clean-project external adoption smoke runs only when --external is passed",
];

#[derive(Clone, Copy, Debug)]
pub enum OutputFormat {
    Human,
    Json,
}

#[derive(Clone, Copy, Debug)]
pub struct RunOptions {
    pub format: OutputFormat,
    pub external: bool,
}

#[derive(Debug, serde::Serialize)]
struct AdoptionRegressionReceipt {
    schema_version: u32,
    status: String,
    generated_at: String,
    git_sha: Option<String>,
    steps: Vec<AdoptionRegressionStep>,
    artifacts: Vec<String>,
    boundaries: Vec<&'static str>,
}

#[derive(Debug, serde::Serialize)]
struct AdoptionRegressionStep {
    name: String,
    command: Vec<String>,
    status: String,
    duration_ms: u64,
    details: Option<String>,
    artifacts: Vec<String>,
}

pub fn run(root: &Path, options: RunOptions) -> Result<()> {
    let out_dir = root.join(OUT_DIR);
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;

    let mut receipt = AdoptionRegressionReceipt {
        schema_version: 1,
        status: "running".to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        git_sha: git_head_sha().ok(),
        steps: Vec::new(),
        artifacts: receipt_artifacts(options.external),
        boundaries: BOUNDARIES.to_vec(),
    };

    let result = run_steps(
        root,
        &mut receipt,
        matches!(options.format, OutputFormat::Json),
        options.external,
    );
    if result.is_ok() {
        receipt.status = "pass".to_string();
    } else {
        receipt.status = "failed".to_string();
    }

    write_receipts(&out_dir, &receipt)?;
    match options.format {
        OutputFormat::Human => print_human(&receipt),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&receipt)?),
    }

    result
}

fn run_steps(
    root: &Path,
    receipt: &mut AdoptionRegressionReceipt,
    quiet_stdout: bool,
    include_external: bool,
) -> Result<()> {
    run_step(
        receipt,
        "user-path-smoke",
        &["cargo", "xtask", "user-path-smoke"],
        &[
            "target/user-path-smoke/",
            "target/release-evidence/webhook/",
            "target/claim-report/",
            "target/contract-packs/",
            "target/claim-proof/webhook-contract-pack/",
        ],
        || user_path_smoke_step(root, quiet_stdout),
    )?;
    run_step(
        receipt,
        "runtime-scanner-safe-matrix",
        &["internal", "runtime-scanner-safe-matrix"],
        &["target/adoption-regression/runtime-matrix/"],
        || runtime_scanner_safe_matrix(root, quiet_stdout),
    )?;
    run_step(
        receipt,
        "webhook-profile-tests",
        &[
            "cargo",
            "test",
            "-p",
            "uselesskey-webhook",
            "--all-features",
        ],
        &[],
        || {
            let mut cmd = Command::new("cargo");
            cmd.args(["test", "-p", "uselesskey-webhook", "--all-features"])
                .current_dir(root)
                .stdin(Stdio::null());
            run_command(&mut cmd, quiet_stdout)
        },
    )?;
    run_step(
        receipt,
        "tls-bundle-proof",
        &[
            "cargo",
            "xtask",
            "bundle-proof",
            "--profile",
            "tls",
            "--out",
            "target/adoption-regression/bundle-proof/tls",
        ],
        &["target/adoption-regression/bundle-proof/tls/"],
        || bundle_proof_step(root, "tls", quiet_stdout),
    )?;
    run_step(
        receipt,
        "oidc-bundle-proof",
        &[
            "cargo",
            "xtask",
            "bundle-proof",
            "--profile",
            "oidc",
            "--out",
            "target/adoption-regression/bundle-proof/oidc",
        ],
        &["target/adoption-regression/bundle-proof/oidc/"],
        || bundle_proof_step(root, "oidc", quiet_stdout),
    )?;
    run_step(
        receipt,
        "no-blob",
        &["cargo", "xtask", "no-blob"],
        &[],
        || no_blob_step(root, quiet_stdout),
    )?;
    if include_external {
        run_step(
            receipt,
            "external-adoption-smoke",
            &["cargo", "xtask", "external-adoption-smoke", "--path", "."],
            &["target/external-adoption-smoke/"],
            || external_adoption_smoke_step(root, quiet_stdout),
        )?;
    }

    Ok(())
}

fn receipt_artifacts(include_external: bool) -> Vec<String> {
    let mut artifacts = vec![
        "target/adoption-regression/adoption-regression.json".to_string(),
        "target/adoption-regression/adoption-regression.md".to_string(),
        "target/user-path-smoke/".to_string(),
        "target/adoption-regression/runtime-matrix/".to_string(),
        "target/adoption-regression/bundle-proof/".to_string(),
    ];
    if include_external {
        artifacts.push("target/external-adoption-smoke/".to_string());
        artifacts.push("target/external-adoption-smoke/report.json".to_string());
        artifacts.push("target/external-adoption-smoke/report.md".to_string());
    }
    artifacts
}

fn user_path_smoke_step(root: &Path, quiet_stdout: bool) -> Result<()> {
    if quiet_stdout {
        let mut cmd = Command::new("cargo");
        cmd.args(["xtask", "user-path-smoke"])
            .current_dir(root)
            .stdin(Stdio::null());
        run_command(&mut cmd, true)
    } else {
        user_path_smoke::run(root)
    }
}

fn bundle_proof_step(root: &Path, profile: &str, quiet_stdout: bool) -> Result<()> {
    let out = root.join(BUNDLE_PROOF_DIR).join(profile);
    if quiet_stdout {
        let mut cmd = Command::new("cargo");
        cmd.args(["xtask", "bundle-proof", "--profile", profile, "--out"])
            .arg(&out)
            .current_dir(root)
            .stdin(Stdio::null());
        run_command(&mut cmd, true)
    } else {
        bundle_proof::run(profile, Some(&out))
    }
}

fn no_blob_step(root: &Path, quiet_stdout: bool) -> Result<()> {
    if quiet_stdout {
        let mut cmd = Command::new("cargo");
        cmd.args(["xtask", "no-blob"])
            .current_dir(root)
            .stdin(Stdio::null());
        run_command(&mut cmd, true)
    } else {
        no_blob_gate()
    }
}

fn external_adoption_smoke_step(root: &Path, quiet_stdout: bool) -> Result<()> {
    if quiet_stdout {
        let mut cmd = Command::new("cargo");
        cmd.args([
            "xtask",
            "external-adoption-smoke",
            "--path",
            ".",
            "--format",
            "json",
        ])
        .current_dir(root)
        .stdin(Stdio::null());
        run_command(&mut cmd, true)
    } else {
        external_adoption_smoke::run(
            root,
            external_adoption_smoke::RunOptions {
                path: Some(root.to_path_buf()),
                version: None,
                ci_recipes: false,
                format: external_adoption_smoke::OutputFormat::Human,
            },
        )
    }
}

fn runtime_scanner_safe_matrix(root: &Path, quiet_stdout: bool) -> Result<()> {
    let out_root = root.join(RUNTIME_MATRIX_DIR);
    if out_root.exists() {
        fs::remove_dir_all(&out_root)
            .with_context(|| format!("failed to remove {}", out_root.display()))?;
    }
    fs::create_dir_all(&out_root)
        .with_context(|| format!("failed to create {}", out_root.display()))?;

    for format in ["jwk", "jwks"] {
        let bundle_dir = out_root.join(format);
        let mut cmd = Command::new("cargo");
        cmd.args([
            "run",
            "--quiet",
            "-p",
            "uselesskey-cli",
            "--",
            "bundle",
            "--profile",
            "runtime",
            "--format",
            format,
            "--seed",
            "adoption-regression-seed",
            "--label",
            "issuer",
            "--out",
        ])
        .arg(&bundle_dir)
        .current_dir(root)
        .stdin(Stdio::null());
        run_command(&mut cmd, quiet_stdout)
            .with_context(|| format!("runtime scanner-safe {format} bundle failed"))?;
        verify_runtime_manifest(&bundle_dir, format)?;
    }

    Ok(())
}

fn verify_runtime_manifest(bundle_dir: &Path, expected_format: &str) -> Result<()> {
    let manifest: Value = read_json(&bundle_dir.join("manifest.json"))?;
    let artifacts = manifest["artifacts"]
        .as_array()
        .context("manifest artifacts is not an array")?;

    for kind in ["rsa", "ecdsa", "ed25519"] {
        let artifact = find_artifact(artifacts, kind, expected_format)?;
        if artifact["scanner_safe"] != true {
            bail!("{kind} {expected_format} artifact is not scanner-safe");
        }
    }

    for kind in ["hmac", "token"] {
        let artifact = artifacts
            .iter()
            .find(|artifact| artifact["kind"].as_str() == Some(kind))
            .with_context(|| format!("missing {kind} artifact"))?;
        if artifact["scanner_safe"] != false {
            bail!("{kind} runtime artifact should remain secret-bearing");
        }
    }

    let audit: Value = read_json(&bundle_dir.join("receipts/audit-surface.json"))?;
    if audit["runtime_material_count"] != 2 {
        bail!("runtime_material_count drifted for {expected_format}");
    }

    Ok(())
}

fn find_artifact<'a>(artifacts: &'a [Value], kind: &str, format: &str) -> Result<&'a Value> {
    artifacts
        .iter()
        .find(|artifact| {
            artifact["kind"].as_str() == Some(kind) && artifact["format"].as_str() == Some(format)
        })
        .with_context(|| format!("missing {kind} {format} artifact"))
}

fn read_json(path: &Path) -> Result<Value> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

fn run_step<F>(
    receipt: &mut AdoptionRegressionReceipt,
    name: &str,
    command: &[&str],
    artifacts: &[&str],
    f: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    eprintln!("==> {name}");
    let start = Instant::now();
    match f() {
        Ok(()) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            eprintln!("==> {name} [ok]");
            receipt.steps.push(AdoptionRegressionStep {
                name: name.to_string(),
                command: command_to_strings(command),
                status: "ok".to_string(),
                duration_ms,
                details: None,
                artifacts: artifacts_to_strings(artifacts),
            });
            Ok(())
        }
        Err(err) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            let details = err.to_string();
            eprintln!("==> {name} [FAILED]");
            eprintln!("    {details}");
            receipt.steps.push(AdoptionRegressionStep {
                name: name.to_string(),
                command: command_to_strings(command),
                status: "failed".to_string(),
                duration_ms,
                details: Some(details),
                artifacts: artifacts_to_strings(artifacts),
            });
            Err(err)
        }
    }
}

fn run_command(cmd: &mut Command, quiet_stdout: bool) -> Result<()> {
    if quiet_stdout {
        cmd.stdout(Stdio::null());
    }
    let status = cmd.status().context("failed to spawn command")?;
    if !status.success() {
        bail!("command failed with {status}");
    }
    Ok(())
}

fn write_receipts(out_dir: &Path, receipt: &AdoptionRegressionReceipt) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;
    fs::write(
        out_dir.join("adoption-regression.json"),
        serde_json::to_string_pretty(receipt).context("failed to serialize adoption receipt")?,
    )
    .with_context(|| {
        format!(
            "failed to write {}",
            out_dir.join("adoption-regression.json").display()
        )
    })?;
    fs::write(
        out_dir.join("adoption-regression.md"),
        render_markdown(receipt),
    )
    .with_context(|| {
        format!(
            "failed to write {}",
            out_dir.join("adoption-regression.md").display()
        )
    })
}

fn render_markdown(receipt: &AdoptionRegressionReceipt) -> String {
    let mut md = String::new();
    md.push_str("# Adoption Regression Receipt\n\n");
    md.push_str(&format!("Status: `{}`\n\n", receipt.status));
    if let Some(git_sha) = &receipt.git_sha {
        md.push_str(&format!("Git SHA: `{git_sha}`\n\n"));
    }

    md.push_str("## Steps\n\n");
    md.push_str("| Step | Status | Command | Details |\n");
    md.push_str("| --- | --- | --- | --- |\n");
    for step in &receipt.steps {
        let command = step.command.join(" ");
        let details = step.details.as_deref().unwrap_or("");
        md.push_str(&format!(
            "| {} | `{}` | `{}` | {} |\n",
            step.name, step.status, command, details
        ));
    }

    md.push_str("\n## Boundaries\n\n");
    for boundary in &receipt.boundaries {
        md.push_str(&format!("- {boundary}\n"));
    }

    md
}

fn print_human(receipt: &AdoptionRegressionReceipt) {
    println!(
        "adoption-regression: {} (steps={})",
        receipt.status,
        receipt.steps.len()
    );
    println!(
        "adoption-regression: wrote target/adoption-regression/adoption-regression.json and target/adoption-regression/adoption-regression.md"
    );
}

fn command_to_strings(command: &[&str]) -> Vec<String> {
    command.iter().map(|part| (*part).to_string()).collect()
}

fn artifacts_to_strings(artifacts: &[&str]) -> Vec<String> {
    artifacts.iter().map(|path| (*path).to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adoption_regression_receipt_markdown_lists_boundaries() {
        let receipt = AdoptionRegressionReceipt {
            schema_version: 1,
            status: "pass".to_string(),
            generated_at: "2026-05-16T00:00:00Z".to_string(),
            git_sha: Some("abc123".to_string()),
            steps: vec![AdoptionRegressionStep {
                name: "no-blob".to_string(),
                command: vec![
                    "cargo".to_string(),
                    "xtask".to_string(),
                    "no-blob".to_string(),
                ],
                status: "ok".to_string(),
                duration_ms: 1,
                details: None,
                artifacts: Vec::new(),
            }],
            artifacts: Vec::new(),
            boundaries: BOUNDARIES.to_vec(),
        };

        let markdown = render_markdown(&receipt);
        assert!(markdown.contains("adoption-regression checks copied user paths"));
        assert!(markdown.contains("| no-blob | `ok` | `cargo xtask no-blob` |  |"));
    }

    #[test]
    fn adoption_regression_artifact_paths_are_target_scoped() {
        for path in receipt_artifacts(true).into_iter().chain([
            OUT_DIR.to_string(),
            BUNDLE_PROOF_DIR.to_string(),
            RUNTIME_MATRIX_DIR.to_string(),
        ]) {
            assert!(path.starts_with("target/"));
        }
    }

    #[test]
    fn adoption_regression_default_artifacts_stay_bounded() {
        let artifacts = receipt_artifacts(false);

        assert!(artifacts.contains(&"target/user-path-smoke/".to_string()));
        assert!(
            !artifacts
                .iter()
                .any(|artifact| artifact.starts_with("target/external-adoption-smoke"))
        );
    }

    #[test]
    fn adoption_regression_external_artifacts_include_smoke_receipts() {
        let artifacts = receipt_artifacts(true);

        assert!(artifacts.contains(&"target/external-adoption-smoke/".to_string()));
        assert!(artifacts.contains(&"target/external-adoption-smoke/report.json".to_string()));
        assert!(artifacts.contains(&"target/external-adoption-smoke/report.md".to_string()));
    }

    #[test]
    fn adoption_regression_external_step_is_explicit() -> Result<()> {
        let mut receipt = AdoptionRegressionReceipt {
            schema_version: 1,
            status: "pass".to_string(),
            generated_at: "2026-05-16T00:00:00Z".to_string(),
            git_sha: Some("abc123".to_string()),
            steps: Vec::new(),
            artifacts: vec!["target/external-adoption-smoke/".to_string()],
            boundaries: BOUNDARIES.to_vec(),
        };

        run_step(
            &mut receipt,
            "external-adoption-smoke",
            &["cargo", "xtask", "external-adoption-smoke", "--path", "."],
            &["target/external-adoption-smoke/"],
            || Ok(()),
        )?;

        let Some(step) = receipt
            .steps
            .iter()
            .find(|step| step.name == "external-adoption-smoke")
        else {
            bail!("external step present");
        };
        assert_eq!(step.status, "ok");
        assert_eq!(
            step.command,
            ["cargo", "xtask", "external-adoption-smoke", "--path", "."]
        );
        assert_eq!(step.artifacts, ["target/external-adoption-smoke/"]);
        Ok(())
    }
}
