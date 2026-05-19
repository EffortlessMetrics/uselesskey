use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::git_head_sha;

const OUT_DIR: &str = "target/external-adoption-smoke";
const WORK_DIR: &str = "target/external-adoption-smoke/work";
const LOG_DIR: &str = "target/external-adoption-smoke/logs";
const REPORT_JSON: &str = "target/external-adoption-smoke/report.json";
const REPORT_MD: &str = "target/external-adoption-smoke/report.md";

const CLI_PROFILES: &[&str] = &["scanner-safe", "tls", "oidc", "webhook"];
const CI_RECIPE_PROFILES: &[&str] = &["webhook", "tls", "oidc"];
const EXTERNAL_EXAMPLES: &[ExternalExample] = &[
    ExternalExample {
        name: "rust-test-fixtures",
        source_dir: "examples/external/rust-test-fixtures",
    },
    ExternalExample {
        name: "webhook-verifier",
        source_dir: "examples/external/webhook-verifier",
    },
    ExternalExample {
        name: "oidc-jwks-validation",
        source_dir: "examples/external/oidc-jwks-validation",
    },
    ExternalExample {
        name: "tls-chain-validation",
        source_dir: "examples/external/tls-chain-validation",
    },
    ExternalExample {
        name: "downstream-ci-bundle-audit",
        source_dir: "examples/external/downstream-ci-bundle-audit",
    },
];
const BOUNDARIES: &[&str] = &[
    "external-adoption-smoke proves clean-project user paths, not release readiness",
    "published-version mode is audit/reference evidence, not a release trigger",
    "installed-style CLI smoke does not claim provider compatibility",
    "repo-local claim-proof and verification-pack remain separate proof surfaces",
    "generated fixture payloads and temp projects stay under target/external-adoption-smoke/",
];

#[derive(Clone, Copy, Debug)]
struct ExternalExample {
    name: &'static str,
    source_dir: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug)]
pub struct RunOptions {
    pub path: Option<PathBuf>,
    pub version: Option<String>,
    pub ci_recipes: bool,
    pub format: OutputFormat,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
enum SmokeMode {
    Path,
    Version,
}

#[derive(Debug)]
struct SmokeSource {
    mode: SmokeMode,
    label: String,
    facade_dep: FacadeDependency,
    cli_source: CliSource,
}

#[derive(Debug)]
enum FacadeDependency {
    Path(PathBuf),
    Version(String),
}

#[derive(Debug)]
enum CliSource {
    LocalPath(PathBuf),
    Version(String),
}

#[derive(Debug, serde::Serialize)]
struct ExternalAdoptionSmokeReceipt {
    schema_version: u32,
    status: String,
    generated_at: String,
    git_sha: Option<String>,
    mode: SmokeMode,
    source: String,
    work_root: String,
    ci_recipes: bool,
    projects: Vec<ExternalAdoptionProject>,
    steps: Vec<ExternalAdoptionStep>,
    artifacts: Vec<String>,
    boundaries: Vec<&'static str>,
}

#[derive(Debug, serde::Serialize)]
struct ExternalAdoptionProject {
    name: String,
    path: String,
    status: String,
    outputs: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
struct ExternalAdoptionStep {
    name: String,
    command: Vec<String>,
    cwd: String,
    status: String,
    duration_ms: u64,
    stdout: String,
    stderr: String,
    details: Option<String>,
    artifacts: Vec<String>,
}

pub fn run(root: &Path, options: RunOptions) -> Result<()> {
    let source = resolve_source(&options)?;
    let out_dir = root.join(OUT_DIR);
    reset_target_output(root, &out_dir)?;
    let work_dir = root.join(WORK_DIR);
    let log_dir = root.join(LOG_DIR);
    fs::create_dir_all(&work_dir)
        .with_context(|| format!("failed to create {}", work_dir.display()))?;
    fs::create_dir_all(&log_dir)
        .with_context(|| format!("failed to create {}", log_dir.display()))?;

    let mut receipt = ExternalAdoptionSmokeReceipt {
        schema_version: 1,
        status: "running".to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        git_sha: git_head_sha().ok(),
        mode: source.mode.clone(),
        source: source.label.clone(),
        work_root: relative_artifact(root, &work_dir),
        ci_recipes: options.ci_recipes,
        projects: Vec::new(),
        steps: Vec::new(),
        artifacts: vec![
            REPORT_JSON.to_string(),
            REPORT_MD.to_string(),
            WORK_DIR.to_string(),
            LOG_DIR.to_string(),
        ],
        boundaries: BOUNDARIES.to_vec(),
    };

    let result = run_matrix(
        root,
        &source,
        &work_dir,
        &log_dir,
        options.ci_recipes,
        &mut receipt,
    );
    receipt.status = if result.is_ok() { "pass" } else { "failed" }.to_string();
    write_receipts(&out_dir, &receipt)?;
    match options.format {
        OutputFormat::Human => print_human(&receipt),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&receipt)?),
    }

    result
}

fn run_matrix(
    root: &Path,
    source: &SmokeSource,
    work_dir: &Path,
    log_dir: &Path,
    ci_recipes: bool,
    receipt: &mut ExternalAdoptionSmokeReceipt,
) -> Result<()> {
    let cli_bin = prepare_cli(root, source, work_dir, log_dir, receipt)?;
    run_external_examples(root, source, work_dir, log_dir, receipt)?;
    run_cli_discovery(&cli_bin, work_dir, log_dir, receipt)?;
    for profile in CLI_PROFILES {
        run_cli_profile(&cli_bin, profile, work_dir, log_dir, receipt)?;
    }
    if ci_recipes {
        run_ci_recipes(&cli_bin, work_dir, log_dir, receipt)?;
    }
    Ok(())
}

fn prepare_cli(
    root: &Path,
    source: &SmokeSource,
    work_dir: &Path,
    log_dir: &Path,
    receipt: &mut ExternalAdoptionSmokeReceipt,
) -> Result<PathBuf> {
    match &source.cli_source {
        CliSource::LocalPath(cli_dir) => {
            let target_dir = work_dir.join("cargo-target/local-cli");
            fs::create_dir_all(&target_dir)
                .with_context(|| format!("failed to create {}", target_dir.display()))?;
            let mut cmd = Command::new("cargo");
            cmd.args(["build", "--quiet", "--bin", "uselesskey", "--manifest-path"])
                .arg(cli_dir.join("Cargo.toml"))
                .env("CARGO_TARGET_DIR", &target_dir);
            run_command_step(
                receipt,
                "build-local-cli",
                cmd,
                root,
                log_dir,
                &["target/external-adoption-smoke/work/cargo-target/local-cli/"],
            )?;
            let bin = target_dir.join("debug").join(cli_binary_name());
            if !bin.is_file() {
                bail!("expected local CLI binary at {}", bin.display());
            }
            Ok(bin)
        }
        CliSource::Version(version) => {
            let cli_root = work_dir.join("cli-root");
            let mut cmd = Command::new("cargo");
            cmd.args(["install", "uselesskey-cli", "--version", version, "--root"])
                .arg(&cli_root)
                .arg("--locked");
            run_command_step(
                receipt,
                "install-published-cli",
                cmd,
                root,
                log_dir,
                &["target/external-adoption-smoke/work/cli-root/"],
            )?;
            let bin = cli_root.join("bin").join(cli_binary_name());
            if !bin.is_file() {
                bail!("expected installed CLI binary at {}", bin.display());
            }
            Ok(bin)
        }
    }
}

fn run_external_examples(
    root: &Path,
    source: &SmokeSource,
    work_dir: &Path,
    log_dir: &Path,
    receipt: &mut ExternalAdoptionSmokeReceipt,
) -> Result<()> {
    for example in EXTERNAL_EXAMPLES {
        run_external_example(root, source, example, work_dir, log_dir, receipt)?;
    }
    Ok(())
}

fn run_external_example(
    root: &Path,
    source: &SmokeSource,
    example: &ExternalExample,
    work_dir: &Path,
    log_dir: &Path,
    receipt: &mut ExternalAdoptionSmokeReceipt,
) -> Result<()> {
    let source_dir = root.join(example.source_dir);
    let project_dir = work_dir.join(example.name);
    copy_example_project(&source_dir, &project_dir)
        .with_context(|| format!("failed to copy {}", source_dir.display()))?;
    patch_example_dependencies(&project_dir, source)
        .with_context(|| format!("failed to patch {}", project_dir.display()))?;

    let project_artifact = relative_artifact_from_path(&project_dir);
    let target_artifact = relative_artifact_from_path(&project_dir.join("target"));

    let mut cmd = Command::new("cargo");
    cmd.args(["test", "--quiet"])
        .current_dir(&project_dir)
        .env("CARGO_TARGET_DIR", project_dir.join("target"));
    run_command_step(
        receipt,
        &format!("external-example-{}", example.name),
        cmd,
        &project_dir,
        log_dir,
        &[project_artifact.as_str()],
    )?;
    record_project(receipt, example.name, &project_dir, &[target_artifact]);
    Ok(())
}

fn run_cli_discovery(
    cli_bin: &Path,
    work_dir: &Path,
    log_dir: &Path,
    receipt: &mut ExternalAdoptionSmokeReceipt,
) -> Result<()> {
    let project_dir = work_dir.join("cli-discovery");
    fs::create_dir_all(project_dir.join("target"))
        .with_context(|| format!("failed to create {}", project_dir.display()))?;

    let mut profiles = Command::new(cli_bin);
    profiles.arg("profiles").current_dir(&project_dir);
    run_command_step(
        receipt,
        "cli-profiles",
        profiles,
        &project_dir,
        log_dir,
        &[],
    )?;

    let mut explain = Command::new(cli_bin);
    explain
        .args(["profile", "webhook", "--explain"])
        .current_dir(&project_dir);
    run_command_step(
        receipt,
        "cli-profile-webhook-explain",
        explain,
        &project_dir,
        log_dir,
        &[],
    )?;

    Ok(())
}

fn run_cli_profile(
    cli_bin: &Path,
    profile: &str,
    work_dir: &Path,
    log_dir: &Path,
    receipt: &mut ExternalAdoptionSmokeReceipt,
) -> Result<()> {
    let project_name = format!("{profile}-cli");
    let project_dir = work_dir.join(&project_name);
    let target_dir = project_dir.join("target");
    let bundle_dir = target_dir.join(format!("uselesskey-{profile}"));
    let inspect_out = target_dir.join(format!("inspect-{profile}.txt"));
    let audit_dir = target_dir.join(format!("audit-{profile}"));
    fs::create_dir_all(&target_dir)
        .with_context(|| format!("failed to create {}", target_dir.display()))?;

    let bundle_artifact = relative_artifact_from_path(&bundle_dir);
    let inspect_artifact = relative_artifact_from_path(&inspect_out);
    let audit_artifact = relative_artifact_from_path(&audit_dir);

    let mut bundle = Command::new(cli_bin);
    bundle
        .args(["bundle", "--profile", profile, "--out"])
        .arg(&bundle_dir)
        .current_dir(&project_dir);
    run_command_step(
        receipt,
        &format!("cli-bundle-{profile}"),
        bundle,
        &project_dir,
        log_dir,
        &[bundle_artifact.as_str()],
    )?;

    let mut verify = Command::new(cli_bin);
    verify
        .args(["verify-bundle", "--path"])
        .arg(&bundle_dir)
        .current_dir(&project_dir);
    run_command_step(
        receipt,
        &format!("cli-verify-{profile}"),
        verify,
        &project_dir,
        log_dir,
        &[bundle_artifact.as_str()],
    )?;

    let mut audit = Command::new(cli_bin);
    audit
        .args(["audit-bundle", "--path"])
        .arg(&bundle_dir)
        .args(["--out"])
        .arg(&audit_dir)
        .current_dir(&project_dir);
    run_command_step(
        receipt,
        &format!("cli-audit-{profile}"),
        audit,
        &project_dir,
        log_dir,
        &[bundle_artifact.as_str(), audit_artifact.as_str()],
    )?;

    let mut inspect = Command::new(cli_bin);
    inspect
        .args(["inspect-bundle", "--path"])
        .arg(&bundle_dir)
        .args(["--out"])
        .arg(&inspect_out)
        .current_dir(&project_dir);
    run_command_step(
        receipt,
        &format!("cli-inspect-{profile}"),
        inspect,
        &project_dir,
        log_dir,
        &[bundle_artifact.as_str(), inspect_artifact.as_str()],
    )?;

    verify_bundle_shape(&bundle_dir, profile)?;
    record_project(
        receipt,
        &project_name,
        &project_dir,
        &[bundle_artifact, audit_artifact, inspect_artifact],
    );

    Ok(())
}

fn run_ci_recipes(
    cli_bin: &Path,
    work_dir: &Path,
    log_dir: &Path,
    receipt: &mut ExternalAdoptionSmokeReceipt,
) -> Result<()> {
    for profile in CI_RECIPE_PROFILES {
        run_ci_recipe_profile(cli_bin, profile, work_dir, log_dir, receipt)?;
    }
    Ok(())
}

fn run_ci_recipe_profile(
    cli_bin: &Path,
    profile: &str,
    work_dir: &Path,
    log_dir: &Path,
    receipt: &mut ExternalAdoptionSmokeReceipt,
) -> Result<()> {
    let project_name = format!("ci-recipe-{profile}");
    let project_dir = work_dir.join(&project_name);
    let target_dir = project_dir.join("target");
    let bundle_dir = target_dir.join(format!("uselesskey-{profile}"));
    let audit_dir = target_dir.join(format!("uselesskey-{profile}-audit"));
    fs::create_dir_all(&target_dir)
        .with_context(|| format!("failed to create {}", target_dir.display()))?;

    let bundle_artifact = relative_artifact_from_path(&bundle_dir);
    let audit_artifact = relative_artifact_from_path(&audit_dir);

    let mut bundle = Command::new(cli_bin);
    bundle
        .args(["bundle", "--profile", profile, "--out"])
        .arg(&bundle_dir)
        .current_dir(&project_dir);
    run_command_step(
        receipt,
        &format!("ci-recipe-bundle-{profile}"),
        bundle,
        &project_dir,
        log_dir,
        &[bundle_artifact.as_str()],
    )?;

    let mut verify = Command::new(cli_bin);
    verify
        .args(["verify-bundle", "--path"])
        .arg(&bundle_dir)
        .current_dir(&project_dir);
    run_command_step(
        receipt,
        &format!("ci-recipe-verify-{profile}"),
        verify,
        &project_dir,
        log_dir,
        &[bundle_artifact.as_str()],
    )?;

    let mut audit = Command::new(cli_bin);
    audit
        .args(["audit-bundle", "--path"])
        .arg(&bundle_dir)
        .args(["--out"])
        .arg(&audit_dir)
        .arg("--ci")
        .current_dir(&project_dir);
    run_command_step(
        receipt,
        &format!("ci-recipe-audit-{profile}"),
        audit,
        &project_dir,
        log_dir,
        &[bundle_artifact.as_str(), audit_artifact.as_str()],
    )?;

    verify_ci_audit_receipt(&audit_dir, profile)?;
    record_project(
        receipt,
        &project_name,
        &project_dir,
        &[bundle_artifact, audit_artifact],
    );
    Ok(())
}

fn verify_ci_audit_receipt(audit_dir: &Path, expected_profile: &str) -> Result<()> {
    let receipt_path = audit_dir.join("bundle-audit.json");
    let audit = read_json(&receipt_path)?;
    if audit["status"].as_str() != Some("pass") {
        bail!(
            "CI recipe audit status mismatch for {}: {:?}",
            audit_dir.display(),
            audit["status"]
        );
    }
    if audit["profile"].as_str() != Some(expected_profile) {
        bail!(
            "CI recipe audit profile mismatch for {}: expected {expected_profile}, got {:?}",
            audit_dir.display(),
            audit["profile"]
        );
    }
    Ok(())
}

fn copy_example_project(source_dir: &Path, project_dir: &Path) -> Result<()> {
    if project_dir.exists() {
        fs::remove_dir_all(project_dir)
            .with_context(|| format!("failed to remove {}", project_dir.display()))?;
    }
    copy_dir_recursive(source_dir, project_dir)
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)
        .with_context(|| format!("failed to create {}", destination.display()))?;
    for entry in
        fs::read_dir(source).with_context(|| format!("failed to read {}", source.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read entry in {}", source.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", entry.path().display()))?;
        let target = destination.join(entry.file_name());
        if file_type.is_dir() {
            if entry.file_name() == "target" {
                continue;
            }
            copy_dir_recursive(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), &target).with_context(|| {
                format!(
                    "failed to copy {} to {}",
                    entry.path().display(),
                    target.display()
                )
            })?;
        }
    }
    Ok(())
}

fn patch_example_dependencies(project_dir: &Path, source: &SmokeSource) -> Result<()> {
    let manifest_path = project_dir.join("Cargo.toml");
    let mut manifest = fs::read_to_string(&manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;

    match &source.facade_dep {
        FacadeDependency::Path(path) => {
            manifest = patch_dependency_path(&manifest, "uselesskey", path);
            let Some(crates_dir) = path.parent() else {
                bail!("failed to find crates dir from {}", path.display());
            };
            manifest = patch_dependency_path(
                &manifest,
                "uselesskey-rustls",
                &crates_dir.join("uselesskey-rustls"),
            );
        }
        FacadeDependency::Version(version) => {
            manifest = patch_dependency_version(&manifest, "uselesskey", version);
            manifest = patch_dependency_version(&manifest, "uselesskey-rustls", version);
        }
    }

    fs::write(&manifest_path, manifest)
        .with_context(|| format!("failed to write {}", manifest_path.display()))
}

fn patch_dependency_path(manifest: &str, crate_name: &str, path: &Path) -> String {
    replace_dependency_line(manifest, crate_name, |line| {
        let Some((_, rhs)) = line.split_once('=') else {
            return line.to_string();
        };
        let rhs = rhs.trim();
        if !(rhs.starts_with('{') && rhs.ends_with('}')) {
            return line.to_string();
        }

        let inner = rhs.trim_start_matches('{').trim_end_matches('}').trim();
        let path_part = format!("path = \"{}\"", toml_escape(&path.display().to_string()));
        let mut parts = vec![path_part];
        parts.extend(
            inner
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty() && !part.starts_with("version"))
                .map(ToString::to_string),
        );

        format!("{crate_name} = {{ {} }}", parts.join(", "))
    })
}

fn patch_dependency_version(manifest: &str, crate_name: &str, version: &str) -> String {
    replace_dependency_line(manifest, crate_name, |line| {
        let Some((_, rhs)) = line.split_once('=') else {
            return line.to_string();
        };
        let rhs = rhs.trim();
        if rhs.starts_with('"') {
            return format!("{crate_name} = \"{}\"", toml_escape(version));
        }
        if !(rhs.starts_with('{') && rhs.ends_with('}')) {
            return line.to_string();
        }

        let mut saw_version = false;
        let mut parts: Vec<String> = rhs
            .trim_start_matches('{')
            .trim_end_matches('}')
            .trim()
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(|part| {
                if part.starts_with("version") {
                    saw_version = true;
                    format!("version = \"{}\"", toml_escape(version))
                } else {
                    part.to_string()
                }
            })
            .collect();
        if !saw_version {
            parts.insert(0, format!("version = \"{}\"", toml_escape(version)));
        }

        format!("{crate_name} = {{ {} }}", parts.join(", "))
    })
}

fn replace_dependency_line(
    manifest: &str,
    crate_name: &str,
    replace: impl Fn(&str) -> String,
) -> String {
    let prefix = format!("{crate_name} =");
    let mut output = manifest
        .lines()
        .map(|line| {
            if line.trim_start().starts_with(&prefix) {
                replace(line)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    output.push('\n');
    output
}

fn verify_bundle_shape(bundle_dir: &Path, expected_profile: &str) -> Result<()> {
    let manifest_path = bundle_dir.join("manifest.json");
    let manifest: Value = read_json(&manifest_path)?;
    if manifest["profile"].as_str() != Some(expected_profile) {
        bail!(
            "bundle profile mismatch for {}: expected {expected_profile}, got {:?}",
            bundle_dir.display(),
            manifest["profile"]
        );
    }
    let artifacts = manifest["artifacts"]
        .as_array()
        .context("manifest artifacts is not an array")?;
    if artifacts.is_empty() {
        bail!("bundle {} has no artifacts", bundle_dir.display());
    }
    for required in [
        "receipts/materialization.json",
        "receipts/audit-surface.json",
        "receipts/bundle-verification.json",
        "receipts/scanner-safety.json",
        "receipts/negative-coverage.json",
    ] {
        if !bundle_dir.join(required).is_file() {
            bail!(
                "bundle {} is missing expected file {required}",
                bundle_dir.display()
            );
        }
    }
    Ok(())
}

fn resolve_source(options: &RunOptions) -> Result<SmokeSource> {
    match (&options.path, &options.version) {
        (Some(path), None) => {
            let source_root = resolve_existing_path(path)?;
            let facade_dir = if source_root.join("crates/uselesskey/Cargo.toml").exists() {
                source_root.join("crates/uselesskey")
            } else {
                source_root.clone()
            };
            let cli_dir = if source_root
                .join("crates/uselesskey-cli/Cargo.toml")
                .exists()
            {
                source_root.join("crates/uselesskey-cli")
            } else {
                source_root.clone()
            };
            if !facade_dir.join("Cargo.toml").is_file() {
                bail!(
                    "external-adoption-smoke --path could not find uselesskey facade Cargo.toml under {}",
                    source_root.display()
                );
            }
            if !cli_dir.join("Cargo.toml").is_file() {
                bail!(
                    "external-adoption-smoke --path could not find uselesskey-cli Cargo.toml under {}",
                    source_root.display()
                );
            }
            Ok(SmokeSource {
                mode: SmokeMode::Path,
                label: source_root.display().to_string(),
                facade_dep: FacadeDependency::Path(facade_dir),
                cli_source: CliSource::LocalPath(cli_dir),
            })
        }
        (None, Some(version)) if !version.trim().is_empty() => Ok(SmokeSource {
            mode: SmokeMode::Version,
            label: version.clone(),
            facade_dep: FacadeDependency::Version(version.clone()),
            cli_source: CliSource::Version(version.clone()),
        }),
        (None, Some(_)) => bail!("external-adoption-smoke --version must not be empty"),
        (None, None) => {
            bail!("external-adoption-smoke requires exactly one of --path or --version")
        }
        (Some(_), Some(_)) => {
            bail!("external-adoption-smoke: --path and --version are mutually exclusive")
        }
    }
}

fn resolve_existing_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to read current dir")?
            .join(path)
    };
    if !absolute.exists() {
        bail!("path does not exist: {}", absolute.display());
    }
    Ok(absolute)
}

fn run_command_step(
    receipt: &mut ExternalAdoptionSmokeReceipt,
    name: &str,
    mut cmd: Command,
    cwd: &Path,
    log_dir: &Path,
    artifacts: &[&str],
) -> Result<()> {
    eprintln!("==> {name}");
    cmd.stdin(Stdio::null());
    let command = command_to_vec(&cmd);
    let stdout_path = log_dir.join(format!("{name}.stdout.txt"));
    let stderr_path = log_dir.join(format!("{name}.stderr.txt"));
    let start = Instant::now();
    let output = cmd
        .output()
        .with_context(|| format!("failed to spawn {name}"))?;
    let duration_ms = start.elapsed().as_millis() as u64;
    fs::write(&stdout_path, &output.stdout)
        .with_context(|| format!("failed to write {}", stdout_path.display()))?;
    fs::write(&stderr_path, &output.stderr)
        .with_context(|| format!("failed to write {}", stderr_path.display()))?;

    let stdout = relative_artifact_from_path(&stdout_path);
    let stderr = relative_artifact_from_path(&stderr_path);
    if output.status.success() {
        eprintln!("==> {name} [ok]");
        receipt.steps.push(ExternalAdoptionStep {
            name: name.to_string(),
            command,
            cwd: cwd.display().to_string(),
            status: "ok".to_string(),
            duration_ms,
            stdout,
            stderr,
            details: None,
            artifacts: artifacts
                .iter()
                .map(|artifact| (*artifact).to_string())
                .collect(),
        });
        Ok(())
    } else {
        let details = format!("command failed with {}", output.status);
        eprintln!("==> {name} [FAILED]");
        eprintln!("    {details}");
        receipt.steps.push(ExternalAdoptionStep {
            name: name.to_string(),
            command,
            cwd: cwd.display().to_string(),
            status: "failed".to_string(),
            duration_ms,
            stdout,
            stderr,
            details: Some(details.clone()),
            artifacts: artifacts
                .iter()
                .map(|artifact| (*artifact).to_string())
                .collect(),
        });
        bail!("{name}: {details}")
    }
}

fn command_to_vec(cmd: &Command) -> Vec<String> {
    let mut command = Vec::new();
    command.push(cmd.get_program().to_string_lossy().into_owned());
    command.extend(cmd.get_args().map(|arg| arg.to_string_lossy().into_owned()));
    command
}

fn record_project(
    receipt: &mut ExternalAdoptionSmokeReceipt,
    name: &str,
    path: &Path,
    outputs: &[String],
) {
    receipt.projects.push(ExternalAdoptionProject {
        name: name.to_string(),
        path: relative_artifact_from_path(path),
        status: "ok".to_string(),
        outputs: outputs.to_vec(),
    });
}

fn reset_target_output(root: &Path, out_root: &Path) -> Result<()> {
    ensure_target_child(root, out_root)?;
    if out_root.exists() {
        fs::remove_dir_all(out_root)
            .with_context(|| format!("failed to remove {}", out_root.display()))?;
    }
    fs::create_dir_all(out_root).with_context(|| format!("failed to create {}", out_root.display()))
}

fn ensure_target_child(root: &Path, path: &Path) -> Result<()> {
    let absolute = absolute_path(root, path);
    let target_root = absolute_path(root, &root.join("target"));
    if !absolute.starts_with(&target_root) {
        bail!(
            "external-adoption-smoke refuses to write outside target/: {}",
            path.display()
        );
    }
    Ok(())
}

fn absolute_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn write_receipts(out_dir: &Path, receipt: &ExternalAdoptionSmokeReceipt) -> Result<()> {
    fs::write(
        out_dir.join("report.json"),
        serde_json::to_string_pretty(receipt).context("failed to serialize adoption smoke")?,
    )
    .with_context(|| format!("failed to write {}", out_dir.join("report.json").display()))?;
    fs::write(out_dir.join("report.md"), render_markdown(receipt))
        .with_context(|| format!("failed to write {}", out_dir.join("report.md").display()))
}

fn render_markdown(receipt: &ExternalAdoptionSmokeReceipt) -> String {
    let mut md = String::new();
    md.push_str("# External Adoption Smoke Receipt\n\n");
    md.push_str(&format!("Status: `{}`\n\n", receipt.status));
    md.push_str(&format!("Mode: `{:?}`\n\n", receipt.mode));
    md.push_str(&format!("Source: `{}`\n\n", receipt.source));
    if let Some(git_sha) = &receipt.git_sha {
        md.push_str(&format!("Git SHA: `{git_sha}`\n\n"));
    }

    md.push_str("## Projects\n\n");
    md.push_str("| Project | Status | Path | Outputs |\n");
    md.push_str("| --- | --- | --- | --- |\n");
    for project in &receipt.projects {
        md.push_str(&format!(
            "| {} | `{}` | `{}` | `{}` |\n",
            project.name,
            project.status,
            project.path,
            project.outputs.join("<br>")
        ));
    }

    md.push_str("\n## Steps\n\n");
    md.push_str("| Step | Status | Command | Logs | Details |\n");
    md.push_str("| --- | --- | --- | --- | --- |\n");
    for step in &receipt.steps {
        let details = step.details.as_deref().unwrap_or("");
        md.push_str(&format!(
            "| {} | `{}` | `{}` | `{}` / `{}` | {} |\n",
            step.name,
            step.status,
            step.command.join(" "),
            step.stdout,
            step.stderr,
            details
        ));
    }

    md.push_str("\n## Boundaries\n\n");
    for boundary in &receipt.boundaries {
        md.push_str(&format!("- {boundary}\n"));
    }

    md
}

fn print_human(receipt: &ExternalAdoptionSmokeReceipt) {
    println!(
        "external-adoption-smoke: {} (projects={}, steps={})",
        receipt.status,
        receipt.projects.len(),
        receipt.steps.len()
    );
    println!("external-adoption-smoke: wrote {REPORT_JSON} and {REPORT_MD}");
}

fn read_json(path: &Path) -> Result<Value> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

fn cli_binary_name() -> &'static str {
    if cfg!(windows) {
        "uselesskey.exe"
    } else {
        "uselesskey"
    }
}

fn relative_artifact(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn relative_artifact_from_path(path: &Path) -> String {
    if let Ok(cwd) = std::env::current_dir()
        && let Ok(stripped) = path.strip_prefix(&cwd)
    {
        return stripped.to_string_lossy().replace('\\', "/");
    }
    path.to_string_lossy().replace('\\', "/")
}

fn toml_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_adoption_profiles_are_bounded() {
        assert_eq!(CLI_PROFILES, ["scanner-safe", "tls", "oidc", "webhook"]);
    }

    #[test]
    fn external_adoption_ci_recipe_profiles_are_bounded() {
        assert_eq!(CI_RECIPE_PROFILES, ["webhook", "tls", "oidc"]);
    }

    #[test]
    fn external_adoption_examples_are_bounded() {
        let names: Vec<&str> = EXTERNAL_EXAMPLES
            .iter()
            .map(|example| example.name)
            .collect();
        assert_eq!(
            names,
            [
                "rust-test-fixtures",
                "webhook-verifier",
                "oidc-jwks-validation",
                "tls-chain-validation",
                "downstream-ci-bundle-audit",
            ]
        );
    }

    #[test]
    fn external_adoption_dependency_patch_switches_versions_to_paths() {
        let manifest = r#"[dependencies]
uselesskey = { version = "0.9.1", default-features = false, features = ["rsa"] }
uselesskey-rustls = { version = "0.9.1", features = ["tls-config", "rustls-ring"] }
"#;

        let patched = patch_dependency_path(
            manifest,
            "uselesskey",
            Path::new(r#"C:\Code\Rust\uselesskey\crates\uselesskey"#),
        );
        let patched = patch_dependency_path(
            &patched,
            "uselesskey-rustls",
            Path::new(r#"C:\Code\Rust\uselesskey\crates\uselesskey-rustls"#),
        );

        assert!(patched.contains(
            r#"uselesskey = { path = "C:\\Code\\Rust\\uselesskey\\crates\\uselesskey", default-features = false, features = ["rsa"] }"#
        ));
        assert!(patched.contains(
            r#"uselesskey-rustls = { path = "C:\\Code\\Rust\\uselesskey\\crates\\uselesskey-rustls", features = ["tls-config", "rustls-ring"] }"#
        ));
        assert!(!patched.contains("version = \"0.9.1\""));
    }

    #[test]
    fn external_adoption_rejects_non_target_output() -> Result<()> {
        let root = std::env::temp_dir().join("uselesskey-external-adoption-test");
        let outside = root
            .parent()
            .context("temp-dir test root has no parent")?
            .join("outside-external-adoption");
        let err = match ensure_target_child(&root, &outside) {
            Ok(()) => bail!("non-target output was accepted"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("outside target"));
        Ok(())
    }

    #[test]
    fn external_adoption_accepts_target_output() -> Result<()> {
        let root = std::env::temp_dir().join("uselesskey-external-adoption-test");

        ensure_target_child(&root, &root.join("target/external-adoption-smoke"))?;
        Ok(())
    }

    #[test]
    fn external_adoption_toml_escape_handles_windows_paths() {
        assert_eq!(
            toml_escape(r#"C:\Code\Rust\uselesskey\crates\uselesskey"#),
            r#"C:\\Code\\Rust\\uselesskey\\crates\\uselesskey"#
        );
    }

    #[test]
    fn external_adoption_markdown_lists_boundaries() {
        let receipt = ExternalAdoptionSmokeReceipt {
            schema_version: 1,
            status: "pass".to_string(),
            generated_at: "2026-05-17T00:00:00Z".to_string(),
            git_sha: Some("abc123".to_string()),
            mode: SmokeMode::Path,
            source: ".".to_string(),
            work_root: WORK_DIR.to_string(),
            ci_recipes: true,
            projects: vec![ExternalAdoptionProject {
                name: "webhook-cli".to_string(),
                path: "target/external-adoption-smoke/work/webhook-cli".to_string(),
                status: "ok".to_string(),
                outputs: vec![
                    "target/external-adoption-smoke/work/webhook-cli/target/uselesskey-webhook"
                        .to_string(),
                    "target/external-adoption-smoke/work/webhook-cli/target/audit-webhook"
                        .to_string(),
                ],
            }],
            steps: vec![
                ExternalAdoptionStep {
                    name: "cli-bundle-webhook".to_string(),
                    command: vec![
                        "uselesskey".to_string(),
                        "bundle".to_string(),
                        "--profile".to_string(),
                        "webhook".to_string(),
                    ],
                    cwd: ".".to_string(),
                    status: "ok".to_string(),
                    duration_ms: 1,
                    stdout: "target/external-adoption-smoke/logs/stdout.txt".to_string(),
                    stderr: "target/external-adoption-smoke/logs/stderr.txt".to_string(),
                    details: None,
                    artifacts: Vec::new(),
                },
                ExternalAdoptionStep {
                    name: "cli-audit-webhook".to_string(),
                    command: vec![
                        "uselesskey".to_string(),
                        "audit-bundle".to_string(),
                        "--path".to_string(),
                        "target/uselesskey-webhook".to_string(),
                    ],
                    cwd: ".".to_string(),
                    status: "ok".to_string(),
                    duration_ms: 1,
                    stdout: "target/external-adoption-smoke/logs/audit-stdout.txt".to_string(),
                    stderr: "target/external-adoption-smoke/logs/audit-stderr.txt".to_string(),
                    details: None,
                    artifacts: vec![
                        "target/external-adoption-smoke/work/webhook-cli/target/audit-webhook"
                            .to_string(),
                    ],
                },
            ],
            artifacts: vec![REPORT_JSON.to_string(), REPORT_MD.to_string()],
            boundaries: BOUNDARIES.to_vec(),
        };

        let markdown = render_markdown(&receipt);
        assert!(markdown.contains("External Adoption Smoke Receipt"));
        assert!(markdown.contains("installed-style CLI smoke does not claim provider"));
        assert!(markdown.contains("cli-bundle-webhook"));
        assert!(markdown.contains("target/audit-webhook"));
    }
}
