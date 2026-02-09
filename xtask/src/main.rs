use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

mod plan;
mod receipt;

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Repo automation (fmt, clippy, tests, fuzz, mutants, bdd).",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run formatter checks.
    Fmt {
        /// Apply formatting changes instead of checking.
        #[arg(long)]
        fix: bool,
    },
    /// Run clippy (denies warnings).
    Clippy,
    /// Run tests.
    Test,
    /// Run tests via cargo-nextest (requires `cargo-nextest` installed).
    Nextest,
    /// Run cargo-deny checks (requires `cargo-deny` installed).
    Deny,
    /// Run the common CI pipeline: fmt + clippy + tests.
    Ci,
    /// Run the feature matrix checks.
    FeatureMatrix,
    /// Enforce no secret-shaped blobs in test/fixture paths.
    NoBlob,
    /// Run publish dry-runs for crates in dependency order.
    PublishCheck,
    /// Run PR-scoped tests based on git diff.
    Pr,
    /// Guard against multiple semver-major versions of pinned deps (e.g. rand_core).
    DepGuard,
    /// Run cucumber BDD features.
    Bdd,
    /// Run mutation testing (requires `cargo-mutants` installed).
    Mutants,
    /// Run code coverage via cargo-llvm-cov (requires `cargo-llvm-cov` installed).
    Coverage,
    /// Validate publish metadata and run `cargo package --no-verify` for all crates.
    PublishPreflight,
    /// Run fuzz targets (requires `cargo-fuzz` installed).
    Fuzz {
        /// Name of the fuzz target (e.g. `rsa_pkcs8_pem_parse`).
        #[arg(long)]
        target: Option<String>,
        /// Extra args passed to `cargo fuzz run`.
        #[arg(last = true)]
        args: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Fmt { fix } => fmt(fix),
        Cmd::Clippy => clippy(),
        Cmd::Test => test(),
        Cmd::Nextest => nextest(),
        Cmd::Deny => deny(),
        Cmd::Ci => ci(),
        Cmd::FeatureMatrix => feature_matrix_cmd(),
        Cmd::NoBlob => no_blob_gate(),
        Cmd::PublishCheck => publish_check(),
        Cmd::Pr => pr(),
        Cmd::DepGuard => dep_guard(),
        Cmd::Bdd => bdd(),
        Cmd::Coverage => coverage(),
        Cmd::PublishPreflight => publish_preflight(),
        Cmd::Mutants => mutants(),
        Cmd::Fuzz { target, args } => fuzz(target.as_deref(), &args),
    }
}

fn run(cmd: &mut Command) -> Result<()> {
    eprintln!("+ {:?}", cmd);
    let status = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("failed to spawn command")?;

    if !status.success() {
        bail!("command failed with status: {status}");
    }
    Ok(())
}

const FEATURE_MATRIX: &[(&str, &[&str])] = &[
    ("default", &[]),
    ("no-default", &["--no-default-features"]),
    ("rsa", &["--no-default-features", "--features", "rsa"]),
    ("ecdsa", &["--no-default-features", "--features", "ecdsa"]),
    (
        "ed25519",
        &["--no-default-features", "--features", "ed25519"],
    ),
    ("hmac", &["--no-default-features", "--features", "hmac"]),
    ("x509", &["--no-default-features", "--features", "x509"]),
    ("jwk", &["--no-default-features", "--features", "jwk"]),
    ("all-features", &["--all-features"]),
];

fn fmt(fix: bool) -> Result<()> {
    if fix {
        run(Command::new("cargo").args(["fmt", "--all"]))
    } else {
        run(Command::new("cargo").args(["fmt", "--all", "--", "--check"]))
    }
}

fn clippy() -> Result<()> {
    run(Command::new("cargo").args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--",
        "-D",
        "warnings",
    ]))
}

fn test() -> Result<()> {
    run(Command::new("cargo").args(["test", "--workspace", "--all-features"]))
}

fn bdd() -> Result<()> {
    run(Command::new("cargo").args(["test", "-p", "uselesskey-bdd", "--test", "bdd"]))
}

fn ci() -> Result<()> {
    let mut runner = receipt::Runner::new("target/xtask/receipt.json");
    let result = run_ci_plan(&mut runner);
    runner.summary();
    if let Err(err) = runner.write() {
        eprintln!("failed to write receipt: {err}");
        if result.is_ok() {
            return Err(err);
        }
    }
    result
}

fn run_ci_plan(runner: &mut receipt::Runner) -> Result<()> {
    runner.step("fmt", None, || fmt(false))?;
    runner.step("clippy", None, clippy)?;
    runner.step("tests", None, test)?;

    run_feature_matrix(runner)?;

    runner.step("dep-guard", None, dep_guard)?;
    runner.step("bdd", None, bdd)?;
    let counts = count_bdd_scenarios().unwrap_or_default();
    runner.set_bdd_counts(counts);

    runner.step("no-blob", None, no_blob_gate)?;
    runner.step("mutants", None, mutants)?;
    runner.step("fuzz", None, fuzz_pr)?;

    if is_llvm_cov_installed() {
        run_coverage(runner)?;
    } else {
        runner.skip("coverage", Some("cargo-llvm-cov not installed".into()));
        runner.skip(
            "coverage:report",
            Some("cargo-llvm-cov not installed".into()),
        );
    }

    run_publish_preflight(runner)?;

    Ok(())
}

fn feature_matrix_cmd() -> Result<()> {
    let mut runner = receipt::Runner::new("target/xtask/receipt.json");
    let result = run_feature_matrix(&mut runner);
    runner.summary();
    if let Err(err) = runner.write() {
        eprintln!("failed to write receipt: {err}");
        if result.is_ok() {
            return Err(err);
        }
    }
    result
}

const PUBLISH_CRATES: &[&str] = &[
    "uselesskey-core",
    "uselesskey-jwk",
    "uselesskey-rsa",
    "uselesskey-ecdsa",
    "uselesskey-ed25519",
    "uselesskey-hmac",
    "uselesskey-x509",
    "uselesskey",
    "uselesskey-jsonwebtoken",
    "uselesskey-rustls",
    "uselesskey-ring",
    "uselesskey-rustcrypto",
    "uselesskey-aws-lc-rs",
];

fn publish_check() -> Result<()> {
    for name in PUBLISH_CRATES {
        run(Command::new("cargo").args(["publish", "--dry-run", "-p", name]))?;
    }
    Ok(())
}

fn is_llvm_cov_installed() -> bool {
    Command::new("cargo")
        .args(["llvm-cov", "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn coverage() -> Result<()> {
    if !is_llvm_cov_installed() {
        bail!(
            "cargo-llvm-cov is not installed. Install with: cargo install cargo-llvm-cov"
        );
    }
    let mut runner = receipt::Runner::new("target/xtask/receipt.json");
    let result = run_coverage(&mut runner);
    runner.summary();
    if let Err(err) = runner.write() {
        eprintln!("failed to write receipt: {err}");
        if result.is_ok() {
            return Err(err);
        }
    }
    result
}

fn run_coverage(runner: &mut receipt::Runner) -> Result<()> {
    fs::create_dir_all("target/coverage")?;
    runner.step("coverage", None, || {
        run(Command::new("cargo")
            .args([
                "llvm-cov",
                "--workspace",
                "--all-features",
                "--lcov",
                "--output-path",
                "target/coverage/lcov.info",
            ])
            .env("PROPTEST_CASES", "16"))
    })?;
    runner.step("coverage:report", None, || {
        run(Command::new("cargo")
            .args(["llvm-cov", "report", "--workspace", "--all-features"])
            .env("PROPTEST_CASES", "16"))
    })?;
    runner.set_coverage_lcov_path("target/coverage/lcov.info".to_string());
    Ok(())
}

fn publish_preflight() -> Result<()> {
    let mut runner = receipt::Runner::new("target/xtask/receipt.json");
    let result = run_publish_preflight(&mut runner);
    runner.summary();
    if let Err(err) = runner.write() {
        eprintln!("failed to write receipt: {err}");
        if result.is_ok() {
            return Err(err);
        }
    }
    result
}

fn run_publish_preflight(runner: &mut receipt::Runner) -> Result<()> {
    runner.step("preflight:metadata", None, check_crate_metadata)?;
    for name in PUBLISH_CRATES {
        let step_name = format!("preflight:package:{name}");
        runner.step(&step_name, None, || {
            run(Command::new("cargo").args(["package", "--no-verify", "-p", name]))
        })?;
    }
    Ok(())
}

fn check_crate_metadata() -> Result<()> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .context("failed to run `cargo metadata`")?;

    if !output.status.success() {
        bail!(
            "`cargo metadata` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let meta: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("failed to parse cargo metadata JSON")?;

    let packages = meta["packages"]
        .as_array()
        .context("missing 'packages' in cargo metadata")?;

    let mut errors: Vec<String> = Vec::new();

    for crate_name in PUBLISH_CRATES {
        let pkg = packages.iter().find(|p| {
            p["name"]
                .as_str()
                .is_some_and(|n| n == *crate_name)
        });

        let Some(pkg) = pkg else {
            errors.push(format!("{crate_name}: not found in workspace metadata"));
            continue;
        };

        let check_string = |field: &str| {
            match pkg.get(field).and_then(|v| v.as_str()) {
                Some(s) if !s.is_empty() => None,
                _ => Some(format!("{crate_name}: missing or empty `{field}`")),
            }
        };

        let check_non_empty_array = |field: &str| {
            match pkg.get(field).and_then(|v| v.as_array()) {
                Some(arr) if !arr.is_empty() => None,
                _ => Some(format!("{crate_name}: missing or empty `{field}`")),
            }
        };

        if let Some(e) = check_string("license") {
            errors.push(e);
        }
        if let Some(e) = check_string("description") {
            errors.push(e);
        }
        if let Some(e) = check_string("repository") {
            errors.push(e);
        }
        if let Some(e) = check_string("readme") {
            errors.push(e);
        }
        if let Some(e) = check_non_empty_array("categories") {
            errors.push(e);
        }
        if let Some(e) = check_non_empty_array("keywords") {
            errors.push(e);
        }
    }

    if !errors.is_empty() {
        bail!("crate metadata errors:\n  {}", errors.join("\n  "));
    }

    Ok(())
}

fn mutants() -> Result<()> {
    // Keep this "soft" so contributors without cargo-mutants can still use xtask.
    let status = Command::new("cargo")
        .args(["mutants", "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => run(Command::new("cargo").args(["mutants"])),
        _ => bail!("cargo-mutants is not installed. Install with: cargo install cargo-mutants"),
    }
}

fn fuzz(target: Option<&str>, extra: &[String]) -> Result<()> {
    let status = Command::new("cargo")
        .args(["fuzz", "--help"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => {
            let mut cmd = Command::new("cargo");
            cmd.args(["fuzz", "run"]);

            if let Some(t) = target {
                cmd.arg(t);
            } else {
                // default target name
                cmd.arg("rsa_pkcs8_pem_parse");
            }

            for a in extra {
                cmd.arg(a);
            }

            run(&mut cmd)
        }
        _ => bail!("cargo-fuzz is not installed. Install with: cargo install cargo-fuzz"),
    }
}

fn pr() -> Result<()> {
    let base_ref = resolve_base_ref();
    let changed_files = git_changed_files(&base_ref)?;
    let plan = plan::build_plan(&changed_files);

    let mut runner = receipt::Runner::new("target/xtask/receipt.json");

    let result = run_pr_plan(&base_ref, &changed_files, &plan, &mut runner);
    runner.summary();
    if let Err(err) = runner.write() {
        eprintln!("failed to write receipt: {err}");
        if result.is_ok() {
            return Err(err);
        }
    }
    result
}

fn run_pr_plan(
    base_ref: &str,
    changed_files: &[String],
    plan: &plan::Plan,
    runner: &mut receipt::Runner,
) -> Result<()> {
    runner.step(
        "detect-changes",
        Some(format!(
            "base_ref={base_ref}, files={}",
            changed_files.len()
        )),
        || Ok(()),
    )?;

    if plan.docs_only {
        let reason = Some("docs-only".to_string());
        runner.skip("fmt", reason.clone());
        runner.skip("clippy", reason.clone());
        runner.skip("tests", reason.clone());
        runner.skip("feature-matrix", reason.clone());
        record_feature_matrix_skipped(runner);
        runner.skip("dep-guard", reason.clone());
        runner.skip("bdd", reason.clone());
        runner.skip("mutants", reason.clone());
        runner.skip("fuzz", reason.clone());
        runner.skip("no-blob", reason.clone());
        runner.skip("coverage", reason.clone());
        runner.skip("coverage:report", reason.clone());
        runner.skip("preflight:metadata", reason.clone());
        for name in PUBLISH_CRATES {
            runner.skip(&format!("preflight:package:{name}"), reason.clone());
        }
        return Ok(());
    }

    if plan.run_fmt {
        runner.step("fmt", None, || fmt(false))?;
    } else {
        runner.skip("fmt", Some("no rust or cargo changes".to_string()));
    }

    if plan.run_clippy {
        runner.step("clippy", None, clippy)?;
    } else {
        runner.skip("clippy", Some("no rust or cargo changes".to_string()));
    }

    if plan.run_tests {
        run_impacted_tests(&plan.impacted_crates, runner)?;
    } else {
        runner.skip("tests", Some("no impacted crates".to_string()));
    }

    if plan.run_feature_matrix {
        run_feature_matrix(runner)?;
    } else {
        runner.skip(
            "feature-matrix",
            Some("no facade or cargo changes".to_string()),
        );
        record_feature_matrix_skipped(runner);
    }

    if plan.run_dep_guard {
        runner.step("dep-guard", None, dep_guard)?;
    } else {
        runner.skip("dep-guard", Some("no cargo changes".to_string()));
    }

    if plan.run_bdd {
        runner.step("bdd", None, bdd)?;
        let counts = count_bdd_scenarios().unwrap_or_default();
        runner.set_bdd_counts(counts);
    } else {
        runner.skip("bdd", Some("no rust or bdd feature changes".to_string()));
    }

    if plan.run_mutants {
        runner.step("mutants", None, mutants)?;
    } else {
        runner.skip("mutants", Some("no rust changes".to_string()));
    }

    if plan.run_fuzz {
        runner.step("fuzz", None, fuzz_pr)?;
    } else {
        runner.skip("fuzz", Some("no rust changes".to_string()));
    }

    if plan.run_no_blob {
        runner.step("no-blob", None, no_blob_gate)?;
    } else {
        runner.skip("no-blob", Some("no test/fixture changes".to_string()));
    }

    if plan.run_coverage {
        if is_llvm_cov_installed() {
            run_coverage(runner)?;
        } else {
            runner.skip("coverage", Some("cargo-llvm-cov not installed".into()));
            runner.skip(
                "coverage:report",
                Some("cargo-llvm-cov not installed".into()),
            );
        }
    } else {
        runner.skip("coverage", Some("no rust changes".into()));
        runner.skip("coverage:report", Some("no rust changes".into()));
    }

    if plan.run_publish_preflight {
        run_publish_preflight(runner)?;
    } else {
        runner.skip("preflight:metadata", Some("no cargo changes".into()));
        for name in PUBLISH_CRATES {
            runner.skip(
                &format!("preflight:package:{name}"),
                Some("no cargo changes".into()),
            );
        }
    }

    Ok(())
}

fn resolve_base_ref() -> String {
    if let Ok(val) = env::var("XTASK_BASE_REF")
        && !val.trim().is_empty()
    {
        return val;
    }

    if let Ok(val) = env::var("GITHUB_BASE_REF")
        && !val.trim().is_empty()
    {
        return format!("origin/{val}");
    }

    "origin/main".to_string()
}

fn git_changed_files(base_ref: &str) -> Result<Vec<String>> {
    let revspec = format!("{base_ref}...HEAD");
    let output = Command::new("git")
        .args(["diff", "--name-only", &revspec])
        .output()
        .context("failed to run git diff")?;

    if !output.status.success() {
        bail!(
            "git diff failed with status {}",
            output.status.code().unwrap_or(-1)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let files = stdout
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    Ok(files)
}

fn run_impacted_tests(
    crates: &std::collections::BTreeSet<String>,
    runner: &mut receipt::Runner,
) -> Result<()> {
    let mut targets: Vec<String> = crates
        .iter()
        .filter(|name| name.as_str() != "uselesskey-bdd")
        .cloned()
        .collect();
    if targets.is_empty() {
        runner.skip(
            "tests",
            Some("no impacted crates after filtering".to_string()),
        );
        return Ok(());
    }
    for name in targets.drain(..) {
        if name == "uselesskey-bdd" {
            continue;
        }
        let step_name = format!("test:{name}");
        runner.step(&step_name, None, || {
            let mut cmd = Command::new("cargo");
            cmd.args(["test", "-p", &name, "--all-features"]);
            run(&mut cmd)
        })?;
    }
    Ok(())
}

fn run_feature_matrix(runner: &mut receipt::Runner) -> Result<()> {
    for (label, args) in FEATURE_MATRIX {
        let step_name = format!("feature-matrix:{label}");
        let result = runner.step(&step_name, None, || {
            let mut cmd = Command::new("cargo");
            cmd.args(["check", "-p", "uselesskey"]);
            for arg in *args {
                cmd.arg(arg);
            }
            run(&mut cmd)
        });
        match result {
            Ok(()) => runner.add_feature_matrix(label, "ok"),
            Err(err) => {
                runner.add_feature_matrix(label, "failed");
                return Err(err);
            }
        }
    }

    Ok(())
}

fn record_feature_matrix_skipped(runner: &mut receipt::Runner) {
    for (label, _) in FEATURE_MATRIX {
        runner.add_feature_matrix(label, "skipped");
    }
}

fn fuzz_pr() -> Result<()> {
    let status = Command::new("cargo")
        .args(["fuzz", "--help"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => {
            let targets = list_fuzz_targets()?;
            if targets.is_empty() {
                return Ok(());
            }
            for target in targets {
                let mut cmd = Command::new("cargo");
                cmd.args([
                    "+nightly",
                    "fuzz",
                    "run",
                    &target,
                    "--",
                    "-runs=1000",
                    "-max_total_time=30",
                ]);
                run(&mut cmd)?;
            }
            Ok(())
        }
        _ => bail!("cargo-fuzz is not installed. Install with: cargo install cargo-fuzz"),
    }
}

fn list_fuzz_targets() -> Result<Vec<String>> {
    let mut targets = Vec::new();
    let dir = Path::new("fuzz/fuzz_targets");
    if !dir.exists() {
        return Ok(targets);
    }
    for entry in fs::read_dir(dir).context("failed to read fuzz_targets")? {
        let entry = entry.context("failed to read fuzz_targets entry")?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            targets.push(stem.to_string());
        }
    }
    targets.sort();
    Ok(targets)
}

fn no_blob_gate() -> Result<()> {
    let offenders = find_secret_blobs()?;
    if offenders.is_empty() {
        return Ok(());
    }
    let joined = offenders.join(", ");
    bail!("found secret-shaped fixtures: {joined}");
}

fn find_secret_blobs() -> Result<Vec<String>> {
    let mut offenders = Vec::new();
    let root = Path::new(".");
    walk_for_blobs(root, root, &mut offenders)?;
    Ok(offenders)
}

fn walk_for_blobs(root: &Path, dir: &Path, offenders: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read_dir failed for {dir:?}"))? {
        let entry = entry.context("failed to read dir entry")?;
        let path = entry.path();
        if path.is_dir() {
            if is_ignored_dir(&path) {
                continue;
            }
            walk_for_blobs(root, &path, offenders)?;
        } else if path.is_file() {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            if !should_scan_path(&rel_str) {
                continue;
            }
            if is_secret_extension(&path) || contains_pem_markers(&path)? {
                offenders.push(rel_str);
            }
        }
    }
    Ok(())
}

fn is_ignored_dir(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    matches!(name, ".git" | "target" | ".cargo")
}

fn should_scan_path(path: &str) -> bool {
    path.starts_with("tests/")
        || path.starts_with("fixtures/")
        || path.starts_with("testdata/")
        || (path.starts_with("crates/") && path.contains("/tests/"))
}

fn is_secret_extension(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "pem" | "der" | "key" | "crt" | "cer" | "p12" | "pfx"
    )
}

fn contains_pem_markers(path: &Path) -> Result<bool> {
    // Skip source code files - they may contain PEM markers as strings in tests
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(ext.as_str(), "rs" | "feature" | "md" | "toml") {
        return Ok(false);
    }
    let content = fs::read(path).with_context(|| format!("failed to read {path:?}"))?;
    let text = String::from_utf8_lossy(&content);
    Ok(text.contains("-----BEGIN") && text.contains("-----END"))
}

fn count_bdd_scenarios() -> Result<BTreeMap<String, usize>> {
    let mut counts = BTreeMap::new();
    let dir = Path::new("crates/uselesskey-bdd/features");
    if !dir.exists() {
        return Ok(counts);
    }
    for entry in fs::read_dir(dir).context("failed to read bdd features dir")? {
        let entry = entry.context("failed to read bdd feature entry")?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("feature") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read feature file {path:?}"))?;
        let mut count = 0usize;
        for line in content.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("Scenario:") || trimmed.starts_with("Scenario Outline:") {
                count += 1;
            }
        }
        counts.insert(name, count);
    }
    Ok(counts)
}

fn nextest() -> Result<()> {
    let status = Command::new("cargo")
        .args(["nextest", "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => {
            run(Command::new("cargo").args(["nextest", "run", "--workspace", "--all-features"]))
        }
        _ => bail!("cargo-nextest is not installed. Install with: cargo install cargo-nextest"),
    }
}

fn deny() -> Result<()> {
    let status = Command::new("cargo")
        .args(["deny", "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => run(Command::new("cargo").args(["deny", "check"])),
        _ => bail!("cargo-deny is not installed. Install with: cargo install cargo-deny"),
    }
}

/// Verify that only one semver-major version of `rand_core` is resolved.
///
/// The RNG pin (`rand_core 0.6`) is a correctness invariant for deterministic
/// derivation. If a transitive dep pulls in a second major version, builds may
/// silently produce different key material.
fn dep_guard() -> Result<()> {
    let output = Command::new("cargo")
        .args(["tree", "--depth", "0", "--duplicates", "--edges", "normal"])
        .output()
        .context("failed to run `cargo tree --duplicates`")?;

    if !output.status.success() {
        bail!(
            "`cargo tree --duplicates` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut versions: Vec<String> = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("rand_core v") {
            let version = rest.split_whitespace().next().unwrap_or(rest);
            if !versions.contains(&version.to_string()) {
                versions.push(version.to_string());
            }
        }
    }

    if versions.is_empty() {
        eprintln!("dep-guard: rand_core has no duplicates (ok)");
        return Ok(());
    }

    // Multiple versions found in duplicates output
    bail!(
        "dep-guard: multiple versions of rand_core resolved: {}. \
         Only rand_core 0.6.x is allowed. \
         A transitive dependency is pulling in a conflicting version.",
        versions
            .iter()
            .map(|v| format!("v{v}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::PathBuf;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct CwdGuard {
        prev: PathBuf,
    }

    impl CwdGuard {
        fn new(path: &Path) -> Self {
            let prev = env::current_dir().expect("current dir");
            env::set_current_dir(path).expect("set current dir");
            Self { prev }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = env::set_current_dir(&self.prev);
        }
    }

    fn restore_env(key: &str, prev: Option<String>) {
        match prev {
            Some(val) => unsafe { env::set_var(key, val) },
            None => unsafe { env::remove_var(key) },
        }
    }

    #[test]
    fn resolve_base_ref_prefers_xtask_base_ref() {
        let _lock = ENV_LOCK.lock().unwrap();
        let prev_xtask = env::var("XTASK_BASE_REF").ok();
        let prev_gh = env::var("GITHUB_BASE_REF").ok();

        unsafe { env::set_var("XTASK_BASE_REF", "origin/feature-branch") };
        unsafe { env::set_var("GITHUB_BASE_REF", "main") };
        assert_eq!(resolve_base_ref(), "origin/feature-branch");

        restore_env("XTASK_BASE_REF", prev_xtask);
        restore_env("GITHUB_BASE_REF", prev_gh);
    }

    #[test]
    fn resolve_base_ref_uses_github_base_ref() {
        let _lock = ENV_LOCK.lock().unwrap();
        let prev_xtask = env::var("XTASK_BASE_REF").ok();
        let prev_gh = env::var("GITHUB_BASE_REF").ok();

        unsafe { env::remove_var("XTASK_BASE_REF") };
        unsafe { env::set_var("GITHUB_BASE_REF", "dev") };
        assert_eq!(resolve_base_ref(), "origin/dev");

        restore_env("XTASK_BASE_REF", prev_xtask);
        restore_env("GITHUB_BASE_REF", prev_gh);
    }

    #[test]
    fn resolve_base_ref_defaults_to_origin_main() {
        let _lock = ENV_LOCK.lock().unwrap();
        let prev_xtask = env::var("XTASK_BASE_REF").ok();
        let prev_gh = env::var("GITHUB_BASE_REF").ok();

        unsafe { env::remove_var("XTASK_BASE_REF") };
        unsafe { env::remove_var("GITHUB_BASE_REF") };
        assert_eq!(resolve_base_ref(), "origin/main");

        restore_env("XTASK_BASE_REF", prev_xtask);
        restore_env("GITHUB_BASE_REF", prev_gh);
    }

    #[test]
    fn should_scan_path_matches_expected() {
        assert!(should_scan_path("tests/fixture.pem"));
        assert!(should_scan_path("fixtures/key.pem"));
        assert!(should_scan_path("testdata/key.pem"));
        assert!(should_scan_path("crates/uselesskey-core/tests/basic.rs"));
        assert!(!should_scan_path("crates/uselesskey-core/src/lib.rs"));
        assert!(!should_scan_path("docs/guide.md"));
    }

    #[test]
    fn is_secret_extension_is_case_insensitive() {
        assert!(is_secret_extension(Path::new("key.PEM")));
        assert!(is_secret_extension(Path::new("cert.CRT")));
        assert!(!is_secret_extension(Path::new("readme.txt")));
    }

    #[test]
    fn contains_pem_markers_skips_source_extensions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("notes.md");
        fs::write(&path, "-----BEGIN TEST-----\nX\n-----END TEST-----\n").unwrap();
        let has = contains_pem_markers(&path).expect("read file");
        assert!(!has);
    }

    #[test]
    fn contains_pem_markers_detects_markers_in_non_source_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let yes = dir.path().join("key.txt");
        let no = dir.path().join("note.txt");
        fs::write(&yes, "-----BEGIN TEST-----\nX\n-----END TEST-----\n").unwrap();
        fs::write(&no, "just text").unwrap();

        assert!(contains_pem_markers(&yes).expect("read file"));
        assert!(!contains_pem_markers(&no).expect("read file"));
    }

    #[test]
    fn contains_pem_markers_errors_on_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing.txt");
        let err = contains_pem_markers(&missing).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to read"));
    }

    #[test]
    fn list_fuzz_targets_returns_sorted_rs_stems() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let fuzz_dir = root.join("fuzz").join("fuzz_targets");
        fs::create_dir_all(&fuzz_dir).expect("create fuzz_targets");
        fs::write(fuzz_dir.join("b.rs"), "fn main() {}").unwrap();
        fs::write(fuzz_dir.join("a.rs"), "fn main() {}").unwrap();
        fs::write(fuzz_dir.join("README.md"), "ignore").unwrap();

        let _cwd = CwdGuard::new(root);
        let targets = list_fuzz_targets().expect("list targets");
        assert_eq!(targets, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn list_fuzz_targets_missing_dir_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _cwd = CwdGuard::new(dir.path());
        let targets = list_fuzz_targets().expect("list targets");
        assert!(targets.is_empty());
    }

    #[test]
    fn count_bdd_scenarios_counts_scenarios_and_outlines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let features_dir = root.join("crates").join("uselesskey-bdd").join("features");
        fs::create_dir_all(&features_dir).expect("create features dir");
        let feature = features_dir.join("sample.feature");
        fs::write(
            &feature,
            "Feature: demo\n  Scenario: one\n  Scenario Outline: two\n",
        )
        .unwrap();

        let _cwd = CwdGuard::new(root);
        let counts = count_bdd_scenarios().expect("count scenarios");
        assert_eq!(counts.get("sample.feature"), Some(&2));
    }
}
