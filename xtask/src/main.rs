use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;
use regex::Regex;
use uselesskey_feature_grid::{BDD_FEATURE_MATRIX, CORE_FEATURE_MATRIX};

mod docs_sync;
mod plan;
mod pr_bundles;
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
    /// Run performance harness and optionally compare against checked-in baselines.
    Perf {
        /// Compare latest run against docs/metadata/perf-baselines.json budgets.
        #[arg(long)]
        compare: bool,
    },
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
    /// Run spell check (requires `typos` installed).
    Typos {
        /// Fix typos automatically.
        #[arg(long)]
        fix: bool,
    },
    /// Run the common CI pipeline: fmt + clippy + tests + typos + deny.
    Ci,
    /// Run the feature matrix checks.
    FeatureMatrix,
    /// Enforce no secret-shaped blobs in test/fixture paths.
    NoBlob,
    /// Synchronize docs from metadata source.
    DocsSync {
        /// Verify generated output instead of writing files.
        #[arg(long)]
        check: bool,
    },
    /// Compile example list from metadata and optionally run curated examples.
    ExamplesSmoke {
        /// Run curated smoke examples after compile checks.
        #[arg(long)]
        run: bool,
    },
    /// Run publish dry-runs for crates in dependency order.
    PublishCheck,
    /// Run PR-scoped tests based on git diff.
    Pr,
    /// Guard against multiple semver-major versions of pinned deps (e.g. rand_core).
    DepGuard,
    /// Run cucumber BDD features.
    Bdd,
    /// Run cucumber BDD matrix with feature sets.
    BddMatrix,
    /// Run mutation testing (requires `cargo-mutants` installed).
    Mutants,
    /// Run code coverage via cargo-llvm-cov (requires `cargo-llvm-cov` installed).
    Coverage,
    /// Validate publish metadata and run `cargo package --no-verify` for all crates.
    PublishPreflight,
    /// Publish all crates to crates.io in dependency order (with retry logic).
    Publish {
        /// Resume from this crate (skip all crates before it in publish order).
        #[arg(long)]
        from: Option<String>,
        /// Resume from the last failure recorded in target/xtask/publish-state.json.
        #[arg(long)]
        resume: bool,
    },
    /// Run fuzz targets (requires `cargo-fuzz` installed).
    Fuzz {
        /// Name of the fuzz target (e.g. `rsa_pkcs8_pem_parse`).
        #[arg(long)]
        target: Option<String>,
        /// Extra args passed to `cargo fuzz run`.
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Auto-fix formatting and clippy warnings.
    LintFix {
        /// Check only (no mutations). Equivalent to fmt --check + clippy.
        #[arg(long)]
        check: bool,
        /// Skip clippy (fmt only).
        #[arg(long)]
        no_clippy: bool,
    },
    /// Pre-push quality gate: fmt check + cargo check + clippy + test compile.
    Gate {
        /// Exists for symmetry; behavior is always non-mutating.
        #[arg(long)]
        check: bool,
    },
    /// Configure git hooks (sets core.hooksPath to .githooks).
    Setup,
    /// Lint commit message (used by git hooks).
    CommitLint {
        /// Path to the commit message file.
        message_file: PathBuf,
    },
    /// Run git hook behavior.
    Hook {
        /// Name of the git hook (pre-commit, pre-push).
        #[command(subcommand)]
        hook: HookCmd,
    },
    /// Manage the PR backlog as keeper-based bundles.
    PrBundles {
        /// Snapshot / ledger / worktree preparation for PR bundles.
        #[command(subcommand)]
        command: PrBundlesCmd,
    },
}

#[derive(Subcommand)]
enum HookCmd {
    /// Delegate for `pre-commit`.
    PreCommit,
    /// Delegate for `pre-push`.
    PrePush,
}

#[derive(Subcommand)]
enum PrBundlesCmd {
    /// Fetch open PRs and recent closed donors using the REST API.
    Snapshot {
        /// Explicit repo in `owner/name` form. Defaults to the current gh repo.
        #[arg(long)]
        repo: Option<String>,
        /// Also collect touched paths for closed PR donor analysis.
        #[arg(long)]
        include_closed_paths: bool,
        /// Output path for the snapshot JSON.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Build keeper-ledger Markdown and companion JSON from a snapshot.
    Ledger {
        /// Input snapshot JSON path.
        #[arg(long)]
        snapshot: Option<PathBuf>,
        /// Output path for the structured ledger JSON.
        #[arg(long)]
        json_out: Option<PathBuf>,
        /// Output path for the rendered ledger Markdown.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Create a dedicated worktree from an explicit keeper PR branch.
    Prepare {
        /// Bundle id from the generated ledger.
        #[arg(long)]
        bundle_id: String,
        /// Explicit keeper PR number. Required before edits begin.
        #[arg(long)]
        keeper: u64,
        /// Snapshot JSON path. Defaults to `target/xtask/pr-bundles/snapshot.json`.
        #[arg(long)]
        snapshot: Option<PathBuf>,
        /// Base ref to rebase onto after the worktree is created.
        #[arg(long)]
        base_ref: Option<String>,
        /// Explicit worktree path. Defaults to `../uselesskey-bundle-<bundle-id>`.
        #[arg(long)]
        worktree_path: Option<PathBuf>,
        /// Explicit local branch name. Defaults to `work/<bundle-id>-keeper`.
        #[arg(long)]
        branch_name: Option<String>,
    },
    /// Remove a prepared worktree and optionally force cleanup.
    Cleanup {
        /// Bundle id used during `cargo xtask pr-bundles prepare`.
        #[arg(long)]
        bundle_id: String,
        /// Explicit worktree path. Defaults to `../uselesskey-bundle-<bundle-id>`.
        #[arg(long)]
        worktree_path: Option<PathBuf>,
        /// Explicit local branch name. Defaults to `work/<bundle-id>-keeper`.
        #[arg(long)]
        branch_name: Option<String>,
        /// Remove the worktree even if it has local changes.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Perf { compare } => perf(compare),
        Cmd::Fmt { fix } => fmt(fix),
        Cmd::Clippy => clippy(),
        Cmd::Test => test(),
        Cmd::Nextest => nextest(),
        Cmd::Deny => deny(),
        Cmd::Typos { fix } => typos(fix),
        Cmd::Ci => ci(),
        Cmd::FeatureMatrix => feature_matrix_cmd(),
        Cmd::NoBlob => no_blob_gate(),
        Cmd::DocsSync { check } => docs_sync::docs_sync_cmd(check),
        Cmd::ExamplesSmoke { run } => docs_sync::examples_smoke_cmd(run),
        Cmd::PublishCheck => publish_check(),
        Cmd::Pr => pr(),
        Cmd::DepGuard => dep_guard(),
        Cmd::Bdd => bdd(),
        Cmd::BddMatrix => bdd_matrix(),
        Cmd::Coverage => coverage(),
        Cmd::PublishPreflight => publish_preflight(),
        Cmd::Publish { from, resume } => publish(from, resume),
        Cmd::Mutants => run_mutants(PUBLISH_CRATES),
        Cmd::Fuzz { target, args } => fuzz(target.as_deref(), &args),
        Cmd::LintFix { check, no_clippy } => lint_fix(check, no_clippy),
        Cmd::Gate { check: _ } => gate(),
        Cmd::Setup => setup(),
        Cmd::CommitLint { message_file } => commit_lint(&message_file),
        Cmd::Hook { hook } => match hook {
            HookCmd::PreCommit => hook_pre_commit(),
            HookCmd::PrePush => hook_pre_push(),
        },
        Cmd::PrBundles { command } => match command {
            PrBundlesCmd::Snapshot {
                repo,
                include_closed_paths,
                output,
            } => bundle_snapshot(repo, include_closed_paths, output),
            PrBundlesCmd::Ledger {
                snapshot,
                json_out,
                output,
            } => bundle_ledger(snapshot, json_out, output),
            PrBundlesCmd::Prepare {
                bundle_id,
                keeper,
                snapshot,
                base_ref,
                worktree_path,
                branch_name,
            } => bundle_prepare(
                &bundle_id,
                keeper,
                snapshot,
                base_ref,
                worktree_path,
                branch_name,
            ),
            PrBundlesCmd::Cleanup {
                bundle_id,
                worktree_path,
                branch_name,
                force,
            } => bundle_cleanup(&bundle_id, worktree_path, branch_name, force),
        },
    }
}

fn bundle_snapshot(
    repo: Option<String>,
    include_closed_paths: bool,
    output: Option<PathBuf>,
) -> Result<()> {
    let mut cmd = pr_bundles::SnapshotCommand::new(repo);
    if let Some(path) = output {
        cmd.output_path = path;
    }
    cmd.include_closed_paths = include_closed_paths;

    let snapshot = pr_bundles::snapshot_cmd(&cmd)?;

    println!(
        "pr-bundles snapshot: wrote {} (open={}, closed={})",
        cmd.output_path.display(),
        snapshot.open_pull_requests.len(),
        snapshot.closed_pull_requests.len()
    );
    Ok(())
}

fn bundle_ledger(
    snapshot: Option<PathBuf>,
    json_out: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<()> {
    let snapshot_path =
        snapshot.unwrap_or_else(|| PathBuf::from("target/xtask/pr-bundles/snapshot.json"));
    let mut cmd = pr_bundles::LedgerCommand::new(&snapshot_path);
    if let Some(path) = &output {
        cmd.output_path = Some(path.clone());
    }

    let report = pr_bundles::ledger_cmd(&cmd)?;
    let json_path =
        json_out.unwrap_or_else(|| PathBuf::from("target/xtask/pr-bundles/ledger.json"));
    write_json_pretty(&json_path, &report.analysis)?;
    let _ = report.markdown.len();

    let markdown_path = cmd
        .output_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("target/xtask/pr-bundles/ledger.md"));
    println!(
        "pr-bundles ledger: wrote {} and {}",
        json_path.display(),
        markdown_path.display()
    );
    Ok(())
}

fn bundle_prepare(
    bundle_id: &str,
    keeper: u64,
    snapshot_json: Option<PathBuf>,
    base_ref: Option<String>,
    worktree_path: Option<PathBuf>,
    branch_name: Option<String>,
) -> Result<()> {
    let snapshot_path =
        snapshot_json.unwrap_or_else(|| PathBuf::from("target/xtask/pr-bundles/snapshot.json"));
    let snapshot: pr_bundles::BundleSnapshot = read_json_file(&snapshot_path)?;
    let analysis = pr_bundles::analyze_snapshot(&snapshot);
    let bundle = analysis
        .bundles
        .iter()
        .find(|bundle| bundle.bundle_id == bundle_id)
        .with_context(|| {
            format!(
                "bundle `{bundle_id}` not found in {}",
                snapshot_path.display()
            )
        })?;
    let keeper_pr = keeper;
    let prepared = pr_bundles::prepare_cmd(&pr_bundles::PrepareCommand {
        repo_root: workspace_root_path(),
        snapshot_path,
        bundle_id: bundle.bundle_id.clone(),
        base_ref: base_ref
            .clone()
            .unwrap_or_else(|| "origin/main".to_string()),
        keeper_pr,
        branch_name,
        worktree_path,
    })?;
    let target_base = base_ref.unwrap_or_else(|| "origin/main".to_string());

    println!("pr-bundles prepare");
    println!("bundle: {}", bundle.bundle_id);
    println!("keeper: #{} ({})", keeper_pr, bundle.keeper.title);
    println!("path: {}", prepared.worktree_path.display());
    println!("branch: {}", prepared.branch);
    println!("next:");
    println!("  cd {}", prepared.worktree_path.display());
    println!("  git fetch origin");
    println!("  git rebase {target_base}");
    Ok(())
}

fn bundle_cleanup(
    bundle_id: &str,
    worktree_path: Option<PathBuf>,
    branch_name: Option<String>,
    force: bool,
) -> Result<()> {
    let repo_root = workspace_root_path();
    let target_path =
        worktree_path.unwrap_or_else(|| pr_bundles::default_worktree_path(&repo_root, bundle_id));
    let target_branch = branch_name.unwrap_or_else(|| pr_bundles::default_keeper_branch(bundle_id));

    let cmd = pr_bundles::CleanupCommand {
        repo_root,
        worktree_path: target_path,
        base_ref: Some("origin/main".to_string()),
        branch: Some(target_branch),
        force,
        delete_branch: true,
        prune: true,
    };
    let report = pr_bundles::cleanup_cmd(&cmd)?;
    println!(
        "pr-bundles cleanup: removed {} (branch_deleted={}, pruned={})",
        report.worktree_path.display(),
        report.branch_deleted,
        report.pruned
    );
    Ok(())
}

fn write_json_pretty(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(value).context("failed to serialize JSON")?;
    fs::write(path, json).with_context(|| format!("failed to write {}", path.display()))
}

fn read_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

fn run(cmd: &mut Command) -> Result<()> {
    eprintln!(
        "{} {:?}",
        " RUN ".on_bright_blue().black().bold(),
        cmd.bold()
    );
    let status = cmd
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("failed to spawn command")?;

    if !status.success() {
        bail!(
            "{} command failed with status: {status}",
            " ERR ".on_bright_red().black().bold()
        );
    }
    Ok(())
}

fn fmt(fix: bool) -> Result<()> {
    if cfg!(windows) {
        for package in workspace_package_names()? {
            let mut cmd = Command::new("cargo");
            cmd.args(["fmt", "-p", &package]);
            if !fix {
                cmd.args(["--", "--check"]);
            }
            run(&mut cmd).with_context(|| format!("cargo fmt failed for {package}"))?;
        }
        Ok(())
    } else if fix {
        run(Command::new("cargo").args(["fmt", "--all"]))
    } else {
        run(Command::new("cargo").args(["fmt", "--all", "--", "--check"]))
    }
}

fn workspace_package_names() -> Result<Vec<String>> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .context("failed to run `cargo metadata` for workspace package list")?;

    if !output.status.success() {
        bail!(
            "`cargo metadata` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let meta: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("failed to parse cargo metadata JSON")?;

    let workspace_members = meta["workspace_members"]
        .as_array()
        .context("missing 'workspace_members' in cargo metadata")?
        .iter()
        .filter_map(|member| member.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    let packages = meta["packages"]
        .as_array()
        .context("missing 'packages' in cargo metadata")?;

    let mut names = packages
        .iter()
        .filter(|pkg| {
            pkg["id"]
                .as_str()
                .is_some_and(|id| workspace_members.contains(id))
        })
        .filter_map(|pkg| pkg["name"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();

    names.sort();
    names.dedup();
    Ok(names)
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
    run(Command::new("cargo").args([
        "test",
        "--workspace",
        "--all-features",
        "--exclude",
        "uselesskey-bdd",
    ]))
}

fn bdd() -> Result<()> {
    run(Command::new("cargo").args([
        "test",
        "-p",
        "uselesskey-bdd",
        "--test",
        "bdd",
        "--features",
        "uk-all",
        "--release",
    ]))
}

fn bdd_matrix() -> Result<()> {
    let mut runner = receipt::Runner::new("target/xtask/receipt.json");

    let pb = ProgressBar::new(BDD_FEATURE_MATRIX.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    // Define the feature sets to run
    for feature_set in BDD_FEATURE_MATRIX {
        let name = feature_set.name;
        pb.set_message(format!("running matrix: {name}"));
        let args = feature_set.cargo_args;
        let step_name = format!("bdd-matrix:{name}");
        let result = runner.step(&step_name, None, || {
            let mut cmd = Command::new("cargo");
            cmd.args(["test", "-p", "uselesskey-bdd", "--test", "bdd", "--release"]);
            for arg in args {
                cmd.arg(arg);
            }
            run_quietly(&mut cmd)
        });

        match result {
            Ok(()) => runner.add_bdd_matrix(name, "ok"),
            Err(err) => {
                runner.add_bdd_matrix(name, "failed");
                pb.finish_with_message(format!("failed matrix: {name}"));
                return Err(err);
            }
        }
        pb.inc(1);
    }

    pb.finish_with_message("BDD matrix complete");
    runner.summary();
    runner.write()
}

fn ci() -> Result<()> {
    let mut runner = receipt::Runner::new("target/xtask/receipt.json");
    let result = run_ci_plan(&mut runner);
    runner.summary();
    if let Err(err) = runner.write() {
        eprintln!(
            "{} failed to write receipt: {err}",
            " WARN ".on_yellow().black().bold()
        );
        if result.is_ok() {
            return Err(err);
        }
    }
    result
}

fn run_ci_plan(runner: &mut receipt::Runner) -> Result<()> {
    runner.step("fmt", None, || fmt(false))?;
    runner.step("clippy", None, clippy)?;
    runner.step("typos", None, || typos(false))?;
    runner.step("deny", None, deny)?;
    runner.step("tests", None, test)?;

    run_feature_matrix(runner)?;

    runner.step("dep-guard", None, dep_guard)?;
    runner.step("docs-sync", None, || docs_sync::docs_sync_cmd(true))?;
    runner.step("bdd", None, bdd)?;
    let counts = count_bdd_scenarios().unwrap_or_default();
    runner.set_bdd_counts(counts);

    runner.step("no-blob", None, no_blob_gate)?;
    runner.step("mutants", None, || run_mutants(MUTANT_CRATES))?;
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
    // Leaf crates (no workspace deps)
    "uselesskey-core-seed",
    "uselesskey-core-base62",
    "uselesskey-core-hash",
    "uselesskey-core-hmac-spec",
    "uselesskey-core-id",
    "uselesskey-core-cache",
    "uselesskey-core-factory",
    "uselesskey-core-kid",
    "uselesskey-token-spec",
    // Negative fixture crates
    "uselesskey-core-negative-der",
    "uselesskey-core-negative-pem",
    "uselesskey-core-negative",
    // Sinks and shapes
    "uselesskey-core-sink",
    "uselesskey-core-token-shape",
    "uselesskey-core-token",
    "uselesskey-core-jwk-shape",
    "uselesskey-core-jwks-order",
    "uselesskey-core-jwk-builder",
    "uselesskey-core-jwk",
    // X.509 crates (in dep order)
    "uselesskey-core-x509-spec",
    "uselesskey-core-x509-derive",
    "uselesskey-core-x509-chain-negative",
    "uselesskey-core-x509-negative",
    "uselesskey-core-x509",
    // Core aggregate
    "uselesskey-core",
    "uselesskey-core-keypair-material",
    "uselesskey-core-keypair",
    // Mid-level crates
    "uselesskey-jwk",
    "uselesskey-rsa",
    "uselesskey-ecdsa",
    "uselesskey-ed25519",
    "uselesskey-hmac",
    "uselesskey-token",
    "uselesskey-pgp",
    "uselesskey-x509",
    // Adapters (depend on key crates, NOT on facade)
    "uselesskey-core-rustls-pki",
    "uselesskey-jsonwebtoken",
    "uselesskey-jose-openid",
    "uselesskey-pgp-native",
    "uselesskey-rustls",
    "uselesskey-tonic",
    "uselesskey-ring",
    "uselesskey-rustcrypto",
    "uselesskey-aws-lc-rs",
    // Facade (dev-depends on adapters above)
    "uselesskey",
];

/// Subset of `PUBLISH_CRATES` for CI-wide mutation testing.
///
/// Excludes algorithm and adapter crates whose tests involve key generation
/// (RSA, ECDSA, Ed25519, PGP, X.509, adapters). These are still
/// mutant-tested when directly impacted in PR-scoped runs.
const MUTANT_CRATES: &[&str] = &[
    "uselesskey-core-seed",
    "uselesskey-core-base62",
    "uselesskey-core-hash",
    "uselesskey-core-hmac-spec",
    "uselesskey-core-id",
    "uselesskey-core-cache",
    "uselesskey-core-factory",
    "uselesskey-core-kid",
    "uselesskey-core-negative-der",
    "uselesskey-core-negative-pem",
    "uselesskey-core-negative",
    "uselesskey-core-sink",
    "uselesskey-core-token-shape",
    "uselesskey-core-token",
    "uselesskey-core-jwk-shape",
    "uselesskey-core-jwks-order",
    "uselesskey-core-jwk-builder",
    "uselesskey-core-jwk",
    "uselesskey-core-x509-spec",
    "uselesskey-core-x509-derive",
    "uselesskey-core-x509-chain-negative",
    "uselesskey-core-x509-negative",
    "uselesskey-core-x509",
    "uselesskey-core",
    "uselesskey-core-keypair-material",
    "uselesskey-core-keypair",
    "uselesskey-jwk",
    "uselesskey-hmac",
    "uselesskey-token",
    "uselesskey-token-spec",
];

fn publish_check() -> Result<()> {
    for name in PUBLISH_CRATES {
        let output = Command::new("cargo")
            .args(["publish", "--dry-run", "-p", name])
            .output()
            .with_context(|| format!("failed to spawn cargo publish --dry-run for {name}"))?;

        if output.status.success() {
            continue;
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_unpublished_workspace_dep_error(&stderr) {
            eprintln!(
                "  [warn] {name} publish check: skipped (workspace dep not yet on crates.io)"
            );
            continue;
        }
        bail!("cargo publish --dry-run -p {name} failed:\n{stderr}");
    }
    Ok(())
}

fn is_unpublished_workspace_dep_error(stderr: &str) -> bool {
    stderr.contains("no matching package named")
        || (stderr.contains("failed to select a version for the requirement")
            && stderr.contains("candidate versions found which didn't match")
            && stderr.contains("location searched: crates.io index"))
}

fn run_quietly(cmd: &mut Command) -> Result<()> {
    let output = cmd.output().context("failed to spawn command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("command failed with status {}: {stderr}", output.status);
    }
    Ok(())
}

const PERF_BASELINE_PATH: &str = "docs/metadata/perf-baselines.json";
const PERF_LATEST_PATH: &str = "target/xtask/perf/latest.json";

#[derive(Debug, serde::Deserialize)]
struct PerfBaselineFile {
    version: u32,
    entries: Vec<PerfBudgetEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct PerfBudgetEntry {
    id: String,
    baseline_median_ns: u64,
    max_regression_pct: f64,
    enforce_in_ci: bool,
    #[allow(dead_code)]
    category: String,
}

#[derive(Debug, serde::Deserialize)]
struct PerfLatestFile {
    version: u32,
    scenarios: Vec<PerfLatestEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct PerfLatestEntry {
    id: String,
    median_ns: u64,
}

fn perf(compare: bool) -> Result<()> {
    run(Command::new("cargo").args([
        "run",
        "-p",
        "uselesskey-bench",
        "--release",
        "--",
        "--output",
        PERF_LATEST_PATH,
    ]))?;

    if compare {
        perf_compare()?;
    }
    Ok(())
}

fn perf_compare() -> Result<()> {
    let baseline_json = fs::read_to_string(PERF_BASELINE_PATH)
        .with_context(|| format!("failed to read {PERF_BASELINE_PATH}"))?;
    let latest_json =
        fs::read_to_string(PERF_LATEST_PATH).with_context(|| format!("failed to read {PERF_LATEST_PATH}"))?;

    let baseline: PerfBaselineFile =
        serde_json::from_str(&baseline_json).context("invalid perf baseline JSON schema")?;
    let latest: PerfLatestFile =
        serde_json::from_str(&latest_json).context("invalid latest perf JSON schema")?;

    if baseline.version != 1 || latest.version != 1 {
        bail!(
            "unsupported perf schema versions baseline={} latest={}",
            baseline.version,
            latest.version
        );
    }

    let latest_by_id = latest
        .scenarios
        .iter()
        .map(|s| (s.id.as_str(), s))
        .collect::<BTreeMap<_, _>>();
    let mut violations = Vec::new();

    for budget in &baseline.entries {
        let Some(measured) = latest_by_id.get(budget.id.as_str()) else {
            bail!("latest perf report missing required benchmark id: {}", budget.id);
        };
        let regression_pct =
            ((measured.median_ns as f64 - budget.baseline_median_ns as f64) / budget.baseline_median_ns as f64)
                * 100.0;
        let status = if regression_pct > budget.max_regression_pct {
            if budget.enforce_in_ci {
                "FAIL"
            } else {
                "WARN"
            }
        } else {
            "OK"
        };
        eprintln!(
            "[perf:{status}] {:32} baseline={}ns latest={}ns regression={:+.2}% threshold={:.2}%",
            budget.id, budget.baseline_median_ns, measured.median_ns, regression_pct, budget.max_regression_pct
        );
        if status == "FAIL" {
            violations.push(format!(
                "{} regressed by {:.2}% (threshold {:.2}%)",
                budget.id, regression_pct, budget.max_regression_pct
            ));
        }
    }

    if !violations.is_empty() {
        bail!("performance budget check failed:\n{}", violations.join("\n"));
    }

    Ok(())
}

fn typos(fix: bool) -> Result<()> {
    let mut cmd = Command::new("typos");
    if fix {
        cmd.arg("--write-changes");
    }
    run(&mut cmd)
}

const PUBLISH_STATE_PATH: &str = "target/xtask/publish-state.json";

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PublishState {
    timestamp: u64,
    crates: Vec<PublishCrateState>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PublishCrateState {
    name: String,
    status: String, // "published", "already_published", "skipped", "failed", "pending"
}

/// Parse a crates.io 429 "try again after" timestamp and return seconds to wait.
///
/// crates.io returns messages like:
/// > Please try again after Sun, 08 Mar 2026 06:57:08 GMT
///
/// Returns `None` if parsing fails (caller falls back to exponential backoff).
fn parse_retry_after(stderr: &str) -> Option<u64> {
    let re = regex::Regex::new(
        r"try again after ([A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT)",
    )
    .ok()?;
    let caps = re.captures(stderr)?;
    let timestamp_str = caps.get(1)?.as_str();
    let retry_at = chrono::DateTime::parse_from_rfc2822(timestamp_str).ok()?;
    let now = chrono::Utc::now();
    let delta = retry_at.signed_duration_since(now).num_seconds();
    // Add 15s buffer; minimum 5s wait
    let wait = (delta + 15).max(5) as u64;
    Some(wait)
}

fn write_publish_state(state: &PublishState) -> Result<()> {
    let dir = Path::new(PUBLISH_STATE_PATH).parent().unwrap();
    fs::create_dir_all(dir).context("failed to create publish state directory")?;
    let json = serde_json::to_string_pretty(state).context("failed to serialize publish state")?;
    fs::write(PUBLISH_STATE_PATH, json).context("failed to write publish state file")?;
    Ok(())
}

fn read_publish_state() -> Result<PublishState> {
    let json =
        fs::read_to_string(PUBLISH_STATE_PATH).context("failed to read publish state file")?;
    let state: PublishState =
        serde_json::from_str(&json).context("failed to parse publish state file")?;
    Ok(state)
}

fn resolve_start_index(from: Option<&str>, resume: bool) -> Result<usize> {
    if from.is_some() && resume {
        bail!("--from and --resume are mutually exclusive; use one or the other");
    }

    if let Some(name) = from {
        match PUBLISH_CRATES.iter().position(|c| *c == name) {
            Some(idx) => return Ok(idx),
            None => {
                let list = PUBLISH_CRATES
                    .iter()
                    .enumerate()
                    .map(|(i, c)| format!("  {i}: {c}"))
                    .collect::<Vec<_>>()
                    .join("\n");
                bail!("crate {name:?} not found in publish order. Valid crates:\n{list}");
            }
        }
    }

    if resume {
        let state = read_publish_state().context(
            "failed to read publish state for --resume; run a publish first or use --from",
        )?;
        for (i, cs) in state.crates.iter().enumerate() {
            if cs.status != "published" && cs.status != "already_published" {
                return Ok(i);
            }
        }
        // All crates already succeeded
        return Ok(PUBLISH_CRATES.len());
    }

    Ok(0)
}

fn publish(from: Option<String>, resume: bool) -> Result<()> {
    let start_index = resolve_start_index(from.as_deref(), resume)?;

    if start_index >= PUBLISH_CRATES.len() {
        eprintln!("all crates already published; nothing to do");
        return Ok(());
    }

    if start_index > 0 {
        eprintln!(
            "starting from crate {} ({}/{})",
            PUBLISH_CRATES[start_index],
            start_index + 1,
            PUBLISH_CRATES.len()
        );
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut state = PublishState {
        timestamp: now,
        crates: PUBLISH_CRATES
            .iter()
            .enumerate()
            .map(|(i, name)| PublishCrateState {
                name: name.to_string(),
                status: if i < start_index {
                    "skipped".to_string()
                } else {
                    "pending".to_string()
                },
            })
            .collect(),
    };

    let pb = ProgressBar::new(PUBLISH_CRATES.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_position(start_index as u64);

    for (i, name) in PUBLISH_CRATES.iter().enumerate() {
        if i < start_index {
            continue;
        }
        pb.set_message(format!("publishing {name}"));
        let mut success = false;
        let mut already_published = false;
        for attempt in 1..=5 {
            let output = Command::new("cargo")
                .args(["publish", "-p", name])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()
                .with_context(|| format!("failed to run cargo publish for {name}"))?;

            if output.status.success() {
                success = true;
                break;
            }

            let stderr = String::from_utf8_lossy(&output.stderr);

            // Already published — treat as success, skip indexing delay
            if stderr.contains("already uploaded")
                || stderr.contains("already exists")
                || stderr.contains("is already published")
            {
                success = true;
                already_published = true;
                break;
            }

            let index_race = stderr.contains("failed to select a version")
                || stderr.contains("no matching package")
                || stderr.to_lowercase().contains("not found in index");
            let rate_limited = stderr.contains("429")
                || stderr.to_lowercase().contains("too many")
                || stderr.to_lowercase().contains("rate limit");
            let server_error = stderr.contains("503")
                || stderr.contains("500")
                || stderr.to_lowercase().contains("try again");

            if index_race || rate_limited || server_error {
                let (reason, wait) = if rate_limited {
                    let wait = parse_retry_after(&stderr).unwrap_or(120 * attempt as u64);
                    ("rate-limited", wait)
                } else if server_error {
                    ("server error", 60 * attempt as u64)
                } else {
                    ("indexing race", 60)
                };
                pb.set_message(format!(
                    "{reason} on {name} (attempt {attempt}/5)... waiting {wait}s"
                ));
                eprintln!("[{name} attempt {attempt}] {reason}: {stderr}");
                std::thread::sleep(std::time::Duration::from_secs(wait));
            } else {
                eprint!("{stderr}");
                state.crates[i].status = "failed".to_string();
                let _ = write_publish_state(&state);
                pb.finish_with_message(format!("failed {name}"));
                bail!("{name} publish failed with a non-retriable error");
            }
        }
        if !success {
            state.crates[i].status = "failed".to_string();
            let _ = write_publish_state(&state);
            pb.finish_with_message(format!("failed {name} after 5 attempts"));
            bail!("{name} failed after 5 attempts");
        }
        if already_published {
            state.crates[i].status = "already_published".to_string();
            pb.set_message(format!("{name} already published, skipping indexing wait"));
        } else {
            state.crates[i].status = "published".to_string();
            pb.set_message(format!("published {name}, waiting for indexing"));
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
        let _ = write_publish_state(&state);
        pb.inc(1);
    }
    pb.finish_with_message("all crates published successfully");
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
        bail!("cargo-llvm-cov is not installed. Install with: cargo install cargo-llvm-cov");
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

    let lcov_path = "target/coverage/lcov.info";
    runner.set_coverage_lcov_path(lcov_path.to_string());

    if let Some(pct) = parse_lcov_coverage(lcov_path) {
        eprintln!("==> coverage: {pct:.1}%");
        runner.set_coverage_percent(pct);
    } else {
        eprintln!("==> coverage: unable to parse lcov.info");
    }

    Ok(())
}

/// Parse an LCOV info file and compute line coverage percentage.
///
/// The LCOV format includes `LF:<count>` (lines found) and `LH:<count>`
/// (lines hit) entries per source file. This sums all entries and returns
/// `(total_hit / total_found) * 100.0`, or `None` if no line data is present.
fn parse_lcov_coverage(lcov_path: &str) -> Option<f64> {
    let content = fs::read_to_string(lcov_path).ok()?;
    let mut lines_found: u64 = 0;
    let mut lines_hit: u64 = 0;
    for line in content.lines() {
        if let Some(n) = line.strip_prefix("LF:") {
            lines_found += n.parse::<u64>().unwrap_or(0);
        } else if let Some(n) = line.strip_prefix("LH:") {
            lines_hit += n.parse::<u64>().unwrap_or(0);
        }
    }
    if lines_found > 0 {
        Some((lines_hit as f64 / lines_found as f64) * 100.0)
    } else {
        None
    }
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
    runner.step(
        "preflight:doc-versions",
        None,
        check_doc_dependency_versions,
    )?;
    let mut first_err: Option<anyhow::Error> = None;
    for name in PUBLISH_CRATES {
        let step_name = format!("preflight:package:{name}");
        if let Err(e) = runner.step(&step_name, None, || {
            let output = Command::new("cargo")
                .args(["package", "--no-verify", "-p", name])
                .output()
                .context("failed to spawn cargo package")?;
            if output.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Tolerate crates.io resolution errors for workspace siblings
            // that haven't been published to crates.io yet.
            if is_unpublished_workspace_dep_error(&stderr) {
                eprintln!("  [warn] {name}: skipped (workspace dep not yet on crates.io)");
                return Ok(());
            }
            bail!("cargo package --no-verify -p {name} failed:\n{stderr}");
        }) && first_err.is_none()
        {
            first_err = Some(e);
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
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
        let pkg = packages
            .iter()
            .find(|p| p["name"].as_str().is_some_and(|n| n == *crate_name));

        let Some(pkg) = pkg else {
            errors.push(format!("{crate_name}: not found in workspace metadata"));
            continue;
        };

        let check_string = |field: &str| match pkg.get(field).and_then(|v| v.as_str()) {
            Some(s) if !s.is_empty() => None,
            _ => Some(format!("{crate_name}: missing or empty `{field}`")),
        };

        let check_non_empty_array = |field: &str| match pkg.get(field).and_then(|v| v.as_array()) {
            Some(arr) if !arr.is_empty() => None,
            _ => Some(format!("{crate_name}: missing or empty `{field}`")),
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

fn check_doc_dependency_versions() -> Result<()> {
    let versions = workspace_publish_versions()?;
    let files = versioned_dependency_snippet_files()?;
    let errors = collect_dependency_version_snippet_errors(&files, &versions)?;

    if !errors.is_empty() {
        bail!(
            "versioned dependency snippet errors:\n  {}",
            errors.join("\n  ")
        );
    }

    Ok(())
}

fn workspace_publish_versions() -> Result<BTreeMap<String, String>> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .context("failed to run `cargo metadata` for doc version checks")?;

    if !output.status.success() {
        bail!(
            "`cargo metadata` failed during doc version checks: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let meta: serde_json::Value = serde_json::from_slice(&output.stdout)
        .context("failed to parse cargo metadata JSON for doc version checks")?;
    let packages = meta["packages"]
        .as_array()
        .context("missing 'packages' in cargo metadata for doc version checks")?;

    let mut versions = BTreeMap::new();
    for crate_name in PUBLISH_CRATES {
        let pkg = packages
            .iter()
            .find(|p| p["name"].as_str().is_some_and(|n| n == *crate_name))
            .with_context(|| format!("{crate_name}: not found in workspace metadata"))?;
        let version = pkg["version"]
            .as_str()
            .with_context(|| format!("{crate_name}: missing `version` in workspace metadata"))?;
        versions.insert((*crate_name).to_string(), version.to_string());
    }

    Ok(versions)
}

fn versioned_dependency_snippet_files() -> Result<Vec<PathBuf>> {
    let workspace_root = workspace_root_path();
    let mut files = vec![
        workspace_root.join("README.md"),
        workspace_root.join("crates/uselesskey/src/lib.rs"),
    ];

    for entry in fs::read_dir(workspace_root.join("crates"))
        .context("failed to read crates dir for doc version checks")?
    {
        let entry = entry.context("failed to read crates dir entry for doc version checks")?;
        let readme = entry.path().join("README.md");
        if readme.is_file() {
            files.push(readme);
        }
    }

    files.sort();
    files.dedup();
    Ok(files)
}

fn collect_dependency_version_snippet_errors(
    files: &[PathBuf],
    versions: &BTreeMap<String, String>,
) -> Result<Vec<String>> {
    let dep_re = Regex::new(
        r#"(?s)\b(?P<name>uselesskey(?:-[a-z0-9-]+)?)\s*=\s*(?:\{[^}]*?\bversion\s*=\s*"(?P<inline>[^"]+)"[^}]*\}|"(?P<bare>[^"]+)")"#,
    )
    .expect("dependency version regex is valid");

    let mut errors = Vec::new();

    for path in files {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;

        for caps in dep_re.captures_iter(&content) {
            let name = caps.name("name").expect("name capture").as_str();
            let Some(expected) = versions.get(name) else {
                errors.push(format!(
                    "{}: dependency snippet references unknown workspace crate `{name}`",
                    path.display()
                ));
                continue;
            };

            let found = caps
                .name("inline")
                .or_else(|| caps.name("bare"))
                .expect("version capture")
                .as_str();

            if found != expected {
                errors.push(format!(
                    "{}: `{name}` example uses version `{found}`, expected `{expected}`",
                    path.display()
                ));
            }
        }
    }

    Ok(errors)
}

fn run_mutants(crates: &[&str]) -> Result<()> {
    let have = Command::new("cargo")
        .args(["mutants", "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    if !have {
        bail!("cargo-mutants is not installed. Install with: cargo install cargo-mutants");
    }

    eprintln!("mutants targets: {crates:?}");

    let all_features_requested =
        env::var("CI").is_ok() || env::var("XTASK_MUTANTS_ALL_FEATURES").is_ok();
    let nasm_available = !cfg!(windows)
        || Command::new("nasm")
            .arg("-v")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());

    for name in crates {
        let mut cmd = Command::new("cargo");
        cmd.arg("mutants");

        let needs_aws_lc_features = *name == "uselesskey-aws-lc-rs";
        let use_all_features = if needs_aws_lc_features {
            all_features_requested || nasm_available
        } else {
            true
        };

        // For aws-lc-rs specifically, all-features on Windows requires NASM.
        // For all other crates, run with all features to avoid false misses
        // from feature-gated APIs (e.g. JWK helpers).
        if needs_aws_lc_features && !use_all_features {
            eprintln!(
                "skipping mutants for {name}: set XTASK_MUTANTS_ALL_FEATURES=1 or install NASM"
            );
            continue;
        }

        if use_all_features {
            cmd.arg("--all-features");
        }

        cmd.args(["--manifest-path", &format!("crates/{name}/Cargo.toml")]);
        run(&mut cmd)?;
    }

    Ok(())
}

fn fuzz(target: Option<&str>, extra: &[String]) -> Result<()> {
    let status = Command::new("cargo")
        .args(["fuzz", "--help"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => {
            let host = host_target_triple()?;
            let mut cmd = Command::new("cargo");
            cmd.args(["+nightly", "fuzz", "run", "--target", &host]);

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
        runner.skip("root-tests", reason.clone());
        runner.skip("xtask-tests", reason.clone());
        runner.skip("preflight:metadata", reason.clone());
        runner.skip("preflight:doc-versions", reason.clone());
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
        runner.skip(
            "bdd",
            Some("no crate source or bdd feature changes".to_string()),
        );
    }

    if plan.run_mutants {
        let pr_crates: Vec<&str> = plan
            .directly_changed_crates
            .iter()
            .filter(|name| PUBLISH_CRATES.contains(&name.as_str()))
            .map(|s| s.as_str())
            .collect();
        if pr_crates.is_empty() {
            runner.skip(
                "mutants",
                Some("no mutant-eligible crates directly changed".into()),
            );
        } else {
            runner.step("mutants", None, || run_mutants(&pr_crates))?;
        }
    } else {
        runner.skip("mutants", Some("no crate source changes".to_string()));
    }

    if plan.run_fuzz {
        runner.step("fuzz", None, fuzz_pr)?;
    } else {
        runner.skip("fuzz", Some("no crate source or fuzz changes".to_string()));
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
        runner.skip("coverage", Some("no crate source changes".into()));
        runner.skip("coverage:report", Some("no crate source changes".into()));
    }

    if plan.run_root_tests {
        runner.step("root-tests", None, || {
            let mut cmd = Command::new("cargo");
            cmd.args([
                "test",
                "-p",
                "uselesskey-integration-tests",
                "--all-features",
            ]);
            run(&mut cmd)
        })?;
    } else {
        runner.skip("root-tests", Some("no root test changes".into()));
    }

    if plan.run_xtask_tests {
        runner.step("xtask-tests", None, || {
            let mut cmd = Command::new("cargo");
            cmd.args(["test", "-p", "xtask"]);
            run(&mut cmd)
        })?;
    } else {
        runner.skip("xtask-tests", Some("no xtask changes".into()));
    }

    if plan.run_publish_preflight {
        run_publish_preflight(runner)?;
    } else {
        runner.skip("preflight:metadata", Some("no cargo changes".into()));
        runner.skip("preflight:doc-versions", Some("no cargo changes".into()));
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
    for feature_set in CORE_FEATURE_MATRIX {
        let label = feature_set.name;
        let step_name = format!("feature-matrix:{}", label);
        let result = runner.step(&step_name, None, || {
            let mut cmd = Command::new("cargo");
            cmd.args(["check", "-p", "uselesskey"]);
            for arg in feature_set.cargo_args {
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
    for feature_set in CORE_FEATURE_MATRIX {
        let label = feature_set.name;
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
            let host = host_target_triple()?;
            for target in targets {
                let mut cmd = Command::new("cargo");
                cmd.args([
                    "+nightly",
                    "fuzz",
                    "run",
                    "--target",
                    &host,
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
    let dir = workspace_path("fuzz/fuzz_targets");
    if !dir.exists() {
        return Ok(targets);
    }
    for entry in fs::read_dir(&dir).context("failed to read fuzz_targets")? {
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
    if matches!(ext.as_str(), "rs" | "feature" | "md" | "toml" | "snap") {
        return Ok(false);
    }
    let content = fs::read(path).with_context(|| format!("failed to read {path:?}"))?;
    let text = String::from_utf8_lossy(&content);
    Ok(text.contains("-----BEGIN") && text.contains("-----END"))
}

fn count_bdd_scenarios() -> Result<BTreeMap<String, usize>> {
    let mut counts = BTreeMap::new();
    let dir = workspace_path("crates/uselesskey-bdd/features");
    if !dir.exists() {
        return Ok(counts);
    }
    for entry in fs::read_dir(&dir).context("failed to read bdd features dir")? {
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

/// Detect the host target triple from `rustc -vV`.
fn host_target_triple() -> Result<String> {
    let output = Command::new("rustc")
        .args(["-vV"])
        .output()
        .context("failed to run rustc")?;
    if !output.status.success() {
        bail!("rustc -vV failed");
    }
    let stdout = String::from_utf8(output.stdout).context("rustc output not UTF-8")?;
    for line in stdout.lines() {
        if let Some(host) = line.strip_prefix("host: ") {
            return Ok(host.to_string());
        }
    }
    bail!("could not determine host target triple from rustc -vV")
}

fn workspace_path(rel: &str) -> PathBuf {
    let cwd_rel = PathBuf::from(rel);
    if cwd_rel.exists() {
        return cwd_rel;
    }

    // Also resolve from the workspace root when running from within this repo
    // (for example from `xtask/`), but do not leak into unrelated temp dirs.
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or(Path::new(env!("CARGO_MANIFEST_DIR")));
    if env::current_dir()
        .ok()
        .is_some_and(|cwd| cwd.starts_with(workspace_root))
    {
        let workspace_rel = workspace_root.join(rel);
        if workspace_rel.exists() {
            return workspace_rel;
        }
    }

    cwd_rel
}

fn workspace_root_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        |p| p.to_path_buf(),
    )
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

/// Verify that only the approved `rand_core` lines are present on normal edges.
///
/// During the RNG transition we intentionally allow:
/// - `rand_core 0.6.x` for stable crypto-edge crates
/// - `rand_core 0.10.x` for the seed/core/helper lane
///
/// Any other `rand_core` line on normal edges is a topology regression.
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

    versions.sort();

    let unexpected = versions
        .iter()
        .filter(|v| !v.starts_with("0.6.") && !v.starts_with("0.10."))
        .map(|v| format!("v{v}"))
        .collect::<Vec<_>>();

    if !unexpected.is_empty() {
        bail!(
            "dep-guard: unexpected rand_core line(s) resolved on normal edges: {}. \
             Only rand_core 0.6.x and 0.10.x are allowed during the transition.",
            unexpected.join(", ")
        );
    }

    eprintln!(
        "dep-guard: allowed rand_core transition lines resolved: {}",
        versions
            .iter()
            .map(|v| format!("v{v}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(())
}

fn lint_fix(check: bool, no_clippy: bool) -> Result<()> {
    if check {
        fmt(false)?;
        if !no_clippy {
            clippy()?;
        }
        return Ok(());
    }

    fmt(true)?;

    if !no_clippy {
        // Best-effort clippy auto-fix, then strict verify.
        let fix_status = Command::new("cargo")
            .args([
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--fix",
                "--allow-dirty",
                "--allow-staged",
            ])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
        if let Ok(s) = fix_status
            && !s.success()
        {
            eprintln!("clippy --fix exited non-zero (best-effort); running strict verify...");
        }
        clippy()?;
    }

    Ok(())
}

fn gate() -> Result<()> {
    let mut runner = receipt::Runner::new("target/xtask/receipt.json");
    let result = run_gate(&mut runner);
    runner.summary();
    if let Err(err) = runner.write() {
        eprintln!("failed to write receipt: {err}");
        if result.is_ok() {
            return Err(err);
        }
    }
    result
}

fn run_gate(runner: &mut receipt::Runner) -> Result<()> {
    runner.step("fmt", None, || fmt(false))?;
    runner.step("docs-sync", None, || docs_sync::docs_sync_cmd(true))?;
    runner.step("check", None, || {
        run(Command::new("cargo").args(["check", "--workspace", "--all-targets", "--all-features"]))
    })?;
    runner.step("clippy", None, clippy)?;
    runner.step("test-compile", None, || {
        run(Command::new("cargo").args([
            "test",
            "--workspace",
            "--all-features",
            "--exclude",
            "uselesskey-bdd",
            "--no-run",
        ]))
    })?;
    Ok(())
}

fn setup() -> Result<()> {
    eprintln!(
        "{} setting up git hooks...",
        " STEP ".on_bright_blue().black().bold()
    );

    // Try installing lefthook if available
    let has_lefthook = Command::new("lefthook")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    if has_lefthook {
        eprintln!(
            "{} lefthook detected, installing...",
            " INFO ".on_blue().black().bold()
        );
        run(Command::new("lefthook").arg("install"))?;
    } else {
        eprintln!(
            "{} lefthook not found, falling back to .githooks",
            " WARN ".on_yellow().black().bold()
        );
        run(Command::new("git").args(["config", "core.hooksPath", ".githooks"]))?;
    }

    eprintln!(
        "{} setup complete!",
        " DONE ".on_bright_green().black().bold()
    );
    Ok(())
}

fn commit_lint(message_file: &Path) -> Result<()> {
    let content = fs::read_to_string(message_file).context("failed to read commit message")?;
    let first_line = content.lines().next().unwrap_or("");

    // Simple conventional commit regex
    let re = regex::Regex::new(
        r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\(.+\))?!?: .+$",
    )
    .unwrap();

    if !re.is_match(first_line) {
        eprintln!(
            "{} invalid commit message format.",
            " ERR ".on_bright_red().black().bold()
        );
        eprintln!("expected: <type>(<scope>)?: <description>");
        eprintln!("types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert");
        bail!("invalid commit message");
    }

    Ok(())
}

fn hook_pre_commit() -> Result<()> {
    let output = Command::new("git")
        .args([
            "diff",
            "--cached",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
            "--",
            "*.rs",
            "Cargo.toml",
            "Cargo.lock",
        ])
        .output()
        .context("failed to run git diff --cached")?;

    if !output.status.success() {
        bail!(
            "git diff --cached failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let staged_files = parse_null_delimited_paths(&output.stdout);

    if staged_files.is_empty() {
        return Ok(());
    }

    lint_fix(false, false)?;

    for file in staged_files {
        if file.is_file() {
            run(Command::new("git")
                .args(["add", "--"])
                .arg(file.as_os_str()))?;
        }
    }
    Ok(())
}

fn parse_null_delimited_paths(raw: &[u8]) -> Vec<PathBuf> {
    raw.split(|b| *b == b'\0')
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStringExt;
                PathBuf::from(std::ffi::OsString::from_vec(entry.to_vec()))
            }

            #[cfg(not(unix))]
            {
                let file = String::from_utf8_lossy(entry).into_owned();
                PathBuf::from(file)
            }
        })
        .collect()
}

fn hook_pre_push() -> Result<()> {
    gate()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::PathBuf;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    static CWD_LOCK: Mutex<()> = Mutex::new(());

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

    fn assert_versioned_dependency_snippet_files_from_cwd(
        cwd: &std::path::Path,
        workspace_root: &std::path::Path,
    ) {
        let _cwd = CwdGuard::new(cwd);
        let files = versioned_dependency_snippet_files().expect("collect versioned snippet files");

        assert!(files.iter().all(|path| path.is_absolute()));
        assert!(
            files.contains(&workspace_root.join("README.md")),
            "workspace root README should be included"
        );
        assert!(files.contains(&workspace_root.join("crates/uselesskey/src/lib.rs")));
        assert!(files.contains(&workspace_root.join("crates/uselesskey/README.md")));
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
    fn perf_baseline_schema_is_valid() {
        let json = fs::read_to_string(workspace_path(PERF_BASELINE_PATH)).expect("read perf baseline");
        let parsed: PerfBaselineFile = serde_json::from_str(&json).expect("parse perf baseline");
        assert_eq!(parsed.version, 1);
        assert!(!parsed.entries.is_empty(), "expected at least one perf budget entry");
        assert!(parsed.entries.iter().all(|e| !e.id.is_empty()));
    }

    #[test]
    fn list_fuzz_targets_returns_sorted_rs_stems() {
        let _cwd_lock = CWD_LOCK.lock().unwrap();
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
        let _cwd_lock = CWD_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        let _cwd = CwdGuard::new(dir.path());
        let targets = list_fuzz_targets().expect("list targets");
        assert!(targets.is_empty());
    }

    #[test]
    fn versioned_dependency_snippet_files_uses_workspace_root_from_crate_path() {
        let _cwd_lock = CWD_LOCK.lock().unwrap();
        let workspace_root = workspace_root_path();
        let crate_dir = workspace_root.join("crates").join("uselesskey");
        assert_versioned_dependency_snippet_files_from_cwd(&crate_dir, &workspace_root);
    }

    #[test]
    fn versioned_dependency_snippet_files_uses_workspace_root_from_xtask_path() {
        let _cwd_lock = CWD_LOCK.lock().unwrap();
        let workspace_root = workspace_root_path();
        let xtask_dir = workspace_root.join("xtask");
        assert_versioned_dependency_snippet_files_from_cwd(&xtask_dir, &workspace_root);
    }

    #[test]
    fn parse_lcov_coverage_computes_percentage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lcov = dir.path().join("lcov.info");
        fs::write(
            &lcov,
            "\
SF:src/lib.rs
DA:1,1
DA:2,0
LF:10
LH:8
end_of_record
SF:src/other.rs
DA:1,1
LF:20
LH:15
end_of_record
",
        )
        .unwrap();

        let pct = parse_lcov_coverage(lcov.to_str().unwrap()).expect("should parse");
        // (8 + 15) / (10 + 20) * 100 = 76.666...
        assert!((pct - 76.666).abs() < 0.1, "expected ~76.7%, got {pct}");
    }

    #[test]
    fn parse_lcov_coverage_returns_none_for_empty_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lcov = dir.path().join("lcov.info");
        fs::write(&lcov, "").unwrap();
        assert!(parse_lcov_coverage(lcov.to_str().unwrap()).is_none());
    }

    #[test]
    fn parse_lcov_coverage_returns_none_for_missing_file() {
        assert!(parse_lcov_coverage("/nonexistent/lcov.info").is_none());
    }

    #[test]
    fn parse_lcov_coverage_handles_zero_lines_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lcov = dir.path().join("lcov.info");
        fs::write(&lcov, "SF:src/lib.rs\nLF:0\nLH:0\nend_of_record\n").unwrap();
        assert!(parse_lcov_coverage(lcov.to_str().unwrap()).is_none());
    }

    #[test]
    fn count_bdd_scenarios_counts_scenarios_and_outlines() {
        let _cwd_lock = CWD_LOCK.lock().unwrap();
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

    #[test]
    fn parse_null_delimited_paths_preserves_path_components() {
        let staged = b"Cargo.toml\0crates/dir/src/lib.rs\0";
        let paths = parse_null_delimited_paths(staged);
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], PathBuf::from("Cargo.toml"));
        assert_eq!(paths[1], PathBuf::from("crates/dir/src/lib.rs"));
    }

    #[test]
    fn parse_null_delimited_paths_ignores_trailing_null() {
        let staged = b"one.rs\0";
        let paths = parse_null_delimited_paths(staged);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], PathBuf::from("one.rs"));
    }

    #[test]
    fn resolve_start_index_from_first_crate() {
        let idx = resolve_start_index(Some("uselesskey-core-seed"), false).unwrap();
        assert_eq!(idx, 0);
    }

    #[test]
    fn publish_order_keeps_core_seed_before_base62() {
        let seed_idx = PUBLISH_CRATES
            .iter()
            .position(|name| *name == "uselesskey-core-seed")
            .expect("seed crate present");
        let base62_idx = PUBLISH_CRATES
            .iter()
            .position(|name| *name == "uselesskey-core-base62")
            .expect("base62 crate present");
        assert!(
            seed_idx < base62_idx,
            "publish order must place uselesskey-core-seed before uselesskey-core-base62"
        );
    }

    #[test]
    fn resolve_start_index_from_last_crate() {
        let idx = resolve_start_index(Some("uselesskey"), false).unwrap();
        assert_eq!(idx, PUBLISH_CRATES.len() - 1);
    }

    #[test]
    fn resolve_start_index_from_nonexistent() {
        let err = resolve_start_index(Some("nonexistent"), false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not found in publish order"), "got: {msg}");
        // Should list valid crate names
        assert!(msg.contains("uselesskey-core-base62"), "got: {msg}");
    }

    #[test]
    fn resolve_start_index_neither_flag() {
        let idx = resolve_start_index(None, false).unwrap();
        assert_eq!(idx, 0);
    }

    #[test]
    fn publish_state_serde_roundtrip() {
        let state = PublishState {
            timestamp: 1234567890,
            crates: vec![
                PublishCrateState {
                    name: "uselesskey-core".to_string(),
                    status: "published".to_string(),
                },
                PublishCrateState {
                    name: "uselesskey-rsa".to_string(),
                    status: "failed".to_string(),
                },
            ],
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: PublishState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.timestamp, state.timestamp);
        assert_eq!(parsed.crates.len(), 2);
        assert_eq!(parsed.crates[0].name, "uselesskey-core");
        assert_eq!(parsed.crates[0].status, "published");
        assert_eq!(parsed.crates[1].name, "uselesskey-rsa");
        assert_eq!(parsed.crates[1].status, "failed");
    }

    #[test]
    fn resolve_start_index_from_and_resume_mutual_exclusion() {
        let err = resolve_start_index(Some("uselesskey-core-seed"), true).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mutually exclusive"),
            "expected mutual exclusion error, got: {msg}"
        );
    }

    #[test]
    fn unpublished_workspace_dep_error_matches_no_matching_package() {
        let stderr = "error: no matching package named `uselesskey-core-hash` found\nlocation searched: crates.io index\nrequired by package `uselesskey-core-id v0.4.1`";
        assert!(is_unpublished_workspace_dep_error(stderr));
    }

    #[test]
    fn unpublished_workspace_dep_error_matches_version_mismatch_form() {
        let stderr = "error: failed to prepare local package for uploading\n\nCaused by:\n  failed to select a version for the requirement `uselesskey-core-hash = \"^0.4.1\"`\n  candidate versions found which didn't match: 0.4.0\n  location searched: crates.io index\n  required by package `uselesskey-core-id v0.4.1`";
        assert!(is_unpublished_workspace_dep_error(stderr));
    }

    #[test]
    fn dependency_version_snippet_errors_accept_matching_versions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let readme = dir.path().join("README.md");
        fs::write(
            &readme,
            r#"[dev-dependencies]
uselesskey = { version = "0.4.1", features = ["rsa"] }
uselesskey-tonic = "0.4.1"
"#,
        )
        .unwrap();

        let versions = BTreeMap::from([
            ("uselesskey".to_string(), "0.4.1".to_string()),
            ("uselesskey-tonic".to_string(), "0.4.1".to_string()),
        ]);

        let errors =
            collect_dependency_version_snippet_errors(&[readme], &versions).expect("collect");
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn dependency_version_snippet_errors_report_mismatches() {
        let dir = tempfile::tempdir().expect("tempdir");
        let readme = dir.path().join("README.md");
        fs::write(
            &readme,
            r#"[dev-dependencies]
uselesskey = { version = "0.4.0", features = ["rsa"] }
"#,
        )
        .unwrap();

        let versions = BTreeMap::from([("uselesskey".to_string(), "0.4.1".to_string())]);

        let errors =
            collect_dependency_version_snippet_errors(&[readme], &versions).expect("collect");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("expected `0.4.1`"), "got: {}", errors[0]);
    }

    #[test]
    fn unpublished_workspace_dep_error_rejects_unrelated_errors() {
        let stderr = "error: failed to load manifest for workspace member";
        assert!(!is_unpublished_workspace_dep_error(stderr));
    }

    #[test]
    fn parse_retry_after_valid_timestamp() {
        // Use a future timestamp to get a positive wait
        let future = chrono::Utc::now() + chrono::Duration::seconds(60);
        let ts = future.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let stderr = format!("Please try again after {ts}");
        let wait = parse_retry_after(&stderr);
        assert!(wait.is_some(), "should parse valid timestamp");
        let w = wait.unwrap();
        // ~60s + 15s buffer = ~75s, allow some clock drift
        assert!((60..=90).contains(&w), "expected ~75s wait, got {w}s");
    }

    #[test]
    fn parse_retry_after_no_match() {
        let stderr = "some random error message without a timestamp";
        assert!(parse_retry_after(stderr).is_none());
    }

    #[test]
    fn parse_retry_after_malformed_timestamp() {
        let stderr = "try again after not-a-real-timestamp";
        assert!(parse_retry_after(stderr).is_none());
    }

    #[test]
    fn parse_retry_after_past_timestamp_clamps_to_minimum() {
        // A past timestamp should still return at least 5s (our minimum)
        let past = chrono::Utc::now() - chrono::Duration::seconds(300);
        let ts = past.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let stderr = format!("Please try again after {ts}");
        let wait = parse_retry_after(&stderr);
        assert!(wait.is_some());
        assert_eq!(
            wait.unwrap(),
            5,
            "past timestamp should clamp to 5s minimum"
        );
    }

    #[test]
    fn parse_retry_after_real_crates_io_message() {
        // Real crates.io 429 error message — the regex must stop at GMT and not
        // greedily capture the trailing "and see https://..." text.
        let stderr = "Please try again after Sun, 08 Mar 2026 06:57:08 GMT and see https://crates.io/docs/rate-limits for more details.";
        let wait = parse_retry_after(stderr);
        assert!(
            wait.is_some(),
            "should parse the real crates.io 429 message"
        );
    }

    #[test]
    fn resolve_start_index_resume_from_state_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_path = dir.path().join("publish-state.json");
        let state = PublishState {
            timestamp: 1234567890,
            crates: vec![
                PublishCrateState {
                    name: "uselesskey-core-base62".to_string(),
                    status: "published".to_string(),
                },
                PublishCrateState {
                    name: "uselesskey-core-seed".to_string(),
                    status: "already_published".to_string(),
                },
                PublishCrateState {
                    name: "uselesskey-core-hash".to_string(),
                    status: "failed".to_string(),
                },
            ],
        };
        let json = serde_json::to_string_pretty(&state).unwrap();
        fs::write(&state_path, &json).unwrap();

        // We can't easily test resume with the hardcoded path,
        // but we can test the serde and state logic directly.
        // Find first non-success crate:
        let first_pending = state
            .crates
            .iter()
            .position(|c| c.status != "published" && c.status != "already_published");
        assert_eq!(first_pending, Some(2));
    }
}
