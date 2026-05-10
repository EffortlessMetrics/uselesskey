use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;
use regex::Regex;
use uselesskey_feature_grid::{BDD_FEATURE_MATRIX, CORE_FEATURE_MATRIX};

mod audit_surface;
mod docs_sync;
mod economics;
mod plan;
mod policy;
mod pr_bundles;
mod public_surface;
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
    /// Measure dependency economics for the main fixture lanes.
    Economics,
    /// Inspect dependency surface for common lanes and adapter islands.
    AuditSurface,
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
    NoBlob {
        /// Subcommand: scan (default) or migrate (show replacement recipe).
        #[command(subcommand)]
        subcmd: Option<NoBlobCmd>,
    },
    /// Synchronize docs from metadata source.
    DocsSync {
        /// Verify generated output instead of writing files.
        #[arg(long)]
        check: bool,
    },
    /// Check public-surface metadata and package topology guardrails.
    PublicSurface,
    /// Compile example list from metadata and optionally run curated examples.
    ExamplesSmoke {
        /// Run curated smoke examples after compile checks.
        #[arg(long)]
        run: bool,
    },
    /// Run publish dry-runs for crates in dependency order.
    PublishCheck,
    /// Run PR-scoped tests based on git diff.
    Pr {
        /// Include the targeted mutation step in the PR gate.
        #[arg(long)]
        with_mutants: bool,
    },
    /// Run advisory ripr PR exposure evidence (requires external `ripr`).
    RiprPr,
    /// Run PR-scoped mutation testing explicitly.
    MutantsPr {
        /// Run mutation testing for mutation-eligible crates changed against the PR base.
        #[arg(long)]
        changed: bool,
        /// Run mutation testing for an explicit crate. Can be supplied multiple times.
        #[arg(long = "crate", value_name = "CRATE")]
        crates: Vec<String>,
        /// Run mutation testing for all publish crates.
        #[arg(long)]
        all: bool,
        /// Document that the selected owner crate(s) should receive full-owner mutation proof.
        #[arg(long)]
        full_owner: bool,
    },
    /// Run scheduled/manual mutation evidence scopes.
    MutantsNightly {
        /// Mutation evidence scope.
        #[arg(long, value_enum, default_value_t = MutationNightlyScope::Public)]
        scope: MutationNightlyScope,
        /// Crate to test when `--scope crate` is selected.
        #[arg(long = "crate", value_name = "CRATE")]
        crate_name: Option<String>,
        /// Write planned artifacts without running cargo-mutants.
        #[arg(long)]
        dry_run: bool,
    },
    /// Report changed-path evidence owners and targeted mutation routing.
    ImpactedEvidence {
        /// Base ref to compare against. Defaults to XTASK_BASE_REF, GITHUB_BASE_REF, or origin/main.
        #[arg(long)]
        base: Option<String>,
    },
    /// Run or plan release-candidate evidence gates and write release evidence artifacts.
    ReleaseEvidence {
        /// Release version being proven, for example `0.7.0`.
        #[arg(long)]
        version: String,
        /// Output directory for release evidence artifacts.
        #[arg(long, default_value = "target/release-evidence")]
        out: PathBuf,
        /// Write planned artifacts without running the release gates.
        #[arg(long)]
        dry_run: bool,
        /// Also write a release-manager summary page.
        #[arg(long)]
        summary: bool,
    },
    /// Generate, verify, inspect, and export a bundle proof artifact for release evidence.
    BundleProof {
        /// Bundle profile to prove. Supports `scanner-safe` and `oidc`.
        #[arg(long, default_value = "scanner-safe")]
        profile: String,
        /// Output directory for proof artifacts.
        #[arg(long)]
        out: Option<PathBuf>,
    },
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
    PublishPreflight {
        /// Allow local uncommitted changes while validating packageability.
        #[arg(long)]
        allow_dirty: bool,
    },
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
    /// Bootstrap Claude agent-swarm commands using native Rust automation.
    AgentSwarmSetup {
        /// Command written to the PostToolUse hook in .claude/settings.json.
        #[arg(long)]
        post_edit_check: Option<String>,
    },
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
    /// Check the semantic no-panic allowlist (panic-family ledger).
    CheckNoPanicFamily,
    /// Emit a proposed no-panic allowlist under target/policy-proposed/.
    NoPanic {
        #[command(subcommand)]
        action: NoPanicCmd,
    },
    /// Check the non-Rust file allowlist.
    CheckFilePolicy,
    /// Check the lint-policy invariants (MSRV, [lints] inheritance, debt expiry).
    CheckLintPolicy,
    /// Aggregate policy report across no-panic, file-policy, and lint-policy.
    PolicyReport,
}

#[derive(Subcommand)]
enum NoBlobCmd {
    /// Scan for secret-shaped blobs and fail if any found (default).
    Scan,
    /// Scan and emit a migration recipe for each detected blob (read-only).
    Migrate,
}

#[derive(Subcommand)]
enum NoPanicCmd {
    /// Generate a candidate allowlist file under target/policy-proposed/.
    Propose,
    /// Regenerate `policy/no-panic-baseline.toml` from current findings.
    Baseline {
        /// Replace the baseline with all current findings.
        ///
        /// Without this flag, regeneration only drops disappeared baseline
        /// entries and refuses to absorb new panic-family debt.
        #[arg(long)]
        reset: bool,
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

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
enum MutationNightlyScope {
    Public,
    Adapters,
    All,
    Crate,
}

impl MutationNightlyScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Adapters => "adapters",
            Self::All => "all",
            Self::Crate => "crate",
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Perf { compare } => perf(compare),
        Cmd::Economics => economics::economics_cmd(),
        Cmd::AuditSurface => audit_surface::audit_surface_cmd(),
        Cmd::Fmt { fix } => fmt(fix),
        Cmd::Clippy => clippy(),
        Cmd::Test => test(),
        Cmd::Nextest => nextest(),
        Cmd::Deny => deny(),
        Cmd::Typos { fix } => typos(fix),
        Cmd::Ci => ci(),
        Cmd::FeatureMatrix => feature_matrix_cmd(),
        Cmd::NoBlob { subcmd } => match subcmd.as_ref().unwrap_or(&NoBlobCmd::Scan) {
            NoBlobCmd::Scan => no_blob_gate(),
            NoBlobCmd::Migrate => no_blob_migrate(),
        },
        Cmd::DocsSync { check } => docs_sync::docs_sync_cmd(check),
        Cmd::PublicSurface => public_surface::public_surface_cmd(PUBLISH_CRATES),
        Cmd::ExamplesSmoke { run } => docs_sync::examples_smoke_cmd(run),
        Cmd::PublishCheck => publish_check(),
        Cmd::Pr { with_mutants } => pr(with_mutants),
        Cmd::RiprPr => ripr_pr(),
        Cmd::MutantsPr {
            changed,
            crates,
            all,
            full_owner,
        } => mutants_pr(changed, crates, all, full_owner),
        Cmd::MutantsNightly {
            scope,
            crate_name,
            dry_run,
        } => mutants_nightly(scope, crate_name, dry_run),
        Cmd::ImpactedEvidence { base } => impacted_evidence(base),
        Cmd::ReleaseEvidence {
            version,
            out,
            dry_run,
            summary,
        } => release_evidence(&version, &out, dry_run, summary),
        Cmd::BundleProof { profile, out } => bundle_proof(&profile, out.as_deref()),
        Cmd::DepGuard => dep_guard(),
        Cmd::Bdd => bdd(),
        Cmd::BddMatrix => bdd_matrix(),
        Cmd::Coverage => coverage(),
        Cmd::PublishPreflight { allow_dirty } => publish_preflight(allow_dirty),
        Cmd::Publish { from, resume } => publish(from, resume),
        Cmd::Mutants => run_mutants(PUBLISH_CRATES),
        Cmd::Fuzz { target, args } => fuzz(target.as_deref(), &args),
        Cmd::LintFix { check, no_clippy } => lint_fix(check, no_clippy),
        Cmd::Gate { check: _ } => gate(),
        Cmd::Setup => setup(),
        Cmd::AgentSwarmSetup { post_edit_check } => agent_swarm_setup(post_edit_check),
        Cmd::CommitLint { message_file } => commit_lint(&message_file),
        Cmd::Hook { hook } => match hook {
            HookCmd::PreCommit => hook_pre_commit(),
            HookCmd::PrePush => hook_pre_push(),
        },
        Cmd::CheckNoPanicFamily => policy::check_no_panic_family(),
        Cmd::NoPanic { action } => match action {
            NoPanicCmd::Propose => policy::no_panic_propose(),
            NoPanicCmd::Baseline { reset } => policy::no_panic_baseline(reset),
        },
        Cmd::CheckFilePolicy => policy::check_file_policy(),
        Cmd::CheckLintPolicy => policy::check_lint_policy(),
        Cmd::PolicyReport => policy::policy_report(),
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
        "--no-default-features",
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
    if let Ok(sha) = git_head_sha() {
        runner.set_git_sha(sha);
    }
    runner.set_crate_set("full".into());
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
    runner.step("public-surface", None, || {
        public_surface::public_surface_cmd(PUBLISH_CRATES)
    })?;
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

    run_publish_preflight(runner, false)?;

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
    "uselesskey-core-hash",
    "uselesskey-core-hmac-spec",
    "uselesskey-core-id",
    "uselesskey-core-cache",
    "uselesskey-core-factory",
    "uselesskey-jwk",
    // JWK compatibility shims
    "uselesskey-core-kid",
    // Negative fixture crates
    "uselesskey-core-negative-der",
    "uselesskey-core-negative-pem",
    "uselesskey-core-negative",
    // Sinks and shapes
    "uselesskey-core-sink",
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
    "uselesskey-entropy",
    "uselesskey-rsa",
    "uselesskey-ecdsa",
    "uselesskey-ed25519",
    "uselesskey-hmac",
    "uselesskey-token",
    // Token compatibility shims
    "uselesskey-token-spec",
    "uselesskey-core-base62",
    "uselesskey-core-token-shape",
    "uselesskey-core-token",
    "uselesskey-webhook",
    "uselesskey-pkcs11-mock",
    "uselesskey-webauthn",
    "uselesskey-ssh",
    "uselesskey-pgp",
    "uselesskey-x509",
    "uselesskey-test-server",
    "uselesskey-axum",
    "uselesskey-cli",
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
    "uselesskey-core-hash",
    "uselesskey-core-hmac-spec",
    "uselesskey-core-id",
    "uselesskey-core-cache",
    "uselesskey-core-factory",
    "uselesskey-jwk",
    "uselesskey-core-kid",
    "uselesskey-core-negative-der",
    "uselesskey-core-negative-pem",
    "uselesskey-core-negative",
    "uselesskey-core-sink",
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
    "uselesskey-hmac",
    "uselesskey-token",
    "uselesskey-token-spec",
    "uselesskey-core-base62",
    "uselesskey-core-token-shape",
    "uselesskey-core-token",
];

const NIGHTLY_PUBLIC_MUTATION_CRATES: &[&str] = &[
    "uselesskey-core",
    "uselesskey-jwk",
    "uselesskey-token",
    "uselesskey-x509",
    "uselesskey-rsa",
    "uselesskey-ecdsa",
    "uselesskey-ed25519",
    "uselesskey-hmac",
    "uselesskey-cli",
];

const NIGHTLY_ADAPTER_MUTATION_CRATES: &[&str] = &[
    "uselesskey-jsonwebtoken",
    "uselesskey-rustls",
    "uselesskey-tonic",
    "uselesskey-axum",
    "uselesskey-ring",
    "uselesskey-rustcrypto",
    "uselesskey-aws-lc-rs",
];

const MUTATION_EVIDENCE_CLAIM_BOUNDARY: &[&str] = &[
    "mutation testing is scoped by lane and crate set",
    "mutation testing does not prove cryptographic correctness",
    "mutation testing does not replace deterministic fixture regression tests",
];

const MUTATION_SURVIVOR_LEDGER_PATH: &str = "policy/mutation-survivors.toml";
const MUTATION_SURVIVOR_CLASSIFICATIONS: &[&str] = &["equivalent", "accepted-risk", "pending-test"];

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
    #[allow(dead_code, reason = "schema field surfaced in baseline JSON only")]
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
    let latest_json = fs::read_to_string(PERF_LATEST_PATH)
        .with_context(|| format!("failed to read {PERF_LATEST_PATH}"))?;

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
            bail!(
                "latest perf report missing required benchmark id: {}",
                budget.id
            );
        };
        let regression_pct = ((measured.median_ns as f64 - budget.baseline_median_ns as f64)
            / budget.baseline_median_ns as f64)
            * 100.0;
        let status = if regression_pct > budget.max_regression_pct {
            if budget.enforce_in_ci { "FAIL" } else { "WARN" }
        } else {
            "OK"
        };
        eprintln!(
            "[perf:{status}] {:32} baseline={}ns latest={}ns regression={:+.2}% threshold={:.2}%",
            budget.id,
            budget.baseline_median_ns,
            measured.median_ns,
            regression_pct,
            budget.max_regression_pct
        );
        if status == "FAIL" {
            violations.push(format!(
                "{} regressed by {:.2}% (threshold {:.2}%)",
                budget.id, regression_pct, budget.max_regression_pct
            ));
        }
    }

    if !violations.is_empty() {
        bail!(
            "performance budget check failed:\n{}",
            violations.join("\n")
        );
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

fn publish_preflight(allow_dirty: bool) -> Result<()> {
    let mut runner = receipt::Runner::new("target/xtask/receipt.json");
    let result = run_publish_preflight(&mut runner, allow_dirty);
    runner.summary();
    if let Err(err) = runner.write() {
        eprintln!("failed to write receipt: {err}");
        if result.is_ok() {
            return Err(err);
        }
    }
    result
}

fn run_publish_preflight(runner: &mut receipt::Runner, allow_dirty: bool) -> Result<()> {
    runner.step("preflight:metadata", None, check_crate_metadata)?;
    runner.step(
        "preflight:doc-versions",
        None,
        check_doc_dependency_versions,
    )?;
    runner.step("preflight:public-surface", None, || {
        public_surface::public_surface_cmd(PUBLISH_CRATES)
    })?;
    let mut first_err: Option<anyhow::Error> = None;
    for name in PUBLISH_CRATES {
        let step_name = format!("preflight:package:{name}");
        if let Err(e) = runner.step(&step_name, None, || {
            let mut cmd = Command::new("cargo");
            cmd.args(["package", "--no-verify", "-p", name]);
            if allow_dirty {
                cmd.arg("--allow-dirty");
            }
            let output = cmd.output().context("failed to spawn cargo package")?;
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
    ensure_cargo_mutants_installed()?;

    eprintln!("mutants targets: {crates:?}");

    let tool_env = MutationToolEnv::detect();

    for name in crates {
        let Some(mut cmd) = mutation_command_for_crate(name, None, &tool_env)? else {
            continue;
        };
        run(&mut cmd)?;
    }

    Ok(())
}

struct MutationToolEnv {
    all_features_requested: bool,
    nasm_available: bool,
}

impl MutationToolEnv {
    fn detect() -> Self {
        Self {
            all_features_requested: env::var("CI").is_ok()
                || env::var("XTASK_MUTANTS_ALL_FEATURES").is_ok(),
            nasm_available: !cfg!(windows)
                || Command::new("nasm")
                    .arg("-v")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success()),
        }
    }
}

fn ensure_cargo_mutants_installed() -> Result<()> {
    let have = Command::new("cargo")
        .args(["mutants", "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    if !have {
        bail!("cargo-mutants is not installed. Install with: cargo install cargo-mutants");
    }

    Ok(())
}

fn mutation_command_for_crate(
    name: &str,
    output_dir: Option<&Path>,
    tool_env: &MutationToolEnv,
) -> Result<Option<Command>> {
    let mut cmd = Command::new("cargo");
    cmd.arg("mutants");

    let needs_aws_lc_features = name == "uselesskey-aws-lc-rs";
    let use_all_features = if needs_aws_lc_features {
        tool_env.all_features_requested || tool_env.nasm_available
    } else {
        true
    };

    // For aws-lc-rs specifically, all-features on Windows requires NASM.
    // For all other crates, run with all features to avoid false misses from
    // feature-gated APIs (e.g. JWK helpers).
    if needs_aws_lc_features && !use_all_features {
        eprintln!("skipping mutants for {name}: set XTASK_MUTANTS_ALL_FEATURES=1 or install NASM");
        return Ok(None);
    }

    if use_all_features {
        cmd.arg("--all-features");
    }

    if name == "uselesskey-cli" {
        // The CLI crate carries a layer of orchestration and export plumbing
        // that is already covered by integration tests and receipt checks, but
        // cargo-mutants generates a large amount of low-signal mutations in
        // those boundary helpers. Keep mutation testing focused on the
        // fixture semantics rather than path/format glue.
        for exclude_re in [
            "fallback_label",
            "normalize_pem_label",
            "normalize_ssh_comment",
            "fixture_const_name",
            "preferred_bundle_format",
            "generate_artifact",
            "artifact_bytes",
            "write_artifact_to_path",
            "read_input",
            "format_extension",
            "file_name_string",
        ] {
            cmd.args(["--exclude-re", exclude_re]);
        }
    }

    if let Some(output_dir) = output_dir {
        cmd.args(["--output", &output_dir.display().to_string()]);
    }

    cmd.args(["--manifest-path", &format!("crates/{name}/Cargo.toml")]);
    Ok(Some(cmd))
}

#[derive(Debug, serde::Serialize)]
struct MutationNightlySummary {
    schema_version: u32,
    lane: &'static str,
    scope: MutationNightlyScope,
    dry_run: bool,
    crates: Vec<String>,
    survivor_ledger: MutationSurvivorLedgerSummary,
    claim_boundary: Vec<&'static str>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct MutationEvidenceReceipt {
    schema_version: u32,
    lane: &'static str,
    scope: MutationNightlyScope,
    dry_run: bool,
    crate_results: Vec<MutationEvidenceCrateResult>,
    survivor_ledger: MutationSurvivorLedgerSummary,
    claim_boundary: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct MutationEvidenceCrateResult {
    #[serde(rename = "crate")]
    crate_name: String,
    status: String,
    mutants_found: usize,
    caught: usize,
    survived: usize,
    unviable: usize,
    timeouts: usize,
    other: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcomes_path: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct MutationSurvivorLedger {
    schema_version: Option<String>,
    #[serde(default)]
    survivor: Vec<MutationSurvivorEntry>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct MutationSurvivorEntry {
    #[serde(rename = "crate")]
    crate_name: String,
    function: String,
    classification: String,
    owner: String,
    reason: String,
    expires: String,
    #[serde(default)]
    issue: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct MutationSurvivorLedgerSummary {
    path: String,
    known_survivors: usize,
    expired_classifications: usize,
    pending_tests: usize,
    accepted_risks: usize,
    equivalent_mutants: usize,
    unviable_mutants: usize,
}

#[derive(Debug, serde::Serialize)]
struct MutationSurvivorLedgerReport {
    summary: MutationSurvivorLedgerSummary,
    known_survivors: Vec<MutationSurvivorEntry>,
    expired_classifications: Vec<MutationSurvivorEntry>,
    classification_counts: BTreeMap<String, usize>,
    notes: Vec<&'static str>,
}

fn mutants_nightly(
    scope: MutationNightlyScope,
    crate_name: Option<String>,
    dry_run: bool,
) -> Result<()> {
    let crates = mutation_nightly_crates(scope, crate_name.as_deref())?;
    let survivor_report = mutation_survivor_report(
        Path::new(MUTATION_SURVIVOR_LEDGER_PATH),
        chrono::Utc::now().date_naive(),
    )?;
    let planned_results = planned_mutation_results(&crates);
    write_mutation_nightly_artifacts(scope, dry_run, &crates, &survivor_report, &planned_results)?;

    println!(
        "mutants-nightly: scope={}, crates={}, dry_run={dry_run}",
        scope.as_str(),
        crates.join(",")
    );

    if dry_run {
        return Ok(());
    }

    let crate_refs = crates.iter().map(String::as_str).collect::<Vec<_>>();
    let mutation_run = run_mutants_with_outputs(&crate_refs, Path::new("target/mutation/runs"))?;
    write_mutation_evidence_receipt(
        Path::new("target/mutation"),
        scope,
        false,
        &mutation_run.crate_results,
        &survivor_report,
    )?;
    if !mutation_run.failed_crates.is_empty() {
        bail!(
            "mutation evidence failed for crates: {}",
            mutation_run.failed_crates.join(", ")
        );
    }

    Ok(())
}

fn mutation_nightly_crates(
    scope: MutationNightlyScope,
    crate_name: Option<&str>,
) -> Result<Vec<String>> {
    let crates = match scope {
        MutationNightlyScope::Public => NIGHTLY_PUBLIC_MUTATION_CRATES
            .iter()
            .map(|name| (*name).to_string())
            .collect(),
        MutationNightlyScope::Adapters => NIGHTLY_ADAPTER_MUTATION_CRATES
            .iter()
            .map(|name| (*name).to_string())
            .collect(),
        MutationNightlyScope::All => PUBLISH_CRATES
            .iter()
            .map(|name| (*name).to_string())
            .collect(),
        MutationNightlyScope::Crate => {
            let Some(name) = crate_name.filter(|name| !name.trim().is_empty()) else {
                bail!("--scope crate requires --crate <CRATE>");
            };
            if !PUBLISH_CRATES.contains(&name) {
                bail!("unknown publish crate for mutation scope: {name}");
            }
            vec![name.to_string()]
        }
    };

    Ok(crates)
}

fn write_mutation_nightly_artifacts(
    scope: MutationNightlyScope,
    dry_run: bool,
    crates: &[String],
    survivor_report: &MutationSurvivorLedgerReport,
    crate_results: &[MutationEvidenceCrateResult],
) -> Result<()> {
    let out_dir = Path::new("target/mutation");
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;

    let summary = MutationNightlySummary {
        schema_version: 1,
        lane: "mutation-nightly",
        scope,
        dry_run,
        crates: crates.to_vec(),
        survivor_ledger: survivor_report.summary.clone(),
        claim_boundary: MUTATION_EVIDENCE_CLAIM_BOUNDARY.to_vec(),
    };

    write_json_pretty(&out_dir.join("nightly-summary.json"), &summary)?;
    write_json_pretty(&out_dir.join("survivors.json"), &survivor_report)?;
    write_mutation_evidence_receipt(out_dir, scope, dry_run, crate_results, survivor_report)?;
    fs::write(
        out_dir.join("nightly-summary.md"),
        render_mutation_nightly_markdown(&summary),
    )
    .with_context(|| {
        format!(
            "failed to write {}",
            out_dir.join("nightly-summary.md").display()
        )
    })?;
    fs::write(
        out_dir.join("survivors.md"),
        render_mutation_survivors_markdown(survivor_report),
    )
    .with_context(|| format!("failed to write {}", out_dir.join("survivors.md").display()))?;

    Ok(())
}

fn render_mutation_nightly_markdown(summary: &MutationNightlySummary) -> String {
    let mut md = String::new();
    md.push_str("# Nightly Mutation Evidence\n\n");
    md.push_str(&format!("- Lane: `{}`\n", summary.lane));
    md.push_str(&format!("- Scope: `{}`\n", summary.scope.as_str()));
    md.push_str(&format!("- Dry run: `{}`\n", summary.dry_run));
    md.push_str(&format!(
        "- Known survivor classifications: `{}`\n",
        summary.survivor_ledger.known_survivors
    ));
    md.push_str(&format!(
        "- Expired survivor classifications: `{}`\n",
        summary.survivor_ledger.expired_classifications
    ));
    md.push_str("\n## Crates\n\n");
    for crate_name in &summary.crates {
        md.push_str(&format!("- `{crate_name}`\n"));
    }
    md.push_str("\n## Claim Boundary\n\n");
    for claim in &summary.claim_boundary {
        md.push_str(&format!("- {claim}\n"));
    }
    md
}

fn planned_mutation_results(crates: &[String]) -> Vec<MutationEvidenceCrateResult> {
    crates
        .iter()
        .map(|crate_name| MutationEvidenceCrateResult {
            crate_name: crate_name.clone(),
            status: "planned".to_string(),
            mutants_found: 0,
            caught: 0,
            survived: 0,
            unviable: 0,
            timeouts: 0,
            other: 0,
            outcomes_path: None,
        })
        .collect()
}

struct MutationRunEvidence {
    crate_results: Vec<MutationEvidenceCrateResult>,
    failed_crates: Vec<String>,
}

fn run_mutants_with_outputs(crates: &[&str], output_root: &Path) -> Result<MutationRunEvidence> {
    ensure_cargo_mutants_installed()?;
    fs::create_dir_all(output_root)
        .with_context(|| format!("failed to create {}", output_root.display()))?;

    let tool_env = MutationToolEnv::detect();
    let mut results = Vec::new();
    let mut failed_crates = Vec::new();

    for name in crates {
        let output_dir = output_root.join(name);
        if output_dir.exists() {
            fs::remove_dir_all(&output_dir)
                .with_context(|| format!("failed to remove {}", output_dir.display()))?;
        }

        let Some(mut cmd) = mutation_command_for_crate(name, Some(&output_dir), &tool_env)? else {
            results.push(MutationEvidenceCrateResult {
                crate_name: (*name).to_string(),
                status: "skipped".to_string(),
                mutants_found: 0,
                caught: 0,
                survived: 0,
                unviable: 0,
                timeouts: 0,
                other: 0,
                outcomes_path: None,
            });
            continue;
        };

        eprintln!("{} {:?}", " RUN ".on_blue().black().bold(), cmd);
        let status = cmd
            .status()
            .with_context(|| format!("failed to run cargo-mutants for {name}"))?;
        let mut result = match read_mutation_evidence_result(name, &output_dir) {
            Ok(result) => result,
            Err(err) if status.success() => return Err(err),
            Err(_) => MutationEvidenceCrateResult {
                crate_name: (*name).to_string(),
                status: "failed-no-outcomes".to_string(),
                mutants_found: 0,
                caught: 0,
                survived: 0,
                unviable: 0,
                timeouts: 0,
                other: 0,
                outcomes_path: None,
            },
        };
        if !status.success() {
            result.status = "failed".to_string();
            failed_crates.push((*name).to_string());
        }
        results.push(result);
    }

    Ok(MutationRunEvidence {
        crate_results: results,
        failed_crates,
    })
}

fn read_mutation_evidence_result(
    crate_name: &str,
    output_dir: &Path,
) -> Result<MutationEvidenceCrateResult> {
    let outcomes_path = mutation_outcomes_path(output_dir);
    let raw = fs::read_to_string(&outcomes_path)
        .with_context(|| format!("failed to read {}", outcomes_path.display()))?;
    let outcomes: CargoMutantsOutcomes = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", outcomes_path.display()))?;
    Ok(mutation_evidence_result_from_outcomes(
        crate_name,
        Some(outcomes_path.display().to_string()),
        &outcomes,
    ))
}

fn mutation_outcomes_path(output_dir: &Path) -> PathBuf {
    let nested = output_dir.join("mutants.out/outcomes.json");
    if nested.is_file() {
        nested
    } else {
        output_dir.join("outcomes.json")
    }
}

#[derive(Debug, serde::Deserialize)]
struct CargoMutantsOutcomes {
    #[serde(default)]
    outcomes: Vec<CargoMutantsOutcome>,
}

#[derive(Debug, serde::Deserialize)]
struct CargoMutantsOutcome {
    scenario: serde_json::Value,
    summary: String,
}

fn mutation_evidence_result_from_outcomes(
    crate_name: &str,
    outcomes_path: Option<String>,
    outcomes: &CargoMutantsOutcomes,
) -> MutationEvidenceCrateResult {
    let mut result = MutationEvidenceCrateResult {
        crate_name: crate_name.to_string(),
        status: "completed".to_string(),
        mutants_found: 0,
        caught: 0,
        survived: 0,
        unviable: 0,
        timeouts: 0,
        other: 0,
        outcomes_path,
    };

    for outcome in &outcomes.outcomes {
        if outcome.scenario.get("Mutant").is_none() {
            continue;
        }

        result.mutants_found += 1;
        match outcome.summary.as_str() {
            "CaughtMutant" => result.caught += 1,
            "MissedMutant" => result.survived += 1,
            "Unviable" => result.unviable += 1,
            summary if summary.contains("Timeout") => result.timeouts += 1,
            _ => result.other += 1,
        }
    }

    result
}

fn write_mutation_evidence_receipt(
    out_dir: &Path,
    scope: MutationNightlyScope,
    dry_run: bool,
    crate_results: &[MutationEvidenceCrateResult],
    survivor_report: &MutationSurvivorLedgerReport,
) -> Result<()> {
    let receipt = MutationEvidenceReceipt {
        schema_version: 1,
        lane: "mutation-nightly",
        scope,
        dry_run,
        crate_results: crate_results.to_vec(),
        survivor_ledger: survivor_report.summary.clone(),
        claim_boundary: MUTATION_EVIDENCE_CLAIM_BOUNDARY.to_vec(),
    };

    write_json_pretty(&out_dir.join("nightly-receipt.json"), &receipt)?;
    fs::write(
        out_dir.join("nightly-receipt.md"),
        render_mutation_evidence_receipt_markdown(&receipt),
    )
    .with_context(|| {
        format!(
            "failed to write {}",
            out_dir.join("nightly-receipt.md").display()
        )
    })?;
    Ok(())
}

fn render_mutation_evidence_receipt_markdown(receipt: &MutationEvidenceReceipt) -> String {
    let mut md = String::new();
    md.push_str("# Mutation Evidence Receipt\n\n");
    md.push_str(&format!("- Lane: `{}`\n", receipt.lane));
    md.push_str(&format!("- Scope: `{}`\n", receipt.scope.as_str()));
    md.push_str(&format!("- Dry run: `{}`\n", receipt.dry_run));
    md.push_str(&format!(
        "- Known survivor classifications: `{}`\n",
        receipt.survivor_ledger.known_survivors
    ));
    md.push_str("\n## Crate Results\n\n");
    md.push_str("| Crate | Status | Found | Caught | Survived | Unviable | Timeouts | Other |\n");
    md.push_str("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for result in &receipt.crate_results {
        md.push_str(&format!(
            "| `{}` | `{}` | {} | {} | {} | {} | {} | {} |\n",
            result.crate_name,
            result.status,
            result.mutants_found,
            result.caught,
            result.survived,
            result.unviable,
            result.timeouts,
            result.other
        ));
    }
    md.push_str("\n## Claim Boundary\n\n");
    for claim in &receipt.claim_boundary {
        md.push_str(&format!("- {claim}\n"));
    }
    md
}

fn mutation_survivor_report(
    path: &Path,
    today: chrono::NaiveDate,
) -> Result<MutationSurvivorLedgerReport> {
    let ledger = read_mutation_survivor_ledger(path)?;
    mutation_survivor_report_from_ledger(path, ledger, today)
}

fn read_mutation_survivor_ledger(path: &Path) -> Result<MutationSurvivorLedger> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read mutation survivor ledger {}", path.display()))?;
    toml::from_str(&raw).with_context(|| {
        format!(
            "failed to parse mutation survivor ledger {}",
            path.display()
        )
    })
}

fn mutation_survivor_report_from_ledger(
    path: &Path,
    ledger: MutationSurvivorLedger,
    today: chrono::NaiveDate,
) -> Result<MutationSurvivorLedgerReport> {
    if ledger.schema_version.as_deref() != Some("0.1") {
        bail!("mutation survivor ledger must set schema_version = \"0.1\"");
    }

    let mut classification_counts = BTreeMap::new();
    let mut expired_classifications = Vec::new();

    for entry in &ledger.survivor {
        validate_mutation_survivor_entry(entry)?;
        *classification_counts
            .entry(entry.classification.clone())
            .or_insert(0) += 1;

        let expires = chrono::NaiveDate::parse_from_str(&entry.expires, "%Y-%m-%d")
            .with_context(|| format!("invalid mutation survivor expiry {}", entry.expires))?;
        if expires < today {
            expired_classifications.push(entry.clone());
        }
    }

    let summary = MutationSurvivorLedgerSummary {
        path: path.display().to_string(),
        known_survivors: ledger.survivor.len(),
        expired_classifications: expired_classifications.len(),
        pending_tests: *classification_counts.get("pending-test").unwrap_or(&0),
        accepted_risks: *classification_counts.get("accepted-risk").unwrap_or(&0),
        equivalent_mutants: *classification_counts.get("equivalent").unwrap_or(&0),
        unviable_mutants: 0,
    };

    Ok(MutationSurvivorLedgerReport {
        summary,
        known_survivors: ledger.survivor,
        expired_classifications,
        classification_counts,
        notes: vec![
            "new survivor detection will be added with mutation result receipts",
            "unviable mutants are counted from cargo-mutants output in a later lane",
        ],
    })
}

fn validate_mutation_survivor_entry(entry: &MutationSurvivorEntry) -> Result<()> {
    for (field, value) in [
        ("crate", entry.crate_name.as_str()),
        ("function", entry.function.as_str()),
        ("classification", entry.classification.as_str()),
        ("owner", entry.owner.as_str()),
        ("reason", entry.reason.as_str()),
        ("expires", entry.expires.as_str()),
    ] {
        if value.trim().is_empty() {
            bail!("mutation survivor entry has empty {field}");
        }
    }

    if !PUBLISH_CRATES.contains(&entry.crate_name.as_str()) {
        bail!(
            "mutation survivor entry references unknown publish crate: {}",
            entry.crate_name
        );
    }

    if !MUTATION_SURVIVOR_CLASSIFICATIONS.contains(&entry.classification.as_str()) {
        bail!(
            "mutation survivor entry has unsupported classification {}",
            entry.classification
        );
    }

    chrono::NaiveDate::parse_from_str(&entry.expires, "%Y-%m-%d")
        .with_context(|| format!("invalid mutation survivor expiry {}", entry.expires))?;

    if entry
        .issue
        .as_deref()
        .is_some_and(|issue| issue.trim().is_empty())
    {
        bail!("mutation survivor entry has empty issue");
    }

    Ok(())
}

fn render_mutation_survivors_markdown(report: &MutationSurvivorLedgerReport) -> String {
    let mut md = String::new();
    md.push_str("# Mutation Survivors\n\n");
    md.push_str(&format!("- Ledger: `{}`\n", report.summary.path));
    md.push_str(&format!(
        "- Known survivor classifications: `{}`\n",
        report.summary.known_survivors
    ));
    md.push_str(&format!(
        "- Expired survivor classifications: `{}`\n",
        report.summary.expired_classifications
    ));
    md.push_str(&format!(
        "- Pending tests: `{}`\n",
        report.summary.pending_tests
    ));
    md.push_str(&format!(
        "- Accepted risks: `{}`\n",
        report.summary.accepted_risks
    ));
    md.push_str(&format!(
        "- Equivalent mutants: `{}`\n",
        report.summary.equivalent_mutants
    ));
    md.push_str("\n## Known Survivors\n\n");
    if report.known_survivors.is_empty() {
        md.push_str("None classified.\n");
    } else {
        for survivor in &report.known_survivors {
            md.push_str(&format!(
                "- `{}` `{}`: {} ({}, expires `{}`)\n",
                survivor.crate_name,
                survivor.function,
                survivor.classification,
                survivor.owner,
                survivor.expires
            ));
        }
    }
    md.push_str("\n## Expired Classifications\n\n");
    if report.expired_classifications.is_empty() {
        md.push_str("None.\n");
    } else {
        for survivor in &report.expired_classifications {
            md.push_str(&format!(
                "- `{}` `{}` expired `{}`\n",
                survivor.crate_name, survivor.function, survivor.expires
            ));
        }
    }
    md.push_str("\n## Notes\n\n");
    for note in &report.notes {
        md.push_str(&format!("- {note}\n"));
    }
    md
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

fn pr(with_mutants: bool) -> Result<()> {
    let base_ref = resolve_base_ref();
    let changed_files = git_changed_files(&base_ref)?;
    let plan = plan::build_plan(&changed_files);

    let mut runner = receipt::Runner::new("target/xtask/receipt.json");
    if let Ok(sha) = git_head_sha() {
        runner.set_git_sha(sha);
    }
    runner.set_crate_set(format!("pr:{}", plan.impacted_crates.len()));

    let result = run_pr_plan(&base_ref, &changed_files, &plan, &mut runner, with_mutants);
    runner.summary();
    if let Err(err) = runner.write() {
        eprintln!("failed to write receipt: {err}");
        if result.is_ok() {
            return Err(err);
        }
    }
    result
}

fn mutants_pr(changed: bool, crates: Vec<String>, all: bool, full_owner: bool) -> Result<()> {
    let selector_count = usize::from(changed) + usize::from(!crates.is_empty()) + usize::from(all);
    if selector_count != 1 {
        bail!("select exactly one of --changed, --crate <CRATE>, or --all");
    }

    if full_owner {
        eprintln!("mutants-pr: full-owner proof requested for selected target(s)");
    }

    if all {
        return run_mutants(PUBLISH_CRATES);
    }

    if !crates.is_empty() {
        let crate_refs = crates.iter().map(String::as_str).collect::<Vec<_>>();
        return run_mutants(&crate_refs);
    }

    let base_ref = resolve_base_ref();
    let changed_files = git_changed_files(&base_ref)?;
    let pr_crates = mutation_target_crates(&base_ref, &changed_files)?;

    if pr_crates.is_empty() {
        println!("mutants-pr: no mutant-eligible behavior changes");
        return Ok(());
    }

    let pr_crate_refs = pr_crates.iter().map(String::as_str).collect::<Vec<_>>();
    run_mutants(&pr_crate_refs)
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct ImpactedEvidenceReport {
    schema_version: u32,
    base: String,
    changed_paths: Vec<String>,
    owner_crates: Vec<String>,
    requires_targeted_mutation: bool,
    reasons: Vec<String>,
    ripr: RiprEvidenceRouting,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct RiprEvidenceRouting {
    status: String,
    requires_targeted_evidence: bool,
    severe_gap_count: usize,
    owner_crates: Vec<String>,
    reasons: Vec<String>,
    suggested_actions: Vec<String>,
}

#[derive(Debug, Clone)]
struct ImpactedEvidenceRule {
    owner_crate: String,
    reason: &'static str,
    requires_targeted_mutation: bool,
}

#[derive(Debug, Clone)]
struct ReleaseEvidenceStep {
    name: &'static str,
    command: &'static [&'static str],
    artifacts: &'static [&'static str],
}

#[derive(Debug, Clone, serde::Serialize)]
struct ReleaseEvidenceCommandReceipt {
    name: String,
    command: Vec<String>,
    status: String,
    artifacts: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ReleaseEvidenceReceipt {
    schema_version: u32,
    lane: String,
    version: String,
    dry_run: bool,
    generated_at: String,
    git_sha: Option<String>,
    commands: Vec<ReleaseEvidenceCommandReceipt>,
    artifacts: Vec<String>,
    claim_boundary: Vec<&'static str>,
}

const RELEASE_EVIDENCE_CLAIM_BOUNDARY: &[&str] = &[
    "release evidence proves fixture-platform readiness for a candidate, not cryptographic correctness",
    "release evidence does not make uselesskey production key management",
    "ripr and mutation evidence are lane-scoped and complement deterministic regression tests",
    "scanner-safe evidence covers checked profiles and committed artifacts, not scanner evasion",
];

fn release_evidence_steps() -> Vec<ReleaseEvidenceStep> {
    vec![
        ReleaseEvidenceStep {
            name: "public-surface",
            command: &["cargo", "xtask", "public-surface"],
            artifacts: &[],
        },
        ReleaseEvidenceStep {
            name: "docs-sync",
            command: &["cargo", "xtask", "docs-sync", "--check"],
            artifacts: &[],
        },
        ReleaseEvidenceStep {
            name: "publish-preflight",
            command: &["cargo", "xtask", "publish-preflight"],
            artifacts: &["target/xtask/receipt.json"],
        },
        ReleaseEvidenceStep {
            name: "publish-check",
            command: &["cargo", "xtask", "publish-check"],
            artifacts: &[],
        },
        ReleaseEvidenceStep {
            name: "pr",
            command: &["cargo", "xtask", "pr"],
            artifacts: &["target/xtask/receipt.json"],
        },
        ReleaseEvidenceStep {
            name: "ripr-pr",
            command: &["cargo", "xtask", "ripr-pr"],
            artifacts: &[
                "target/ripr/pr/repo-exposure.json",
                "target/ripr/pr/summary.md",
                "target/ripr/pr/review.md",
            ],
        },
        ReleaseEvidenceStep {
            name: "impacted-evidence",
            command: &[
                "cargo",
                "xtask",
                "impacted-evidence",
                "--base",
                "origin/main",
            ],
            artifacts: &["target/xtask/impacted-evidence/latest.json"],
        },
        ReleaseEvidenceStep {
            name: "no-blob",
            command: &["cargo", "xtask", "no-blob"],
            artifacts: &[],
        },
        ReleaseEvidenceStep {
            name: "examples-smoke",
            command: &["cargo", "xtask", "examples-smoke"],
            artifacts: &[],
        },
        ReleaseEvidenceStep {
            name: "scanner-safe-bundle-proof",
            command: &[
                "cargo",
                "xtask",
                "bundle-proof",
                "--profile",
                "scanner-safe",
                "--out",
                "target/release-evidence/scanner-safe",
            ],
            artifacts: &[
                "target/release-evidence/scanner-safe/scanner-safe-bundle-proof.json",
                "target/release-evidence/scanner-safe/scanner-safe-bundle-proof.md",
            ],
        },
        ReleaseEvidenceStep {
            name: "oidc-contract-pack-proof",
            command: &[
                "cargo",
                "xtask",
                "bundle-proof",
                "--profile",
                "oidc",
                "--out",
                "target/release-evidence/oidc",
            ],
            artifacts: &[
                "target/release-evidence/oidc/oidc-contract-pack-proof.json",
                "target/release-evidence/oidc/oidc-contract-pack-proof.md",
            ],
        },
        ReleaseEvidenceStep {
            name: "economics",
            command: &["cargo", "xtask", "economics"],
            artifacts: &[
                "target/xtask/economics/latest.json",
                "target/xtask/economics/latest.md",
            ],
        },
        ReleaseEvidenceStep {
            name: "audit-surface",
            command: &["cargo", "xtask", "audit-surface"],
            artifacts: &[
                "target/xtask/audit-surface/latest.json",
                "target/xtask/audit-surface/latest.md",
            ],
        },
        ReleaseEvidenceStep {
            name: "perf",
            command: &["cargo", "xtask", "perf", "--compare"],
            artifacts: &["target/xtask/perf/latest.json"],
        },
        ReleaseEvidenceStep {
            name: "mutants-nightly-public",
            command: &["cargo", "xtask", "mutants-nightly", "--scope", "public"],
            artifacts: &[
                "target/mutation/nightly-summary.json",
                "target/mutation/nightly-summary.md",
                "target/mutation/nightly-receipt.json",
                "target/mutation/nightly-receipt.md",
                "target/mutation/survivors.json",
                "target/mutation/survivors.md",
            ],
        },
    ]
}

fn release_evidence(version: &str, out_dir: &Path, dry_run: bool, summary: bool) -> Result<()> {
    if version.trim().is_empty() {
        bail!("--version must not be empty");
    }

    let steps = release_evidence_steps();
    let mut receipt = release_evidence_receipt(version, dry_run, &steps);

    if dry_run {
        write_release_evidence_artifacts(out_dir, &receipt, summary)?;
        println!(
            "release-evidence: planned {} commands for v{}",
            receipt.commands.len(),
            receipt.version
        );
        println!(
            "release-evidence: wrote {} and {}",
            out_dir.join("release-evidence.json").display(),
            out_dir.join("release-evidence.md").display()
        );
        if summary {
            println!(
                "release-evidence: wrote {}",
                out_dir.join("summary.md").display()
            );
        }
        return Ok(());
    }

    for (idx, step) in steps.iter().enumerate() {
        receipt.commands[idx].status = "running".to_string();
        match run_release_evidence_step(step) {
            Ok(()) => receipt.commands[idx].status = "ok".to_string(),
            Err(err) => {
                receipt.commands[idx].status = "failed".to_string();
                write_release_evidence_artifacts(out_dir, &receipt, summary)?;
                return Err(err)
                    .with_context(|| format!("release evidence step failed: {}", step.name));
            }
        }
    }

    write_release_evidence_artifacts(out_dir, &receipt, summary)?;
    println!(
        "release-evidence: wrote {} and {}",
        out_dir.join("release-evidence.json").display(),
        out_dir.join("release-evidence.md").display()
    );
    if summary {
        println!(
            "release-evidence: wrote {}",
            out_dir.join("summary.md").display()
        );
    }
    Ok(())
}

fn release_evidence_receipt(
    version: &str,
    dry_run: bool,
    steps: &[ReleaseEvidenceStep],
) -> ReleaseEvidenceReceipt {
    let artifacts = steps
        .iter()
        .flat_map(|step| step.artifacts.iter().copied())
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    ReleaseEvidenceReceipt {
        schema_version: 1,
        lane: "release-evidence".to_string(),
        version: version.trim().to_string(),
        dry_run,
        generated_at: chrono::Utc::now().to_rfc3339(),
        git_sha: git_head_sha().ok(),
        commands: steps
            .iter()
            .map(|step| ReleaseEvidenceCommandReceipt {
                name: step.name.to_string(),
                command: step
                    .command
                    .iter()
                    .map(|part| (*part).to_string())
                    .collect(),
                status: if dry_run { "planned" } else { "pending" }.to_string(),
                artifacts: step
                    .artifacts
                    .iter()
                    .map(|artifact| (*artifact).to_string())
                    .collect(),
            })
            .collect(),
        artifacts,
        claim_boundary: RELEASE_EVIDENCE_CLAIM_BOUNDARY.to_vec(),
    }
}

fn run_release_evidence_step(step: &ReleaseEvidenceStep) -> Result<()> {
    let Some((program, args)) = step.command.split_first() else {
        bail!("release evidence step {} has no command", step.name);
    };
    let mut cmd = Command::new(program);
    cmd.args(args);
    run(&mut cmd)
}

fn write_release_evidence_artifacts(
    out_dir: &Path,
    receipt: &ReleaseEvidenceReceipt,
    write_summary: bool,
) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;
    write_json_pretty(&out_dir.join("release-evidence.json"), receipt)?;
    fs::write(
        out_dir.join("release-evidence.md"),
        render_release_evidence_markdown(receipt),
    )
    .with_context(|| {
        format!(
            "failed to write {}",
            out_dir.join("release-evidence.md").display()
        )
    })?;
    if write_summary {
        fs::write(
            out_dir.join("summary.md"),
            render_release_evidence_summary_markdown(receipt),
        )
        .with_context(|| format!("failed to write {}", out_dir.join("summary.md").display()))?;
    }
    Ok(())
}

fn render_release_evidence_markdown(receipt: &ReleaseEvidenceReceipt) -> String {
    let mut md = String::new();
    md.push_str("# Release Evidence\n\n");
    md.push_str(&format!("- Lane: `{}`\n", receipt.lane));
    md.push_str(&format!("- Version: `{}`\n", receipt.version));
    md.push_str(&format!("- Dry run: `{}`\n", receipt.dry_run));
    if let Some(sha) = &receipt.git_sha {
        md.push_str(&format!("- Git SHA: `{sha}`\n"));
    }
    md.push_str(&format!("- Generated at: `{}`\n", receipt.generated_at));
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
    md
}

fn release_summary_status(receipt: &ReleaseEvidenceReceipt, names: &[&str]) -> String {
    let statuses = names
        .iter()
        .map(|name| {
            receipt
                .commands
                .iter()
                .find(|command| command.name == *name)
                .map(|command| command.status.as_str())
                .unwrap_or("missing")
        })
        .collect::<Vec<_>>();

    if statuses.contains(&"failed") {
        "failed".to_string()
    } else if statuses.contains(&"missing") {
        "missing".to_string()
    } else if statuses.contains(&"running") {
        "running".to_string()
    } else if statuses.contains(&"pending") {
        "pending".to_string()
    } else if statuses.contains(&"planned") {
        "planned".to_string()
    } else if statuses.iter().all(|status| *status == "ok") {
        "ok".to_string()
    } else {
        statuses.join(", ")
    }
}

fn release_summary_artifacts(receipt: &ReleaseEvidenceReceipt, names: &[&str]) -> String {
    let artifacts = receipt
        .commands
        .iter()
        .filter(|command| names.iter().any(|name| command.name == *name))
        .flat_map(|command| command.artifacts.iter())
        .cloned()
        .collect::<BTreeSet<_>>();

    if artifacts.is_empty() {
        "-".to_string()
    } else {
        artifacts
            .iter()
            .map(|artifact| format!("`{artifact}`"))
            .collect::<Vec<_>>()
            .join("<br>")
    }
}

fn render_release_evidence_summary_markdown(receipt: &ReleaseEvidenceReceipt) -> String {
    let mut md = String::new();
    md.push_str("# v");
    md.push_str(&receipt.version);
    md.push_str(" Release Evidence Summary\n\n");
    md.push_str("## Release Claim\n\n");
    md.push_str(
        "v0.7.0 is the Rust 1.95 scanner-safe fixture platform release. It raises the v0.6.0 crates.io baseline from Rust 1.92 and keeps published internal shards as compatibility shims while users move to owner crates and facade surfaces.\n\n",
    );
    md.push_str("`uselesskey` generates deterministic, scanner-safe, protocol-shaped test fixtures and bundles. It is not production key management, scanner evasion, or cryptographic assurance.\n\n");
    md.push_str("## Gate Summary\n\n");
    md.push_str("| Area | Status | Evidence |\n");
    md.push_str("| --- | --- | --- |\n");
    for (area, names) in [
        ("Public surface", &["public-surface"][..]),
        (
            "Package and publish proof",
            &["publish-preflight", "publish-check"][..],
        ),
        (
            "Scanner-safe bundle proof",
            &["scanner-safe-bundle-proof"][..],
        ),
        (
            "OIDC contract-pack proof",
            &["oidc-contract-pack-proof"][..],
        ),
        ("RIPR exposure", &["ripr-pr", "impacted-evidence"][..]),
        ("Nightly mutation scope", &["mutants-nightly-public"][..]),
        ("Performance evidence", &["perf"][..]),
        (
            "Docs, examples, and scanner guard",
            &["docs-sync", "examples-smoke", "no-blob"][..],
        ),
        ("Receipts", &["economics", "audit-surface"][..]),
    ] {
        md.push_str(&format!(
            "| {area} | `{}` | {} |\n",
            release_summary_status(receipt, names),
            release_summary_artifacts(receipt, names)
        ));
    }

    md.push_str("\n## Open Issues\n\n");
    let failed = receipt
        .commands
        .iter()
        .filter(|command| command.status == "failed")
        .map(|command| command.name.as_str())
        .collect::<Vec<_>>();
    if !failed.is_empty() {
        for name in failed {
            md.push_str(&format!(
                "- `{name}` failed. Link the release-blocking issue before publishing.\n"
            ));
        }
    } else if receipt
        .commands
        .iter()
        .any(|command| command.status == "planned" || command.status == "pending")
    {
        md.push_str("- Pending RC execution. Replace planned or pending rows with artifacts, command results, or issue links before publishing.\n");
    } else {
        md.push_str("- None recorded by this release-evidence receipt.\n");
    }

    md.push_str("\n## Claim Boundaries\n\n");
    for claim in &receipt.claim_boundary {
        md.push_str(&format!("- {claim}\n"));
    }

    md
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct BundleProofManifest {
    profile: String,
    files: Vec<String>,
    #[serde(default)]
    artifacts: Vec<BundleProofArtifactRecord>,
    #[serde(default)]
    receipts: Vec<BundleProofReceiptRecord>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct BundleProofArtifactRecord {
    path: String,
    kind: String,
    format: String,
    #[serde(default)]
    lanes: Vec<String>,
    scanner_safe: bool,
    description: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct BundleProofReceiptRecord {
    path: String,
    kind: String,
    profile: String,
    description: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct BundleProofExportReceipt {
    target: String,
    path: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct BundleProofContractCheck {
    name: String,
    path: String,
    description: String,
    present: bool,
}

#[derive(Debug, Clone)]
struct BundleProofExpectedArtifact {
    name: &'static str,
    path: &'static str,
    description: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
struct BundleProofReceipt {
    schema_version: u32,
    lane: String,
    profile: String,
    generated_at: String,
    git_sha: Option<String>,
    bundle_dir: String,
    manifest_path: String,
    inspect_summary_path: String,
    artifact_count: usize,
    verified_file_count: usize,
    scanner_safe: bool,
    scanner_safe_artifact_count: usize,
    runtime_material_count: usize,
    private_key_material: bool,
    symmetric_secret_material: bool,
    receipts_present: Vec<String>,
    exports_generated: Vec<BundleProofExportReceipt>,
    contract_pack_checks: Vec<BundleProofContractCheck>,
    commands: Vec<ReleaseEvidenceCommandReceipt>,
    artifacts: Vec<BundleProofArtifactRecord>,
    claim_boundary: Vec<&'static str>,
}

struct BundleProofReceiptInput<'a> {
    profile: &'a str,
    bundle_dir: &'a Path,
    manifest_path: &'a Path,
    inspect_summary_path: &'a Path,
    manifest: &'a BundleProofManifest,
    audit_surface: &'a serde_json::Value,
    expected_artifacts: Vec<BundleProofExpectedArtifact>,
    commands: Vec<ReleaseEvidenceCommandReceipt>,
    exports_generated: Vec<BundleProofExportReceipt>,
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

fn bundle_proof(profile: &str, out_dir: Option<&Path>) -> Result<()> {
    let profile = profile.trim();
    ensure_supported_bundle_proof_profile(profile)?;
    let default_out_dir;
    let out_dir = match out_dir {
        Some(path) => path,
        None => {
            default_out_dir = default_bundle_proof_out_dir(profile)?;
            &default_out_dir
        }
    };
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;
    let bundle_dir = out_dir.join("bundle");
    let inspect_summary_path = out_dir.join("inspect-bundle.txt");
    let k8s_path = out_dir.join("secret.yaml");
    let vault_path = out_dir.join("kv-v2.json");

    let mut commands = vec![
        run_bundle_proof_command(
            "bundle",
            vec![
                "cargo".to_string(),
                "run".to_string(),
                "-p".to_string(),
                "uselesskey-cli".to_string(),
                "--".to_string(),
                "bundle".to_string(),
                "--profile".to_string(),
                profile.to_string(),
                "--out".to_string(),
                bundle_dir.display().to_string(),
            ],
            vec![
                bundle_dir.join("manifest.json").display().to_string(),
                bundle_dir
                    .join("receipts/materialization.json")
                    .display()
                    .to_string(),
                bundle_dir
                    .join("receipts/audit-surface.json")
                    .display()
                    .to_string(),
            ],
        )?,
        run_bundle_proof_command(
            "verify-bundle",
            vec![
                "cargo".to_string(),
                "run".to_string(),
                "-p".to_string(),
                "uselesskey-cli".to_string(),
                "--".to_string(),
                "verify-bundle".to_string(),
                "--path".to_string(),
                bundle_dir.display().to_string(),
            ],
            Vec::new(),
        )?,
        run_bundle_proof_command(
            "inspect-bundle",
            vec![
                "cargo".to_string(),
                "run".to_string(),
                "-p".to_string(),
                "uselesskey-cli".to_string(),
                "--".to_string(),
                "inspect-bundle".to_string(),
                "--path".to_string(),
                bundle_dir.display().to_string(),
                "--out".to_string(),
                inspect_summary_path.display().to_string(),
            ],
            vec![inspect_summary_path.display().to_string()],
        )?,
    ];
    let mut exports_generated = Vec::new();

    if profile == "scanner-safe" {
        commands.push(run_bundle_proof_command(
            "export-k8s",
            vec![
                "cargo".to_string(),
                "run".to_string(),
                "-p".to_string(),
                "uselesskey-cli".to_string(),
                "--".to_string(),
                "export".to_string(),
                "k8s".to_string(),
                "--bundle-dir".to_string(),
                bundle_dir.display().to_string(),
                "--name".to_string(),
                "uselesskey-fixtures".to_string(),
                "--namespace".to_string(),
                "tests".to_string(),
                "--out".to_string(),
                k8s_path.display().to_string(),
            ],
            vec![k8s_path.display().to_string()],
        )?);
        exports_generated.push(BundleProofExportReceipt {
            target: "k8s".to_string(),
            path: k8s_path.display().to_string(),
        });
        commands.push(run_bundle_proof_command(
            "export-vault-kv-json",
            vec![
                "cargo".to_string(),
                "run".to_string(),
                "-p".to_string(),
                "uselesskey-cli".to_string(),
                "--".to_string(),
                "export".to_string(),
                "vault-kv-json".to_string(),
                "--bundle-dir".to_string(),
                bundle_dir.display().to_string(),
                "--out".to_string(),
                vault_path.display().to_string(),
            ],
            vec![vault_path.display().to_string()],
        )?);
        exports_generated.push(BundleProofExportReceipt {
            target: "vault-kv-json".to_string(),
            path: vault_path.display().to_string(),
        });
    }

    if profile == "oidc" {
        commands.push(run_bundle_proof_command(
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
        commands.push(run_bundle_proof_command(
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
        commands.push(run_bundle_proof_command(
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
    }

    commands.push(run_bundle_proof_command(
        "no-blob",
        vec![
            "cargo".to_string(),
            "xtask".to_string(),
            "no-blob".to_string(),
        ],
        Vec::new(),
    )?);

    let manifest_path = bundle_dir.join("manifest.json");
    let manifest: BundleProofManifest = read_json_file(&manifest_path)?;
    let audit_surface_path = bundle_dir.join("receipts/audit-surface.json");
    let audit_surface: serde_json::Value = read_json_file(&audit_surface_path)?;
    let receipt = bundle_proof_receipt(BundleProofReceiptInput {
        profile,
        bundle_dir: &bundle_dir,
        manifest_path: &manifest_path,
        inspect_summary_path: &inspect_summary_path,
        manifest: &manifest,
        audit_surface: &audit_surface,
        expected_artifacts: bundle_proof_expected_artifacts(profile)?,
        commands,
        exports_generated,
    })?;

    write_bundle_proof_artifacts(out_dir, &receipt)?;
    println!(
        "bundle-proof: wrote {} and {}",
        out_dir.join(bundle_proof_json_filename(profile)?).display(),
        out_dir
            .join(bundle_proof_markdown_filename(profile)?)
            .display()
    );
    Ok(())
}

fn ensure_supported_bundle_proof_profile(profile: &str) -> Result<()> {
    if matches!(profile, "scanner-safe" | "oidc") {
        Ok(())
    } else {
        bail!("bundle-proof currently supports --profile scanner-safe and --profile oidc");
    }
}

fn default_bundle_proof_out_dir(profile: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(match profile {
        "scanner-safe" => "target/release-evidence/scanner-safe",
        "oidc" => "target/release-evidence/oidc",
        _ => bail!("bundle-proof currently supports --profile scanner-safe and --profile oidc"),
    }))
}

fn bundle_proof_json_filename(profile: &str) -> Result<&'static str> {
    Ok(match profile {
        "scanner-safe" => "scanner-safe-bundle-proof.json",
        "oidc" => "oidc-contract-pack-proof.json",
        _ => bail!("bundle-proof currently supports --profile scanner-safe and --profile oidc"),
    })
}

fn bundle_proof_markdown_filename(profile: &str) -> Result<&'static str> {
    Ok(match profile {
        "scanner-safe" => "scanner-safe-bundle-proof.md",
        "oidc" => "oidc-contract-pack-proof.md",
        _ => bail!("bundle-proof currently supports --profile scanner-safe and --profile oidc"),
    })
}

fn bundle_proof_markdown_title(profile: &str) -> Result<&'static str> {
    Ok(match profile {
        "scanner-safe" => "Scanner-Safe Bundle Proof",
        "oidc" => "OIDC Contract-Pack Proof",
        _ => bail!("bundle-proof currently supports --profile scanner-safe and --profile oidc"),
    })
}

fn bundle_proof_claim_boundary(profile: &str) -> Result<Vec<&'static str>> {
    Ok(match profile {
        "scanner-safe" => SCANNER_SAFE_BUNDLE_PROOF_CLAIM_BOUNDARY.to_vec(),
        "oidc" => OIDC_CONTRACT_PACK_PROOF_CLAIM_BOUNDARY.to_vec(),
        _ => bail!("bundle-proof currently supports --profile scanner-safe and --profile oidc"),
    })
}

fn bundle_proof_expected_artifacts(profile: &str) -> Result<Vec<BundleProofExpectedArtifact>> {
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
    run(&mut cmd).with_context(|| format!("bundle proof step failed: {name}"))?;
    Ok(ReleaseEvidenceCommandReceipt {
        name: name.to_string(),
        command,
        status: "ok".to_string(),
        artifacts,
    })
}

fn bundle_proof_receipt(input: BundleProofReceiptInput<'_>) -> Result<BundleProofReceipt> {
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
    if !scanner_safe {
        bail!("bundle proof expected all artifacts to be scanner-safe");
    }
    if runtime_material_count != 0 {
        bail!("bundle proof expected zero runtime material artifacts");
    }
    if private_key_material {
        bail!("bundle proof found private key material");
    }
    if symmetric_secret_material {
        bail!("bundle proof found symmetric secret material");
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
    artifact.kind == "hmac" && !artifact.scanner_safe
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

fn render_bundle_proof_markdown(receipt: &BundleProofReceipt) -> Result<String> {
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

fn impacted_evidence(base: Option<String>) -> Result<()> {
    let base_ref = base.unwrap_or_else(resolve_base_ref);
    let changed_paths = git_changed_files(&base_ref)?;
    let ripr_json = read_optional_ripr_pr_json(&Path::new(RIPR_PR_DIR).join("repo-exposure.json"))?;
    let report = impacted_evidence_report_with_ripr(&base_ref, &changed_paths, ripr_json.as_ref());
    let artifact_path = Path::new("target/xtask/impacted-evidence/latest.json");
    write_json_pretty(artifact_path, &report)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).context("failed to render impacted evidence JSON")?
    );
    eprintln!("impacted-evidence: wrote {}", artifact_path.display());
    Ok(())
}

fn impacted_evidence_report(base_ref: &str, changed_paths: &[String]) -> ImpactedEvidenceReport {
    impacted_evidence_report_with_ripr(base_ref, changed_paths, None)
}

fn impacted_evidence_report_with_ripr(
    base_ref: &str,
    changed_paths: &[String],
    ripr_json: Option<&serde_json::Value>,
) -> ImpactedEvidenceReport {
    let mut owner_crates = BTreeSet::new();
    let mut reasons = BTreeSet::new();
    let mut requires_targeted_mutation = false;
    let changed_paths = changed_paths
        .iter()
        .map(|path| path.replace('\\', "/"))
        .collect::<Vec<_>>();

    for path in &changed_paths {
        if let Some(rule) = impacted_evidence_rule(path) {
            owner_crates.insert(rule.owner_crate.to_string());
            reasons.insert(rule.reason.to_string());
            requires_targeted_mutation |= rule.requires_targeted_mutation;
        }
    }

    ImpactedEvidenceReport {
        schema_version: 1,
        base: base_ref.to_string(),
        ripr: ripr_evidence_routing(&changed_paths, ripr_json),
        changed_paths,
        owner_crates: owner_crates.into_iter().collect(),
        requires_targeted_mutation,
        reasons: reasons.into_iter().collect(),
    }
}

fn read_optional_ripr_pr_json(path: &Path) -> Result<Option<serde_json::Value>> {
    if !path.is_file() {
        return Ok(None);
    }

    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let json = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(json))
}

fn ripr_evidence_routing(
    changed_paths: &[String],
    ripr_json: Option<&serde_json::Value>,
) -> RiprEvidenceRouting {
    let Some(json) = ripr_json else {
        return RiprEvidenceRouting {
            status: "missing".to_string(),
            requires_targeted_evidence: false,
            severe_gap_count: 0,
            owner_crates: Vec::new(),
            reasons: Vec::new(),
            suggested_actions: Vec::new(),
        };
    };

    if json_str(json, "status") == Some("skipped") {
        return RiprEvidenceRouting {
            status: "skipped".to_string(),
            requires_targeted_evidence: false,
            severe_gap_count: 0,
            owner_crates: Vec::new(),
            reasons: vec!["ripr-skipped".to_string()],
            suggested_actions: vec![
                "Install ripr and rerun cargo xtask ripr-pr for oracle-exposure evidence"
                    .to_string(),
            ],
        };
    }

    let summary = json.get("summary").unwrap_or(&serde_json::Value::Null);
    let reachable_unrevealed = json_u64(summary, "reachable_unrevealed") as usize;
    let no_static_path = json_u64(summary, "no_static_path") as usize;
    let mut reasons = BTreeSet::new();
    let mut owner_crates = BTreeSet::new();

    if reachable_unrevealed > 0 {
        reasons.insert("reachable-unrevealed".to_string());
    }
    if no_static_path > 0 {
        reasons.insert("no-static-path".to_string());
    }

    let findings = json
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut severe_finding_count = 0usize;
    for finding in findings
        .iter()
        .filter(|finding| ripr_finding_is_severe(finding))
    {
        severe_finding_count += 1;
        reasons.insert("severe-finding".to_string());
        if let Some(owner) = ripr_public_owner_for_finding(finding) {
            owner_crates.insert(owner);
        }
    }

    if reachable_unrevealed + no_static_path > 0 {
        for owner in ripr_changed_public_owners(changed_paths) {
            owner_crates.insert(owner);
        }
    }

    let severe_gap_count = reachable_unrevealed + no_static_path + severe_finding_count;
    let owner_crates = owner_crates.into_iter().collect::<Vec<_>>();
    let requires_targeted_evidence = severe_gap_count > 0 && !owner_crates.is_empty();
    let mut suggested_actions = Vec::new();
    if requires_targeted_evidence {
        suggested_actions.push("Add focused tests for severe ripr exposure gaps".to_string());
        suggested_actions.push("Run cargo xtask mutants-pr --changed".to_string());
        for owner in &owner_crates {
            suggested_actions.push(format!("Run cargo xtask mutants-pr --crate {owner}"));
        }
    }

    RiprEvidenceRouting {
        status: "available".to_string(),
        requires_targeted_evidence,
        severe_gap_count,
        owner_crates,
        reasons: reasons.into_iter().collect(),
        suggested_actions,
    }
}

fn ripr_finding_is_severe(finding: &serde_json::Value) -> bool {
    for key in ["severity", "status", "classification"] {
        let Some(value) = json_str(finding, key) else {
            continue;
        };
        if matches!(
            value.to_ascii_lowercase().as_str(),
            "high" | "severe" | "critical" | "reachable_unrevealed" | "no_static_path"
        ) {
            return true;
        }
    }
    false
}

fn ripr_public_owner_for_finding(finding: &serde_json::Value) -> Option<String> {
    let file = json_str(finding, "file")
        .or_else(|| json_str(finding, "path"))
        .or_else(|| json_str(finding, "changed_file"))?;
    ripr_public_owner_for_path(file)
}

fn ripr_changed_public_owners(changed_paths: &[String]) -> Vec<String> {
    let mut owners = BTreeSet::new();
    for path in changed_paths {
        if let Some(owner) = ripr_public_owner_for_path(path) {
            owners.insert(owner);
        }
    }
    owners.into_iter().collect()
}

fn ripr_public_owner_for_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let rule = impacted_evidence_rule(&normalized)?;
    if PUBLISH_CRATES.contains(&rule.owner_crate.as_str()) {
        Some(rule.owner_crate)
    } else {
        None
    }
}

fn impacted_evidence_rule(path: &str) -> Option<ImpactedEvidenceRule> {
    let path = path.replace('\\', "/");
    let path = path.as_str();

    if path.starts_with("crates/uselesskey-core/src/srp/hash")
        || path.starts_with("crates/uselesskey-core/src/srp/identity")
        || path.starts_with("crates/uselesskey-core/src/srp/seed")
    {
        return Some(ImpactedEvidenceRule {
            owner_crate: "uselesskey-core".to_string(),
            reason: "core-derivation",
            requires_targeted_mutation: true,
        });
    }

    if path.starts_with("crates/uselesskey-core/src/srp/cache") {
        return Some(ImpactedEvidenceRule {
            owner_crate: "uselesskey-core".to_string(),
            reason: "core-cache",
            requires_targeted_mutation: true,
        });
    }

    if path.starts_with("crates/uselesskey-core/src/srp/sink") {
        return Some(ImpactedEvidenceRule {
            owner_crate: "uselesskey-core".to_string(),
            reason: "core-sink",
            requires_targeted_mutation: true,
        });
    }

    if path.starts_with("crates/uselesskey-core/src/srp/keypair")
        || path.starts_with("crates/uselesskey-core/src/srp/keypair_material")
    {
        return Some(ImpactedEvidenceRule {
            owner_crate: "uselesskey-core".to_string(),
            reason: "core-key-material",
            requires_targeted_mutation: true,
        });
    }

    if path.starts_with("crates/uselesskey-core/src/srp/negative")
        || path.starts_with("crates/uselesskey-core/src/negative")
    {
        return Some(ImpactedEvidenceRule {
            owner_crate: "uselesskey-core".to_string(),
            reason: "negative-helper",
            requires_targeted_mutation: true,
        });
    }

    if path.starts_with("crates/uselesskey-core/src/") {
        return Some(ImpactedEvidenceRule {
            owner_crate: "uselesskey-core".to_string(),
            reason: "core-foundation",
            requires_targeted_mutation: true,
        });
    }

    for (prefix, owner, reason) in [
        (
            "crates/uselesskey-jwk/src/srp/",
            "uselesskey-jwk",
            "jwk-owner-internal",
        ),
        (
            "crates/uselesskey-token/src/srp/",
            "uselesskey-token",
            "token-owner-internal",
        ),
        (
            "crates/uselesskey-x509/src/srp/",
            "uselesskey-x509",
            "x509-owner-internal",
        ),
        (
            "crates/uselesskey-hmac/src/srp/",
            "uselesskey-hmac",
            "hmac-owner-internal",
        ),
        (
            "crates/uselesskey-rustls/src/srp/",
            "uselesskey-rustls",
            "adapter-conversion",
        ),
    ] {
        if path.starts_with(prefix) {
            return Some(ImpactedEvidenceRule {
                owner_crate: owner.to_string(),
                reason,
                requires_targeted_mutation: true,
            });
        }
    }

    if path.starts_with("crates/uselesskey-cli/src/") {
        return Some(ImpactedEvidenceRule {
            owner_crate: "uselesskey-cli".to_string(),
            reason: "cli-bundle-or-receipt",
            requires_targeted_mutation: true,
        });
    }

    if let Some(owner) = compatibility_shim_owner(path) {
        return Some(ImpactedEvidenceRule {
            owner_crate: owner.to_string(),
            reason: "compatibility-shim",
            requires_targeted_mutation: false,
        });
    }

    if let Some(crate_name) = path
        .strip_prefix("crates/")
        .and_then(|rest| rest.split('/').next())
        && path.starts_with(&format!("crates/{crate_name}/src/"))
        && PUBLISH_CRATES.contains(&crate_name)
    {
        let reason = if is_adapter_crate(crate_name) {
            "adapter-conversion"
        } else {
            "public-owner-crate"
        };
        return Some(ImpactedEvidenceRule {
            owner_crate: crate_name.to_string(),
            reason,
            requires_targeted_mutation: true,
        });
    }

    None
}

fn compatibility_shim_owner(path: &str) -> Option<&'static str> {
    for (prefix, owner) in [
        ("crates/uselesskey-core-jwk/", "uselesskey-jwk"),
        ("crates/uselesskey-core-jwk-shape/", "uselesskey-jwk"),
        ("crates/uselesskey-core-jwk-builder/", "uselesskey-jwk"),
        ("crates/uselesskey-core-jwks-order/", "uselesskey-jwk"),
        ("crates/uselesskey-core-kid/", "uselesskey-jwk"),
        ("crates/uselesskey-core-token/", "uselesskey-token"),
        ("crates/uselesskey-core-token-shape/", "uselesskey-token"),
        ("crates/uselesskey-core-base62/", "uselesskey-token"),
        ("crates/uselesskey-token-spec/", "uselesskey-token"),
        ("crates/uselesskey-core-x509/", "uselesskey-x509"),
        ("crates/uselesskey-core-x509-spec/", "uselesskey-x509"),
        ("crates/uselesskey-core-x509-derive/", "uselesskey-x509"),
        ("crates/uselesskey-core-x509-negative/", "uselesskey-x509"),
        (
            "crates/uselesskey-core-x509-chain-negative/",
            "uselesskey-x509",
        ),
        ("crates/uselesskey-core-hmac-spec/", "uselesskey-hmac"),
        ("crates/uselesskey-core-rustls-pki/", "uselesskey-rustls"),
    ] {
        if path.starts_with(prefix) {
            return Some(owner);
        }
    }
    None
}

fn is_adapter_crate(crate_name: &str) -> bool {
    matches!(
        crate_name,
        "uselesskey-jsonwebtoken"
            | "uselesskey-rustls"
            | "uselesskey-tonic"
            | "uselesskey-axum"
            | "uselesskey-ring"
            | "uselesskey-rustcrypto"
            | "uselesskey-aws-lc-rs"
            | "uselesskey-jose-openid"
            | "uselesskey-pgp-native"
    )
}

fn run_pr_plan(
    base_ref: &str,
    changed_files: &[String],
    plan: &plan::Plan,
    runner: &mut receipt::Runner,
    with_mutants: bool,
) -> Result<()> {
    runner.step(
        "detect-changes",
        Some(format!(
            "base_ref={base_ref}, files={}, direct_crates={}, impacted_crates={}",
            changed_files.len(),
            plan.directly_changed_crates.len(),
            plan.impacted_crates.len()
        )),
        || Ok(()),
    )?;

    runner.step("public-surface", None, || {
        public_surface::public_surface_cmd(PUBLISH_CRATES)
    })?;

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
        runner.skip("preflight:public-surface", reason.clone());
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

    if plan.run_mutants && with_mutants {
        let pr_crates = mutation_target_crates(base_ref, changed_files)?;
        if pr_crates.is_empty() {
            runner.skip(
                "mutants",
                Some("no mutant-eligible behavior changes".into()),
            );
        } else {
            let pr_crate_refs = pr_crates.iter().map(String::as_str).collect::<Vec<_>>();
            runner.step("mutants", None, || run_mutants(&pr_crate_refs))?;
        }
    } else if plan.run_mutants {
        runner.skip(
            "mutants",
            Some("split from default pr gate; run cargo xtask pr --with-mutants or cargo xtask mutants-pr --changed".to_string()),
        );
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
        run_publish_preflight(runner, false)?;
    } else {
        runner.skip("preflight:metadata", Some("no cargo changes".into()));
        runner.skip("preflight:doc-versions", Some("no cargo changes".into()));
        runner.skip("preflight:public-surface", Some("no cargo changes".into()));
        for name in PUBLISH_CRATES {
            runner.skip(
                &format!("preflight:package:{name}"),
                Some("no cargo changes".into()),
            );
        }
    }

    Ok(())
}

fn git_head_sha() -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .context("failed to run git rev-parse")?;
    if !output.status.success() {
        bail!("git rev-parse HEAD failed");
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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

const RIPR_PR_DIR: &str = "target/ripr/pr";

const RIPR_CLAIM_BOUNDARY: &[&str] = &[
    "ripr is static oracle-exposure evidence for changed behavior",
    "ripr does not run mutants and does not replace mutation testing",
    "advisory PR evidence should route targeted mutation, not suppress it",
];

fn ripr_pr() -> Result<()> {
    let base_ref = resolve_base_ref();
    let out_dir = PathBuf::from(RIPR_PR_DIR);
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;

    let output = match Command::new("ripr")
        .args(["check", "--base", &base_ref, "--format", "json"])
        .output()
    {
        Ok(output) => output,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            let reason = "ripr is not installed or not on PATH";
            write_ripr_skipped_artifacts(&out_dir, &base_ref, reason)?;
            println!("ripr-pr: skipped ({reason})");
            println!(
                "ripr-pr: wrote {}, {}, and {}",
                out_dir.join("repo-exposure.json").display(),
                out_dir.join("summary.md").display(),
                out_dir.join("review.md").display()
            );
            return Ok(());
        }
        Err(err) => return Err(err).context("failed to spawn ripr"),
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "ripr check failed with status {}: {}",
            output.status,
            stderr
        );
    }

    let raw = String::from_utf8(output.stdout).context("ripr emitted non-UTF-8 JSON")?;
    let json: serde_json::Value =
        serde_json::from_str(&raw).context("failed to parse ripr JSON output")?;

    let json_path = out_dir.join("repo-exposure.json");
    fs::write(&json_path, serde_json::to_string_pretty(&json)?)
        .with_context(|| format!("failed to write {}", json_path.display()))?;

    let markdown = render_ripr_markdown(&base_ref, &json);
    let summary_path = out_dir.join("summary.md");
    fs::write(&summary_path, &markdown)
        .with_context(|| format!("failed to write {}", summary_path.display()))?;
    let review_path = out_dir.join("review.md");
    fs::write(&review_path, &markdown)
        .with_context(|| format!("failed to write {}", review_path.display()))?;

    let summary = json.get("summary").unwrap_or(&serde_json::Value::Null);
    println!(
        "ripr-pr: findings={} exposed={} weakly_exposed={}",
        json_u64(summary, "findings"),
        json_u64(summary, "exposed"),
        json_u64(summary, "weakly_exposed")
    );
    println!(
        "ripr-pr: wrote {}, {}, and {}",
        json_path.display(),
        summary_path.display(),
        review_path.display()
    );
    Ok(())
}

fn write_ripr_skipped_artifacts(out_dir: &Path, base_ref: &str, reason: &str) -> Result<()> {
    let json = serde_json::json!({
        "schema_version": 1,
        "tool": "ripr",
        "lane": "pr",
        "status": "skipped",
        "base": base_ref,
        "reason": reason,
        "artifacts": [
            "target/ripr/pr/repo-exposure.json",
            "target/ripr/pr/summary.md",
            "target/ripr/pr/review.md"
        ],
        "claim_boundary": RIPR_CLAIM_BOUNDARY,
    });
    write_json_pretty(&out_dir.join("repo-exposure.json"), &json)?;

    let markdown = render_ripr_skipped_markdown(base_ref, reason);
    fs::write(out_dir.join("summary.md"), &markdown)
        .with_context(|| format!("failed to write {}", out_dir.join("summary.md").display()))?;
    fs::write(out_dir.join("review.md"), &markdown)
        .with_context(|| format!("failed to write {}", out_dir.join("review.md").display()))?;
    Ok(())
}

fn render_ripr_skipped_markdown(base_ref: &str, reason: &str) -> String {
    format!(
        "\
# RIPR PR Evidence

Status: skipped

Base: `{base_ref}`

Reason: {reason}.

Install `ripr` and rerun `cargo xtask ripr-pr` to generate advisory PR exposure evidence.

## Claim Boundary

{}
",
        render_claim_boundary()
    )
}

fn render_ripr_markdown(base_ref: &str, json: &serde_json::Value) -> String {
    let summary = json.get("summary").unwrap_or(&serde_json::Value::Null);
    let findings = json
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut md = String::new();
    md.push_str("# RIPR PR Evidence\n\n");
    md.push_str("Status: advisory\n\n");
    md.push_str(&format!("Base: `{base_ref}`\n\n"));
    md.push_str("`ripr` estimates whether changed Rust behavior appears to reach a meaningful test oracle. It does not run mutants.\n\n");
    md.push_str("## Summary\n\n");
    md.push_str("| Metric | Count |\n");
    md.push_str("| --- | ---: |\n");
    for key in [
        "changed_rust_files",
        "probes",
        "findings",
        "exposed",
        "weakly_exposed",
        "reachable_unrevealed",
        "no_static_path",
        "infection_unknown",
        "propagation_unknown",
        "static_unknown",
    ] {
        md.push_str(&format!(
            "| {} | {} |\n",
            key.replace('_', " "),
            json_u64(summary, key)
        ));
    }

    md.push_str("\n## Findings\n\n");
    if findings.is_empty() {
        md.push_str("No findings reported.\n");
    } else {
        for finding in findings.iter().take(20) {
            md.push_str(&format!("- {}\n", render_ripr_finding(finding)));
        }
        if findings.len() > 20 {
            md.push_str(&format!(
                "- ... {} additional findings omitted from summary.\n",
                findings.len() - 20
            ));
        }
    }

    md.push_str("\n## Claim Boundary\n\n");
    md.push_str(&render_claim_boundary());
    md
}

fn render_ripr_finding(finding: &serde_json::Value) -> String {
    let id = json_str(finding, "id").unwrap_or("unidentified");
    let file = json_str(finding, "file").unwrap_or("unknown file");
    let line = finding
        .get("line")
        .and_then(serde_json::Value::as_u64)
        .map(|line| line.to_string())
        .unwrap_or_else(|| "?".to_string());
    let status = json_str(finding, "status")
        .or_else(|| json_str(finding, "classification"))
        .unwrap_or("unknown");
    let message = json_str(finding, "message")
        .or_else(|| json_str(finding, "summary"))
        .unwrap_or("no message");
    format!("`{id}` at `{file}:{line}`: {status} - {message}")
}

fn render_claim_boundary() -> String {
    RIPR_CLAIM_BOUNDARY
        .iter()
        .map(|claim| format!("- {claim}\n"))
        .collect::<String>()
}

fn json_u64(value: &serde_json::Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn json_str<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

fn git_changed_files(base_ref: &str) -> Result<Vec<String>> {
    let mut attempts = Vec::new();

    for candidate in base_ref_candidates(base_ref) {
        let revspec = format!("{candidate}...HEAD");
        let output = Command::new("git")
            .args(["diff", "--name-only", &revspec])
            .output()
            .context("failed to run git diff")?;

        if output.status.success() {
            return parse_changed_files(&output.stdout);
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        attempts.push(format!(
            "{revspec} (status {}): {stderr}",
            output.status.code().unwrap_or(-1)
        ));
    }

    if git_commit_exists("HEAD~1")? {
        let output = Command::new("git")
            .args(["diff", "--name-only", "HEAD~1..HEAD"])
            .output()
            .context("failed to run git diff HEAD~1..HEAD")?;
        if output.status.success() {
            eprintln!("xtask pr: base ref '{base_ref}' unavailable, falling back to HEAD~1..HEAD");
            return parse_changed_files(&output.stdout);
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        attempts.push(format!(
            "HEAD~1..HEAD (status {}): {stderr}",
            output.status.code().unwrap_or(-1)
        ));
    } else {
        eprintln!(
            "xtask pr: base ref '{base_ref}' and HEAD~1 unavailable, treating repository as unchanged"
        );
        return Ok(Vec::new());
    }

    bail!(
        "git diff failed for all attempted base refs: {}",
        attempts.join(" | ")
    )
}

fn base_ref_candidates(base_ref: &str) -> Vec<String> {
    let mut refs = vec![base_ref.to_string()];
    if let Some(local) = base_ref.strip_prefix("origin/")
        && !local.is_empty()
    {
        refs.push(local.to_string());
    }
    refs
}

fn git_commit_exists(rev: &str) -> Result<bool> {
    Ok(Command::new("git")
        .args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{rev}^{{commit}}"),
        ])
        .status()
        .with_context(|| format!("failed to run git rev-parse --verify for {rev}"))?
        .success())
}

fn parse_changed_files(stdout: &[u8]) -> Result<Vec<String>> {
    let stdout =
        String::from_utf8(stdout.to_vec()).context("git diff output was not valid UTF-8")?;
    let files = stdout
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    Ok(files)
}

fn mutation_target_crates(base_ref: &str, changed_files: &[String]) -> Result<Vec<String>> {
    let report = impacted_evidence_report(base_ref, changed_files);
    if !report.requires_targeted_mutation {
        if report.reasons.is_empty() {
            println!("mutants-pr: targeted mutation not required by impacted evidence");
        } else {
            println!(
                "mutants-pr: targeted mutation not required by impacted evidence ({})",
                report.reasons.join(", ")
            );
        }
        return Ok(Vec::new());
    }

    let mut targets = Vec::new();
    for name in mutation_target_owners(changed_files) {
        let owner_paths = mutation_target_paths_for_owner(&name, changed_files);
        let rust_paths = owner_paths
            .iter()
            .filter(|path| path.ends_with(".rs"))
            .cloned()
            .collect::<Vec<_>>();
        if rust_paths.is_empty() {
            targets.push(name.clone());
            continue;
        }

        let diff = git_diff_for_paths(base_ref, &rust_paths)?;
        if diff_is_lint_allow_reason_only(&diff) {
            eprintln!(
                "xtask pr: skipping mutants for {name}: only lint allow reason metadata changed"
            );
            continue;
        }

        targets.push(name.clone());
    }
    Ok(targets)
}

fn mutation_target_owners(changed_files: &[String]) -> Vec<String> {
    let mut owners = BTreeSet::new();
    for path in changed_files {
        let normalized = path.replace('\\', "/");
        let Some(rule) = impacted_evidence_rule(&normalized) else {
            continue;
        };
        if rule.requires_targeted_mutation && PUBLISH_CRATES.contains(&rule.owner_crate.as_str()) {
            owners.insert(rule.owner_crate);
        }
    }
    owners.into_iter().collect()
}

fn mutation_target_paths_for_owner(owner: &str, changed_files: &[String]) -> Vec<String> {
    changed_files
        .iter()
        .map(|path| path.replace('\\', "/"))
        .filter(|path| {
            impacted_evidence_rule(path)
                .is_some_and(|rule| rule.requires_targeted_mutation && rule.owner_crate == owner)
        })
        .collect()
}

fn git_diff_for_paths(base_ref: &str, paths: &[String]) -> Result<String> {
    let mut attempts = Vec::new();
    for candidate in base_ref_candidates(base_ref) {
        let revspec = format!("{candidate}...HEAD");
        let mut cmd = Command::new("git");
        cmd.args(["diff", "--unified=0", "--no-ext-diff", &revspec, "--"]);
        for path in paths {
            cmd.arg(path);
        }
        let output = cmd.output().context("failed to run git diff")?;
        if output.status.success() {
            return String::from_utf8(output.stdout).context("git diff output was not valid UTF-8");
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        attempts.push(format!(
            "{revspec} (status {}): {stderr}",
            output.status.code().unwrap_or(-1)
        ));
    }

    bail!(
        "git diff failed for mutation target paths: {}",
        attempts.join("; ")
    )
}

fn diff_is_lint_allow_reason_only(diff: &str) -> bool {
    let mut saw_changed_line = false;
    let mut saw_changed_hunk = false;
    let mut hunk_lines = Vec::new();

    for line in diff.lines() {
        if line.starts_with("@@") {
            if !hunk_lines.is_empty() {
                saw_changed_hunk = true;
                if !lint_allow_reason_hunk_only(&hunk_lines) {
                    return false;
                }
                hunk_lines.clear();
            }
            continue;
        }

        if line.starts_with("diff --git ")
            || line.starts_with("index ")
            || line.starts_with("new file mode ")
            || line.starts_with("deleted file mode ")
            || line.starts_with("similarity index ")
            || line.starts_with("rename from ")
            || line.starts_with("rename to ")
            || line.starts_with("--- ")
            || line.starts_with("+++ ")
        {
            continue;
        }

        if let Some(rest) = line.strip_prefix('+') {
            saw_changed_line = true;
            hunk_lines.push(rest);
        } else if let Some(rest) = line.strip_prefix('-') {
            saw_changed_line = true;
            hunk_lines.push(rest);
        }
    }

    if !hunk_lines.is_empty() {
        saw_changed_hunk = true;
        if !lint_allow_reason_hunk_only(&hunk_lines) {
            return false;
        }
    }

    saw_changed_line && saw_changed_hunk
}

fn lint_allow_reason_hunk_only(lines: &[&str]) -> bool {
    let mut saw_allow = false;
    let mut saw_reason = false;

    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return false;
        }
        if trimmed.starts_with("#[allow(") || trimmed.starts_with("#![allow(") {
            saw_allow = true;
            if trimmed.contains("reason") {
                saw_reason = true;
            }
            continue;
        }
        if trimmed.starts_with("reason = ") {
            saw_reason = true;
            continue;
        }
        if trimmed == ")]" {
            continue;
        }
        if lint_name_fragment(trimmed) {
            continue;
        }
        return false;
    }

    saw_allow && saw_reason
}

fn lint_name_fragment(line: &str) -> bool {
    let lint = line.trim_end_matches(',');
    lint == "dead_code"
        || lint == "unused"
        || lint.starts_with("unused_")
        || lint.starts_with("clippy::")
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
    let mut msg = String::from("found secret-shaped fixtures:\n");
    for hit in &offenders {
        msg.push_str(&format!(
            "\n  {}\n    kind: {}\n    fix:  {}\n",
            hit.rel_path, hit.kind, hit.suggestion
        ));
    }
    bail!("{msg}");
}

struct BlobHit {
    rel_path: String,
    kind: &'static str,
    suggestion: &'static str,
}

/// Scan for blobs and emit migration recipes (read-only).
fn no_blob_migrate() -> Result<()> {
    let offenders = find_secret_blobs()?;
    if offenders.is_empty() {
        println!("no-blob: no secret-shaped fixtures found");
        return Ok(());
    }

    println!(
        "no-blob migrate: found {} secret-shaped fixture(s)",
        offenders.len()
    );
    println!();
    println!("# Migration Recipe");
    println!();
    for (i, hit) in offenders.iter().enumerate() {
        println!("## {}. {}", i + 1, hit.rel_path);
        println!();
        println!("  Detected: {}", hit.kind);
        println!();
        println!("  Suggested replacement:");
        println!("  ```rust");
        println!("  {}", hit.suggestion);
        println!("  ```");
        println!();
        println!("---\n");
    }

    println!("# Next Steps");
    println!();
    println!("1. Identify the fixture type (see suggested replacement above)");
    println!("2. Replace static file with runtime generation using uselesskey");
    println!(
        "3. Remove the static file: `git rm {}`",
        offenders
            .iter()
            .map(|h| h.rel_path.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("4. Re-run `cargo xtask no-blob` to verify");
    println!();
    println!("For more details, see: https://docs.rs/uselesskey");

    Ok(())
}

fn find_secret_blobs() -> Result<Vec<BlobHit>> {
    let mut offenders = Vec::new();
    let root = Path::new(".");
    walk_for_blobs(root, root, &mut offenders)?;
    Ok(offenders)
}

fn walk_for_blobs(root: &Path, dir: &Path, offenders: &mut Vec<BlobHit>) -> Result<()> {
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
            if let Some((kind, suggestion)) = detect_and_classify(&path)? {
                offenders.push(BlobHit {
                    rel_path: rel_str,
                    kind,
                    suggestion,
                });
            }
        }
    }
    Ok(())
}

/// Read the file header once and use it for both detection and classification.
/// Returns `Some((kind, suggestion))` if the file is a secret-shaped blob.
fn detect_and_classify(path: &Path) -> Result<Option<(&'static str, &'static str)>> {
    let ext_hit = is_secret_extension(path);
    let header = read_file_header(path)?;
    let allow_secret_markers = !is_source_like_extension(path);

    if let Some(hit) = classify_by_content(&header, allow_secret_markers) {
        return Ok(Some(hit));
    }

    if ext_hit {
        return Ok(Some(classify_by_extension(path)));
    }

    if allow_secret_markers && has_secret_markers(&header) {
        return Ok(Some(classify_by_extension(path)));
    }

    Ok(None)
}

/// Read a bounded prefix of a file for marker detection.
fn read_file_header(path: &Path) -> Result<Vec<u8>> {
    const HEADER_SIZE: u64 = 64 * 1024;
    let file = fs::File::open(path).with_context(|| format!("failed to read {path:?}"))?;
    let mut buf = Vec::new();
    file.take(HEADER_SIZE).read_to_end(&mut buf)?;
    Ok(buf)
}

fn is_source_like_extension(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(ext.as_str(), "rs" | "feature" | "md" | "toml" | "snap")
}

/// Check if a file header contains PEM, SSH, or other secret markers.
fn has_secret_markers(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    if text.contains("-----BEGIN") && text.contains("-----END") {
        return true;
    }
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("ssh-rsa ")
            || trimmed.starts_with("ssh-ed25519 ")
            || trimmed.starts_with("ssh-dss ")
            || trimmed.starts_with("ecdsa-sha2-")
        {
            return true;
        }
    }
    false
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
    if matches!(
        ext.as_str(),
        "pem" | "der" | "key" | "crt" | "cer" | "p12" | "pfx" | "pub"
    ) {
        return true;
    }
    // SSH private key filenames: id_rsa, id_ed25519, id_ecdsa (no extension)
    let stem = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(stem.as_str(), "id_rsa" | "id_ed25519" | "id_ecdsa")
}

/// Backward-compatible wrapper used by tests. Delegates to `read_file_header` + `has_secret_markers`.
#[cfg(test)]
fn contains_pem_markers(path: &Path) -> Result<bool> {
    if is_source_like_extension(path) {
        return Ok(false);
    }
    let header = read_file_header(path)?;
    Ok(has_secret_markers(&header))
}

/// Classify a secret-shaped blob by content (first 1024 bytes) then extension.
#[cfg(test)]
fn classify_blob(path: &Path) -> (&'static str, &'static str) {
    let header = fs::read(path)
        .ok()
        .map(|bytes| bytes.into_iter().take(1024).collect::<Vec<u8>>());

    if let Some(ref bytes) = header
        && let Some(hit) = classify_by_content(bytes, !is_source_like_extension(path))
    {
        return hit;
    }

    classify_by_extension(path)
}

fn classify_by_content(
    bytes: &[u8],
    allow_secret_markers: bool,
) -> Option<(&'static str, &'static str)> {
    let text = String::from_utf8_lossy(bytes);

    if allow_secret_markers {
        // PEM header detection
        if let Some(pem_start) = text.find("-----BEGIN ") {
            let after = &text[pem_start + 11..];
            if let Some(end) = after.find("-----") {
                let label = after[..end].trim();
                return Some(classify_pem_label(label));
            }
        }

        // SSH public key prefixes (check per-line, not just file start)
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("ssh-rsa ")
                || trimmed.starts_with("ssh-ed25519 ")
                || trimmed.starts_with("ssh-dss ")
                || trimmed.starts_with("ecdsa-sha2-")
            {
                return Some((
                    "SSH public key",
                    "fx.ssh_key(\"key\", SshSpec::ed25519()).authorized_key_line()",
                ));
            }
        }
    }

    if find_jwt_candidate(&text).is_some() {
        return Some((
            "JWT token",
            "fx.token(\"auth\", TokenSpec::oauth_access_token())",
        ));
    }

    None
}

fn find_jwt_candidate(text: &str) -> Option<&str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '=')))
        .find(|candidate| looks_like_jwt(candidate))
}

fn classify_pem_label(label: &str) -> (&'static str, &'static str) {
    match label {
        "RSA PRIVATE KEY" => (
            "RSA private key (PKCS#1)",
            "fx.rsa(\"key\", RsaSpec::rs256()).private_key_pkcs1_pem()",
        ),
        "PRIVATE KEY" => (
            "Private key (PKCS#8)",
            "fx.rsa(\"key\", RsaSpec::rs256()).private_key_pem()  -- or ecdsa/ed25519 variant",
        ),
        "EC PRIVATE KEY" => (
            "EC private key (SEC1)",
            "fx.ecdsa(\"key\", EcdsaSpec::es256()).private_key_sec1_pem()",
        ),
        "PUBLIC KEY" => (
            "Public key (SPKI)",
            "fx.rsa(\"key\", RsaSpec::rs256()).public_key_pem()  -- or ecdsa/ed25519 variant",
        ),
        "RSA PUBLIC KEY" => (
            "RSA public key (PKCS#1)",
            "fx.rsa(\"key\", RsaSpec::rs256()).public_key_pkcs1_pem()",
        ),
        "CERTIFICATE" => (
            "X.509 certificate",
            "fx.x509_self_signed(\"ca\", X509Spec::default()).cert_pem()",
        ),
        "CERTIFICATE REQUEST" => (
            "X.509 CSR",
            "fx.x509_self_signed(\"ca\", X509Spec::default()) -- CSR not yet supported; use cert",
        ),
        "ENCRYPTED PRIVATE KEY" => (
            "Encrypted private key (PKCS#8)",
            "fx.rsa(\"key\", RsaSpec::rs256()).private_key_pem()  -- uselesskey generates unencrypted keys",
        ),
        "OPENSSH PRIVATE KEY" => (
            "OpenSSH private key",
            "fx.ssh_key(\"key\", SshSpec::ed25519()).private_key_openssh()",
        ),
        "PGP PUBLIC KEY BLOCK" | "PGP PRIVATE KEY BLOCK" => {
            ("PGP key block", "fx.pgp(\"key\", PgpSpec::rsa()).armored()")
        }
        "PGP MESSAGE" => (
            "PGP message",
            "fx.pgp(\"key\", PgpSpec::rsa()) -- generate key, then encrypt test data",
        ),
        "PGP SIGNATURE" => (
            "PGP signature",
            "fx.pgp(\"key\", PgpSpec::rsa()) -- generate key, then sign test data",
        ),
        _ => (
            "Unknown PEM type",
            "Delete the file and use the appropriate uselesskey fixture API",
        ),
    }
}

fn looks_like_jwt(s: &str) -> bool {
    let mut parts = s.split('.');
    let (Some(header), Some(payload), Some(signature)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }

    if !is_jwt_signature_segment(signature) {
        return false;
    }

    let header = decode_jwt_json_segment(header);
    let payload = decode_jwt_json_segment(payload);
    let (Some(header), Some(payload)) = (header, payload) else {
        return false;
    };

    header.is_object()
        && payload.is_object()
        && header
            .as_object()
            .is_some_and(|header| header.contains_key("alg") || header.contains_key("enc"))
}

fn decode_jwt_json_segment(segment: &str) -> Option<serde_json::Value> {
    let decoded = decode_jwt_segment(segment)?;
    serde_json::from_slice(&decoded).ok()
}

fn decode_jwt_segment(segment: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .or_else(|_| URL_SAFE.decode(segment))
        .ok()
}

fn is_jwt_signature_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() >= 8
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '='))
}

fn classify_by_extension(path: &Path) -> (&'static str, &'static str) {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "pem" => (
            "PEM file (unknown type)",
            "Read the PEM header to determine key type, then use the matching uselesskey API",
        ),
        "der" => (
            "DER-encoded file",
            "fx.rsa(\"key\", RsaSpec::rs256()).private_key_der()  -- or .public_key_der(), .cert_der()",
        ),
        "key" => (
            "Key file",
            "fx.rsa(\"key\", RsaSpec::rs256()).private_key_pem()  -- or ecdsa/ed25519 variant",
        ),
        "crt" | "cer" => (
            "Certificate file",
            "fx.x509_self_signed(\"ca\", X509Spec::default()).cert_pem()",
        ),
        "p12" | "pfx" => (
            "PKCS#12 bundle",
            "fx.x509_self_signed(\"ca\", X509Spec::default()) for cert/key material, then build PKCS#12 at runtime",
        ),
        "pub" => (
            "Public key file",
            "fx.rsa(\"key\", RsaSpec::rs256()).public_key_pem()  -- or ecdsa/ed25519 variant",
        ),
        _ => (
            "Secret-shaped file",
            "Delete the file and use the appropriate uselesskey fixture API",
        ),
    }
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
        let mut docstring_fence: Option<&str> = None;
        for line in content.lines() {
            let trimmed = line.trim_start();
            if let Some(fence) = docstring_fence {
                if trimmed.starts_with(fence) {
                    docstring_fence = None;
                }
                continue;
            }
            if trimmed.starts_with("\"\"\"") {
                docstring_fence = Some("\"\"\"");
                continue;
            }
            if trimmed.starts_with("```") {
                docstring_fence = Some("```");
                continue;
            }
            if trimmed.starts_with('#') {
                continue;
            }
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
    runner.step("public-surface", None, || {
        public_surface::public_surface_cmd(PUBLISH_CRATES)
    })?;
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

const DEFAULT_POST_EDIT_CHECK: &str =
    "cargo check --quiet --message-format=short 2>&1 | head -20 || true";

fn agent_swarm_setup(post_edit_check: Option<String>) -> Result<()> {
    let source_dir = workspace_root_path()
        .join(".claude")
        .join("agent-swarm-workflow")
        .join("slash-commands");
    let repo_root = env::current_dir().context("failed to resolve current directory")?;
    agent_swarm_setup_at(&source_dir, &repo_root, post_edit_check)
}

fn agent_swarm_setup_at(
    slash_command_source: &Path,
    repo_root: &Path,
    post_edit_check: Option<String>,
) -> Result<()> {
    if !slash_command_source.is_dir() {
        bail!(
            "cannot find slash-commands directory at {}",
            slash_command_source.display()
        );
    }

    let claude_dir = repo_root.join(".claude");
    let command_dir = claude_dir.join("commands");
    let settings_path = claude_dir.join("settings.json");
    let post_edit_check = post_edit_check
        .or_else(|| env::var("POST_EDIT_CHECK").ok())
        .unwrap_or_else(|| DEFAULT_POST_EDIT_CHECK.to_string());

    println!("Creating .claude/commands/ ...");
    fs::create_dir_all(&command_dir)
        .with_context(|| format!("failed to create {}", command_dir.display()))?;

    println!("Copying slash command templates ...");
    let mut copied_any = false;
    let mut templates = fs::read_dir(slash_command_source)
        .with_context(|| format!("failed to read {}", slash_command_source.display()))?
        .map(|entry| {
            entry.map(|entry| entry.path()).with_context(|| {
                format!(
                    "failed to read entry from {}",
                    slash_command_source.display()
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    templates.retain(|path| path.extension().and_then(|ext| ext.to_str()) == Some("md"));
    templates.sort();

    for source_path in templates {
        let file_name = source_path
            .file_name()
            .context("slash command template missing file name")?;
        let display_name = file_name.to_string_lossy();
        let destination = command_dir.join(file_name);
        if destination.exists() {
            println!("  SKIP: {display_name} (already exists, not overwriting)");
        } else {
            fs::copy(&source_path, &destination).with_context(|| {
                format!(
                    "failed to copy {} to {}",
                    source_path.display(),
                    destination.display()
                )
            })?;
            println!("  COPY: {display_name}");
            copied_any = true;
        }
    }

    if !copied_any {
        println!("  No new slash command templates copied.");
    }

    if settings_path.exists() {
        println!();
        println!("SKIP: .claude/settings.json already exists.");
        println!("      Review it manually and add PostToolUse hooks if needed.");
        println!("      Recommended hook command: {post_edit_check}");
    } else {
        println!();
        println!("Creating .claude/settings.json ...");
        let settings = serde_json::json!({
            "hooks": {
                "PostToolUse": [
                    {
                        "matcher": "Edit|Write|NotebookEdit",
                        "hooks": [
                            {
                                "type": "command",
                                "command": post_edit_check.clone(),
                            }
                        ]
                    }
                ]
            }
        });
        write_json_pretty(&settings_path, &settings)?;
        println!("  Created with PostToolUse hook: {post_edit_check}");
    }

    print_agent_swarm_next_steps(&command_dir);
    Ok(())
}

fn print_agent_swarm_next_steps(command_dir: &Path) {
    println!();
    println!("========================================================================");
    println!(" Agent Swarm Workflow -- Setup Complete");
    println!("========================================================================");
    println!();
    println!(" Files created in: {}/", command_dir.display());
    println!();
    println!(" Next steps:");
    println!();
    println!("   1. Edit the slash commands in .claude/commands/ to replace");
    println!("      placeholder variables with your project's commands:");
    println!();
    println!("        $TEST_CMD   -- your test runner       (e.g., cargo test, pytest)");
    println!("        $LINT_CMD   -- your linter             (e.g., cargo clippy, ruff)");
    println!("        $FMT_CMD    -- your formatter           (e.g., cargo fmt, prettier)");
    println!("        $BUILD_CMD  -- your build command       (e.g., cargo build, npm build)");
    println!("        $CHECK_CMD  -- fast type/compile check  (e.g., cargo check, tsc)");
    println!("        $GATE_CMD   -- full CI gate command     (e.g., just ci-gate, make ci)");
    println!();
    println!("   2. Review .claude/settings.json and adjust the PostToolUse hook");
    println!("      command if needed.");
    println!();
    println!("   3. Start Claude Code and try:");
    println!("        /wave test-coverage     -- launch a test coverage wave");
    println!("        /tdd-fix <bug>          -- fix a bug with TDD");
    println!("        /bulk-pr                -- PR all worktrees at once");
    println!();
    println!("   4. (Optional) Add .claude/ to .gitignore if you do not want");
    println!("      to check in agent configuration, or commit it to share");
    println!("      with your team.");
    println!();
    println!("   5. Read .claude/agent-swarm-workflow/agent-patterns.md");
    println!("      for tips on effective agent dispatch.");
    println!();
    println!("========================================================================");
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

    fn run_git<const N: usize>(args: [&str; N]) {
        let status = Command::new("git")
            .args(args)
            .status()
            .unwrap_or_else(|err| panic!("failed to run git {}: {err}", args.join(" ")));
        assert!(status.success(), "git {} failed", args.join(" "));
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

    fn sample_jwt() -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"1234567890"}"#);
        let signature = URL_SAFE_NO_PAD.encode(b"signature");
        format!("{header}.{payload}.{signature}")
    }

    #[test]
    fn agent_swarm_setup_copies_templates_and_writes_settings() {
        let source = tempfile::tempdir().expect("source tempdir");
        let repo = tempfile::tempdir().expect("repo tempdir");
        fs::write(source.path().join("wave.md"), "# Wave\n").expect("write template");
        fs::write(source.path().join("ignored.txt"), "ignore\n").expect("write non-template");

        agent_swarm_setup_at(
            source.path(),
            repo.path(),
            Some("cargo check --quiet".to_string()),
        )
        .expect("agent swarm setup should succeed");

        assert_eq!(
            fs::read_to_string(repo.path().join(".claude/commands/wave.md"))
                .expect("read copied template"),
            "# Wave\n"
        );
        assert!(!repo.path().join(".claude/commands/ignored.txt").exists());

        let settings =
            fs::read_to_string(repo.path().join(".claude/settings.json")).expect("read settings");
        assert!(settings.contains("PostToolUse"));
        assert!(settings.contains("cargo check --quiet"));
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
    fn ripr_markdown_summarizes_counts_and_claim_boundary() {
        let json = serde_json::json!({
            "summary": {
                "changed_rust_files": 1,
                "probes": 2,
                "findings": 1,
                "exposed": 1,
                "weakly_exposed": 0,
                "reachable_unrevealed": 0,
                "no_static_path": 0,
                "infection_unknown": 0,
                "propagation_unknown": 0,
                "static_unknown": 0
            },
            "findings": [{
                "id": "finding-1",
                "file": "crates/example/src/lib.rs",
                "line": 42,
                "status": "exposed",
                "message": "assertion appears to reveal changed behavior"
            }]
        });

        let rendered = render_ripr_markdown("origin/main", &json);

        assert!(rendered.contains("Status: advisory"));
        assert!(rendered.contains("| changed rust files | 1 |"));
        assert!(rendered.contains("`finding-1` at `crates/example/src/lib.rs:42`"));
        assert!(rendered.contains("ripr does not run mutants"));
    }

    #[test]
    fn ripr_skipped_artifacts_record_reason() {
        let dir = tempfile::tempdir().expect("tempdir");

        write_ripr_skipped_artifacts(dir.path(), "origin/main", "ripr missing")
            .expect("write skipped artifacts");

        let json: serde_json::Value =
            read_json_file(&dir.path().join("repo-exposure.json")).expect("read skip json");
        assert_eq!(json["status"], "skipped");
        assert_eq!(json["base"], "origin/main");
        assert_eq!(json["reason"], "ripr missing");

        let summary =
            fs::read_to_string(dir.path().join("summary.md")).expect("read summary markdown");
        assert!(summary.contains("Status: skipped"));
        assert!(summary.contains("ripr missing"));
        assert!(dir.path().join("review.md").exists());
    }

    #[test]
    fn impacted_evidence_routes_ripr_summary_gap_to_changed_owner() {
        let paths = vec!["crates/uselesskey-token/src/srp/shape.rs".to_string()];
        let ripr = serde_json::json!({
            "summary": {
                "reachable_unrevealed": 1,
                "no_static_path": 0
            },
            "findings": []
        });

        let report = impacted_evidence_report_with_ripr("origin/main", &paths, Some(&ripr));

        assert!(report.ripr.requires_targeted_evidence);
        assert_eq!(report.ripr.severe_gap_count, 1);
        assert_eq!(
            report.ripr.owner_crates,
            vec!["uselesskey-token".to_string()]
        );
        assert_eq!(
            report.ripr.reasons,
            vec!["reachable-unrevealed".to_string()]
        );
        assert!(
            report
                .ripr
                .suggested_actions
                .contains(&"Run cargo xtask mutants-pr --changed".to_string())
        );
    }

    #[test]
    fn impacted_evidence_routes_ripr_severe_finding_to_public_owner() {
        let paths = vec!["docs/ci/test-evidence-lanes.md".to_string()];
        let ripr = serde_json::json!({
            "summary": {
                "reachable_unrevealed": 0,
                "no_static_path": 0
            },
            "findings": [{
                "id": "finding-1",
                "file": "crates/uselesskey-cli/src/bundle.rs",
                "severity": "critical",
                "message": "bundle metadata has weak revealability"
            }]
        });

        let report = impacted_evidence_report_with_ripr("origin/main", &paths, Some(&ripr));

        assert!(report.ripr.requires_targeted_evidence);
        assert_eq!(report.ripr.severe_gap_count, 1);
        assert_eq!(report.ripr.owner_crates, vec!["uselesskey-cli".to_string()]);
        assert_eq!(report.ripr.reasons, vec!["severe-finding".to_string()]);
    }

    #[test]
    fn impacted_evidence_keeps_ripr_severe_docs_gap_advisory_without_owner() {
        let paths = vec!["docs/ci/test-evidence-lanes.md".to_string()];
        let ripr = serde_json::json!({
            "summary": {
                "reachable_unrevealed": 1,
                "no_static_path": 0
            },
            "findings": []
        });

        let report = impacted_evidence_report_with_ripr("origin/main", &paths, Some(&ripr));

        assert!(!report.ripr.requires_targeted_evidence);
        assert_eq!(report.ripr.severe_gap_count, 1);
        assert!(report.ripr.owner_crates.is_empty());
        assert!(report.ripr.suggested_actions.is_empty());
    }

    #[test]
    fn impacted_evidence_core_derivation_requires_mutation() {
        let paths = vec![
            "crates/uselesskey-core/src/srp/hash.rs".to_string(),
            "docs/ci/test-evidence-lanes.md".to_string(),
        ];

        let report = impacted_evidence_report("origin/main", &paths);

        assert_eq!(report.schema_version, 1);
        assert_eq!(report.base, "origin/main");
        assert_eq!(report.owner_crates, vec!["uselesskey-core".to_string()]);
        assert!(report.requires_targeted_mutation);
        assert_eq!(report.reasons, vec!["core-derivation".to_string()]);
    }

    #[test]
    fn impacted_evidence_maps_owner_internals_and_adapters() {
        let paths = vec![
            "crates/uselesskey-x509/src/srp/spec/chain_spec.rs".to_string(),
            "crates/uselesskey-rustls/src/config.rs".to_string(),
            "crates/uselesskey-core-jwk/src/lib.rs".to_string(),
        ];

        let report = impacted_evidence_report("origin/main", &paths);

        assert_eq!(
            report.owner_crates,
            vec![
                "uselesskey-jwk".to_string(),
                "uselesskey-rustls".to_string(),
                "uselesskey-x509".to_string()
            ]
        );
        assert!(report.requires_targeted_mutation);
        assert_eq!(
            report.reasons,
            vec![
                "adapter-conversion".to_string(),
                "compatibility-shim".to_string(),
                "x509-owner-internal".to_string()
            ]
        );
    }

    #[test]
    fn impacted_evidence_docs_only_has_no_owner() {
        let paths = vec!["docs/ci/test-evidence-lanes.md".to_string()];

        let report = impacted_evidence_report("origin/main", &paths);

        assert!(report.owner_crates.is_empty());
        assert!(!report.requires_targeted_mutation);
        assert!(report.reasons.is_empty());
    }

    #[test]
    fn impacted_evidence_normalizes_windows_paths() {
        let paths = vec!["crates\\uselesskey-token\\src\\srp\\shape.rs".to_string()];

        let report = impacted_evidence_report("origin/main", &paths);

        assert_eq!(
            report.changed_paths[0],
            "crates/uselesskey-token/src/srp/shape.rs"
        );
        assert_eq!(report.owner_crates, vec!["uselesskey-token".to_string()]);
        assert!(report.requires_targeted_mutation);
        assert_eq!(report.reasons, vec!["token-owner-internal".to_string()]);
    }

    #[test]
    fn mutation_target_owners_use_impacted_evidence() {
        let paths = vec![
            "crates/uselesskey-token/src/srp/shape.rs".to_string(),
            "crates/uselesskey-core-token/src/lib.rs".to_string(),
            "docs/ci/test-evidence-lanes.md".to_string(),
        ];

        assert_eq!(
            mutation_target_owners(&paths),
            vec!["uselesskey-token".to_string()]
        );
    }

    #[test]
    fn mutation_target_owners_skip_docs_and_shims() {
        let paths = vec![
            "crates/uselesskey-core-jwk/src/lib.rs".to_string(),
            "docs/ci/test-evidence-lanes.md".to_string(),
        ];

        assert!(mutation_target_owners(&paths).is_empty());
    }

    #[test]
    fn mutation_target_paths_follow_owner_mapping() {
        let paths = vec![
            "crates/uselesskey-rustls/src/config.rs".to_string(),
            "crates/uselesskey-core-rustls-pki/src/lib.rs".to_string(),
            "crates/uselesskey-x509/src/srp/spec/chain_spec.rs".to_string(),
        ];

        assert_eq!(
            mutation_target_paths_for_owner("uselesskey-rustls", &paths),
            vec!["crates/uselesskey-rustls/src/config.rs".to_string()]
        );
        assert_eq!(
            mutation_target_paths_for_owner("uselesskey-x509", &paths),
            vec!["crates/uselesskey-x509/src/srp/spec/chain_spec.rs".to_string()]
        );
    }

    #[test]
    fn mutation_nightly_public_scope_uses_public_owner_crates() {
        let crates = mutation_nightly_crates(MutationNightlyScope::Public, None).unwrap();

        assert!(crates.contains(&"uselesskey-core".to_string()));
        assert!(crates.contains(&"uselesskey-jwk".to_string()));
        assert!(crates.contains(&"uselesskey-token".to_string()));
        assert!(crates.contains(&"uselesskey-x509".to_string()));
        assert!(crates.contains(&"uselesskey-cli".to_string()));
        assert!(!crates.contains(&"uselesskey-core-jwk".to_string()));
    }

    #[test]
    fn mutation_nightly_adapter_scope_uses_adapter_crates() {
        let crates = mutation_nightly_crates(MutationNightlyScope::Adapters, None).unwrap();

        assert_eq!(
            crates,
            vec![
                "uselesskey-jsonwebtoken".to_string(),
                "uselesskey-rustls".to_string(),
                "uselesskey-tonic".to_string(),
                "uselesskey-axum".to_string(),
                "uselesskey-ring".to_string(),
                "uselesskey-rustcrypto".to_string(),
                "uselesskey-aws-lc-rs".to_string(),
            ]
        );
    }

    #[test]
    fn mutation_nightly_crate_scope_requires_known_crate() {
        assert_eq!(
            mutation_nightly_crates(MutationNightlyScope::Crate, Some("uselesskey-token")).unwrap(),
            vec!["uselesskey-token".to_string()]
        );
        assert!(mutation_nightly_crates(MutationNightlyScope::Crate, None).is_err());
        assert!(mutation_nightly_crates(MutationNightlyScope::Crate, Some("not-a-crate")).is_err());
    }

    #[test]
    fn mutation_survivor_ledger_reports_expired_and_counts() {
        let ledger: MutationSurvivorLedger = toml::from_str(
            r#"
schema_version = "0.1"

[[survivor]]
crate = "uselesskey-x509"
function = "encode_optional_not_before"
classification = "pending-test"
owner = "fixtures/x509"
reason = "Needs a focused stable-bytes assertion."
expires = "2026-01-01"
issue = "https://github.com/EffortlessMetrics/uselesskey/issues/1"

[[survivor]]
crate = "uselesskey-token"
function = "near_miss_api_key"
classification = "equivalent"
owner = "fixtures/token"
reason = "Equivalent mutant under current parser boundary."
expires = "2026-12-01"
"#,
        )
        .unwrap();
        let report = mutation_survivor_report_from_ledger(
            Path::new("policy/mutation-survivors.toml"),
            ledger,
            chrono::NaiveDate::from_ymd_opt(2026, 5, 9).unwrap(),
        )
        .unwrap();

        assert_eq!(report.summary.known_survivors, 2);
        assert_eq!(report.summary.expired_classifications, 1);
        assert_eq!(report.summary.pending_tests, 1);
        assert_eq!(report.summary.equivalent_mutants, 1);
        assert_eq!(
            report.expired_classifications[0].function,
            "encode_optional_not_before"
        );
    }

    #[test]
    fn mutation_survivor_ledger_rejects_unknown_classification() {
        let ledger = MutationSurvivorLedger {
            schema_version: Some("0.1".to_string()),
            survivor: vec![MutationSurvivorEntry {
                crate_name: "uselesskey-token".to_string(),
                function: "token_shape".to_string(),
                classification: "ignored".to_string(),
                owner: "fixtures/token".to_string(),
                reason: "unsupported classification should fail".to_string(),
                expires: "2026-12-01".to_string(),
                issue: None,
            }],
        };

        assert!(
            mutation_survivor_report_from_ledger(
                Path::new("policy/mutation-survivors.toml"),
                ledger,
                chrono::NaiveDate::from_ymd_opt(2026, 5, 9).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn mutation_evidence_counts_cargo_mutants_outcomes() {
        let outcomes: CargoMutantsOutcomes = serde_json::from_str(
            r#"
{
  "outcomes": [
    { "scenario": "Baseline", "summary": "Success" },
    {
      "scenario": { "Mutant": { "name": "caught" } },
      "summary": "CaughtMutant"
    },
    {
      "scenario": { "Mutant": { "name": "missed" } },
      "summary": "MissedMutant"
    },
    {
      "scenario": { "Mutant": { "name": "unviable" } },
      "summary": "Unviable"
    },
    {
      "scenario": { "Mutant": { "name": "timeout" } },
      "summary": "Timeout"
    },
    {
      "scenario": { "Mutant": { "name": "unknown" } },
      "summary": "Unknown"
    }
  ]
}
"#,
        )
        .unwrap();
        let result = mutation_evidence_result_from_outcomes(
            "uselesskey-token",
            Some("target/mutation/runs/uselesskey-token/outcomes.json".to_string()),
            &outcomes,
        );

        assert_eq!(result.mutants_found, 5);
        assert_eq!(result.caught, 1);
        assert_eq!(result.survived, 1);
        assert_eq!(result.unviable, 1);
        assert_eq!(result.timeouts, 1);
        assert_eq!(result.other, 1);
        assert_eq!(result.status, "completed");
    }

    #[test]
    fn planned_mutation_results_mark_crates_as_planned() {
        let results = planned_mutation_results(&[
            "uselesskey-core".to_string(),
            "uselesskey-token".to_string(),
        ]);

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|result| result.status == "planned"));
        assert!(results.iter().all(|result| result.mutants_found == 0));
    }

    #[test]
    fn base_ref_candidates_include_local_branch_for_origin_ref() {
        assert_eq!(
            base_ref_candidates("origin/main"),
            vec!["origin/main".to_string(), "main".to_string()]
        );
    }

    #[test]
    fn base_ref_candidates_keep_non_origin_ref_as_is() {
        assert_eq!(
            base_ref_candidates("upstream/trunk"),
            vec!["upstream/trunk".to_string()]
        );
    }

    #[test]
    fn git_changed_files_uses_local_branch_when_origin_ref_missing() {
        let _cwd_lock = CWD_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        let _cwd = CwdGuard::new(dir.path());

        run_git(["init"]);
        run_git(["config", "user.email", "agent@example.com"]);
        run_git(["config", "user.name", "Agent"]);

        fs::write("tracked.txt", "base\n").expect("write base");
        run_git(["add", "tracked.txt"]);
        run_git(["commit", "-m", "initial"]);
        run_git(["branch", "-M", "main"]);
        run_git(["checkout", "-b", "feature"]);

        fs::write("first.txt", "one\n").expect("write first");
        run_git(["add", "first.txt"]);
        run_git(["commit", "-m", "first"]);
        fs::write("second.txt", "two\n").expect("write second");
        run_git(["add", "second.txt"]);
        run_git(["commit", "-m", "second"]);

        let mut changed =
            git_changed_files("origin/main").expect("local main fallback should succeed");
        changed.sort();
        assert_eq!(
            changed,
            vec!["first.txt".to_string(), "second.txt".to_string()]
        );
    }

    #[test]
    fn git_changed_files_returns_empty_without_base_ref_or_parent() {
        let _cwd_lock = CWD_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        let _cwd = CwdGuard::new(dir.path());

        run_git(["init"]);
        run_git(["config", "user.email", "agent@example.com"]);
        run_git(["config", "user.name", "Agent"]);
        fs::write("tracked.txt", "v1\n").expect("write tracked");
        run_git(["add", "tracked.txt"]);
        run_git(["commit", "-m", "initial"]);

        let changed = git_changed_files("origin/main").expect("missing refs should not fail");
        assert!(changed.is_empty(), "expected no changes, got {changed:?}");
    }

    #[test]
    fn diff_is_lint_allow_reason_only_accepts_multiline_reason() {
        let diff = "\
diff --git a/crates/example/src/lib.rs b/crates/example/src/lib.rs
index 1111111..2222222 100644
--- a/crates/example/src/lib.rs
+++ b/crates/example/src/lib.rs
@@ -1 +1,4 @@
-#[allow(dead_code)]
+#[allow(
+    dead_code,
+    reason = \"reserved for a feature-gated fixture path\"
+)]
";

        assert!(diff_is_lint_allow_reason_only(diff));
    }

    #[test]
    fn diff_is_lint_allow_reason_only_accepts_single_line_reason() {
        let diff = "\
diff --git a/crates/example/src/lib.rs b/crates/example/src/lib.rs
index 1111111..2222222 100644
--- a/crates/example/src/lib.rs
+++ b/crates/example/src/lib.rs
@@ -1 +1 @@
-#[allow(clippy::clone_on_copy)]
+#[allow(clippy::clone_on_copy, reason = \"explicit clone is under test\")]
";

        assert!(diff_is_lint_allow_reason_only(diff));
    }

    #[test]
    fn diff_is_lint_allow_reason_only_rejects_bare_allow_change() {
        let diff = "\
diff --git a/crates/example/src/lib.rs b/crates/example/src/lib.rs
index 1111111..2222222 100644
--- a/crates/example/src/lib.rs
+++ b/crates/example/src/lib.rs
@@ -1 +1 @@
-#[allow(dead_code)]
+#[allow(dead_code)]
";

        assert!(!diff_is_lint_allow_reason_only(diff));
    }

    #[test]
    fn diff_is_lint_allow_reason_only_rejects_behavior_change() {
        let diff = "\
diff --git a/crates/example/src/lib.rs b/crates/example/src/lib.rs
index 1111111..2222222 100644
--- a/crates/example/src/lib.rs
+++ b/crates/example/src/lib.rs
@@ -1 +1,4 @@
-#[allow(dead_code)]
+#[allow(
+    dead_code,
+    reason = \"reserved for a feature-gated fixture path\"
+)]
@@ -10 +13 @@
-let timeout = 20;
+let timeout = 40;
";

        assert!(!diff_is_lint_allow_reason_only(diff));
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

    // ── no-blob content detection tests ──────────────────────────────

    #[test]
    fn test_is_secret_extension_ssh_keys() {
        // SSH key filenames without extension
        assert!(is_secret_extension(Path::new("id_rsa")));
        assert!(is_secret_extension(Path::new("id_ed25519")));
        assert!(is_secret_extension(Path::new("id_ecdsa")));
        // .pub files
        assert!(is_secret_extension(Path::new("id_rsa.pub")));
    }

    #[test]
    fn test_contains_pem_markers_ssh_public_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ssh_pub = dir.path().join("key.txt");
        fs::write(&ssh_pub, "ssh-rsa AAAAB3NzaC1yc2EAAA... user@host\n").unwrap();
        assert!(contains_pem_markers(&ssh_pub).expect("read file"));

        let ssh_ed = dir.path().join("ed.txt");
        fs::write(
            &ssh_ed,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host\n",
        )
        .unwrap();
        assert!(contains_pem_markers(&ssh_ed).expect("read file"));

        // ssh-dss should also be detected
        let ssh_dss = dir.path().join("dss.txt");
        fs::write(&ssh_dss, "ssh-dss AAAAB3NzaC1kc3MAAA... user@host\n").unwrap();
        assert!(contains_pem_markers(&ssh_dss).expect("read file"));
    }

    #[test]
    fn test_classify_by_content_ssh_not_on_first_line() {
        // SSH key on a non-first line should still be classified as SSH, not fall
        // through to extension-based classification.
        let bytes = b"# authorized keys\nssh-rsa AAAAB3NzaC1yc2EAAA... user@host\n";
        let (kind, suggestion) = classify_by_content(bytes, true).expect("classify by content");
        assert_eq!(kind, "SSH public key");
        assert_eq!(
            suggestion,
            "fx.ssh_key(\"key\", SshSpec::ed25519()).authorized_key_line()"
        );
    }

    #[test]
    fn test_classify_blob_pem_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pem_file = dir.path().join("cert.txt");
        fs::write(
            &pem_file,
            "-----BEGIN CERTIFICATE-----\nbase64\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let (kind, _) = classify_blob(&pem_file);
        assert_eq!(kind, "X.509 certificate");
    }

    #[test]
    fn test_classify_blob_extension_fallback() {
        let dir = tempfile::tempdir().expect("tempdir");
        let der_file = dir.path().join("key.der");
        fs::write(&der_file, [0x00, 0x01, 0x02]).unwrap();
        let (kind, _) = classify_blob(&der_file);
        assert_eq!(kind, "DER-encoded file");
    }

    #[test]
    fn test_looks_like_jwt() {
        let jwt = sample_jwt();
        assert!(looks_like_jwt(&jwt));
        assert!(looks_like_jwt(
            format!("Bearer {jwt}")
                .split_whitespace()
                .nth(1)
                .expect("jwt token")
        ));
        assert!(!looks_like_jwt("abcd.efgh.ijkl"));
        assert!(!looks_like_jwt("not.a.jwt"));
        assert!(!looks_like_jwt("only-one-segment"));
        assert!(!looks_like_jwt("two.parts"));
    }

    #[test]
    fn test_classify_by_content_finds_embedded_jwt() {
        let bytes = format!(r#"{{"authorization":"Bearer {}"}}"#, sample_jwt());
        let (kind, suggestion) =
            classify_by_content(bytes.as_bytes(), false).expect("should classify jwt content");
        assert_eq!(kind, "JWT token");
        assert_eq!(
            suggestion,
            "fx.token(\"auth\", TokenSpec::oauth_access_token())"
        );
    }

    #[test]
    fn test_classify_pem_label_coverage() {
        assert_eq!(
            classify_pem_label("RSA PRIVATE KEY").0,
            "RSA private key (PKCS#1)"
        );
        assert_eq!(classify_pem_label("PRIVATE KEY").0, "Private key (PKCS#8)");
        assert_eq!(
            classify_pem_label("EC PRIVATE KEY").0,
            "EC private key (SEC1)"
        );
        assert_eq!(classify_pem_label("CERTIFICATE").0, "X.509 certificate");
        assert_eq!(
            classify_pem_label("OPENSSH PRIVATE KEY").0,
            "OpenSSH private key"
        );
        assert_eq!(
            classify_pem_label("OPENSSH PRIVATE KEY").1,
            "fx.ssh_key(\"key\", SshSpec::ed25519()).private_key_openssh()"
        );
        assert_eq!(
            classify_pem_label("RSA PRIVATE KEY").1,
            "fx.rsa(\"key\", RsaSpec::rs256()).private_key_pkcs1_pem()"
        );
        assert_eq!(
            classify_pem_label("PGP PUBLIC KEY BLOCK").0,
            "PGP key block"
        );
        assert_eq!(
            classify_pem_label("SOMETHING UNKNOWN").0,
            "Unknown PEM type"
        );
    }

    #[test]
    fn test_find_blobs_in_tempdir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();

        // tests/ with .pem (should be found)
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::write(root.join("tests/server.pem"), "fake pem content").unwrap();

        // tests/ with .key (should be found)
        fs::write(root.join("tests/private.key"), "fake key content").unwrap();

        // tests/ with .rs (should NOT be found)
        fs::write(root.join("tests/helper.rs"), "fn helper() {}").unwrap();

        // fixtures/ with .der (should be found)
        fs::create_dir_all(root.join("fixtures")).unwrap();
        fs::write(root.join("fixtures/cert.der"), [0x30, 0x82, 0x01]).unwrap();

        // fixtures/ with .txt containing PEM markers (should be found)
        fs::create_dir_all(root.join("fixtures/nested")).unwrap();
        fs::write(
            root.join("fixtures/nested/embedded.txt"),
            "-----BEGIN PRIVATE KEY-----\nbase64\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();

        // fixtures/ with .txt containing an embedded JWT beyond 8 KiB should be found
        let jwt = sample_jwt();
        let mut embedded = "x".repeat(10 * 1024);
        embedded.push_str("\n{\"token\":\"");
        embedded.push_str(&jwt);
        embedded.push_str("\"}\n");
        fs::write(root.join("fixtures/token.txt"), embedded).unwrap();

        // crates/foo/tests/ with .p12 (should be found)
        fs::create_dir_all(root.join("crates/foo/tests")).unwrap();
        fs::write(root.join("crates/foo/tests/store.p12"), "fake p12").unwrap();

        // src/ with .pem (should NOT be found)
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/secret.pem"), "fake pem").unwrap();

        // testdata/ with .crt (should be found)
        fs::create_dir_all(root.join("testdata")).unwrap();
        fs::write(root.join("testdata/ca.crt"), "fake cert").unwrap();

        // .git/ should be skipped
        fs::create_dir_all(root.join("tests/.git")).unwrap();
        fs::write(root.join("tests/.git/secret.pem"), "git internal").unwrap();

        // target/ should be skipped
        fs::create_dir_all(root.join("tests/target")).unwrap();
        fs::write(root.join("tests/target/leaked.key"), "build artifact").unwrap();

        let mut offenders = Vec::new();
        walk_for_blobs(root, root, &mut offenders).expect("walk_for_blobs");
        let paths: Vec<&str> = offenders.iter().map(|h| h.rel_path.as_str()).collect();

        assert!(
            paths.contains(&"tests/server.pem"),
            "should find .pem: {paths:?}"
        );
        assert!(
            paths.contains(&"tests/private.key"),
            "should find .key: {paths:?}"
        );
        assert!(
            paths.contains(&"fixtures/cert.der"),
            "should find .der: {paths:?}"
        );
        assert!(
            paths.contains(&"fixtures/nested/embedded.txt"),
            "should find PEM in .txt: {paths:?}"
        );
        assert!(
            paths.contains(&"fixtures/token.txt"),
            "should find JWT in .txt: {paths:?}"
        );
        let jwt_hit = offenders
            .iter()
            .find(|h| h.rel_path == "fixtures/token.txt")
            .expect("should report JWT hit");
        assert_eq!(jwt_hit.kind, "JWT token");
        assert!(
            paths.contains(&"crates/foo/tests/store.p12"),
            "should find .p12: {paths:?}"
        );
        assert!(
            paths.contains(&"testdata/ca.crt"),
            "should find .crt: {paths:?}"
        );

        assert!(
            !paths.iter().any(|o| o.contains("helper.rs")),
            "should not flag .rs: {paths:?}"
        );
        assert!(
            !paths.iter().any(|o| o.contains("src/")),
            "should not scan src/: {paths:?}"
        );
        assert!(
            !paths.iter().any(|o| o.contains(".git/")),
            "should skip .git/: {paths:?}"
        );
        assert!(
            !paths.iter().any(|o| o.contains("target/")),
            "should skip target/: {paths:?}"
        );

        assert_eq!(paths.len(), 7, "expected 7 offenders: {paths:?}");
    }

    #[test]
    fn test_walk_for_blobs_finds_jwt_in_source_like_fixture() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        fs::create_dir_all(root.join("fixtures")).unwrap();
        fs::write(
            root.join("fixtures/token.md"),
            format!("token = \"{}\"\n", sample_jwt()),
        )
        .unwrap();

        let mut offenders = Vec::new();
        walk_for_blobs(root, root, &mut offenders).expect("walk_for_blobs");

        let hit = offenders
            .iter()
            .find(|h| h.rel_path == "fixtures/token.md")
            .expect("should report JWT hit");
        assert_eq!(hit.kind, "JWT token");
    }

    #[test]
    fn perf_baseline_schema_is_valid() {
        let _cwd_lock = CWD_LOCK.lock().unwrap();
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or(Path::new(env!("CARGO_MANIFEST_DIR")));
        let _cwd = CwdGuard::new(workspace_root);
        let json =
            fs::read_to_string(workspace_path(PERF_BASELINE_PATH)).expect("read perf baseline");
        let parsed: PerfBaselineFile = serde_json::from_str(&json).expect("parse perf baseline");
        assert_eq!(parsed.version, 1);
        assert!(
            !parsed.entries.is_empty(),
            "expected at least one perf budget entry"
        );
        assert!(parsed.entries.iter().all(|e| !e.id.is_empty()));
    }

    #[test]
    fn release_evidence_dry_run_plans_release_gates() {
        let steps = release_evidence_steps();
        let names = steps.iter().map(|step| step.name).collect::<BTreeSet<_>>();

        for expected in [
            "public-surface",
            "docs-sync",
            "publish-preflight",
            "publish-check",
            "pr",
            "ripr-pr",
            "impacted-evidence",
            "no-blob",
            "examples-smoke",
            "scanner-safe-bundle-proof",
            "oidc-contract-pack-proof",
            "economics",
            "audit-surface",
            "perf",
            "mutants-nightly-public",
        ] {
            assert!(names.contains(expected), "missing release gate {expected}");
        }

        let receipt = release_evidence_receipt("0.7.0", true, &steps);
        assert_eq!(receipt.version, "0.7.0");
        assert!(receipt.dry_run);
        assert!(receipt.commands.iter().all(|cmd| cmd.status == "planned"));
        assert!(
            receipt
                .artifacts
                .contains(&"target/ripr/pr/summary.md".to_string())
        );
        assert!(receipt.artifacts.contains(
            &"target/release-evidence/scanner-safe/scanner-safe-bundle-proof.md".to_string()
        ));
        assert!(
            receipt
                .artifacts
                .contains(&"target/release-evidence/oidc/oidc-contract-pack-proof.md".to_string())
        );
        assert!(
            receipt
                .artifacts
                .contains(&"target/mutation/nightly-receipt.md".to_string())
        );
    }

    #[test]
    fn release_evidence_markdown_summarizes_commands_and_boundaries() {
        let steps = release_evidence_steps();
        let receipt = release_evidence_receipt("0.7.0", true, &steps);
        let markdown = render_release_evidence_markdown(&receipt);

        assert!(markdown.contains("Version: `0.7.0`"));
        assert!(markdown.contains("cargo xtask mutants-nightly --scope public"));
        assert!(
            markdown
                .contains("release evidence does not make uselesskey production key management")
        );
    }

    #[test]
    fn release_evidence_summary_highlights_public_promises() {
        let steps = release_evidence_steps();
        let receipt = release_evidence_receipt("0.7.0", true, &steps);
        let markdown = render_release_evidence_summary_markdown(&receipt);

        assert!(markdown.contains("Rust 1.95 scanner-safe fixture platform release"));
        assert!(markdown.contains("Package and publish proof"));
        assert!(markdown.contains("Scanner-safe bundle proof"));
        assert!(markdown.contains("OIDC contract-pack proof"));
        assert!(markdown.contains("Nightly mutation scope"));
        assert!(markdown.contains("Pending RC execution"));
        assert!(markdown.contains("not production key management"));
    }

    #[test]
    fn bundle_proof_receipt_enforces_scanner_safe_posture() {
        let manifest = scanner_safe_bundle_proof_manifest();
        let audit_surface = serde_json::json!({
            "scanner_safe": true,
            "runtime_material_count": 0,
        });
        let receipt = bundle_proof_receipt(BundleProofReceiptInput {
            profile: "scanner-safe",
            bundle_dir: Path::new("target/release-evidence/scanner-safe/bundle"),
            manifest_path: Path::new("target/release-evidence/scanner-safe/bundle/manifest.json"),
            inspect_summary_path: Path::new(
                "target/release-evidence/scanner-safe/inspect-bundle.txt",
            ),
            manifest: &manifest,
            audit_surface: &audit_surface,
            expected_artifacts: Vec::new(),
            commands: vec![ReleaseEvidenceCommandReceipt {
                name: "no-blob".to_string(),
                command: vec![
                    "cargo".to_string(),
                    "xtask".to_string(),
                    "no-blob".to_string(),
                ],
                status: "ok".to_string(),
                artifacts: Vec::new(),
            }],
            exports_generated: vec![BundleProofExportReceipt {
                target: "k8s".to_string(),
                path: "target/release-evidence/scanner-safe/secret.yaml".to_string(),
            }],
        })
        .expect("scanner-safe proof receipt");

        assert_eq!(receipt.profile, "scanner-safe");
        assert_eq!(receipt.artifact_count, 2);
        assert_eq!(receipt.scanner_safe_artifact_count, 2);
        assert_eq!(receipt.runtime_material_count, 0);
        assert!(!receipt.private_key_material);
        assert!(!receipt.symmetric_secret_material);
        assert!(
            receipt
                .receipts_present
                .contains(&"materialization".to_string())
        );
        assert!(
            receipt
                .receipts_present
                .contains(&"audit-surface".to_string())
        );
    }

    #[test]
    fn bundle_proof_receipt_rejects_runtime_material() {
        let mut manifest = scanner_safe_bundle_proof_manifest();
        manifest.artifacts.push(BundleProofArtifactRecord {
            path: "runtime.pem".to_string(),
            kind: "rsa".to_string(),
            format: "pem".to_string(),
            lanes: vec!["runtime".to_string()],
            scanner_safe: false,
            description: "runtime material".to_string(),
        });
        let audit_surface = serde_json::json!({
            "scanner_safe": false,
            "runtime_material_count": 1,
        });
        let error = bundle_proof_receipt(BundleProofReceiptInput {
            profile: "scanner-safe",
            bundle_dir: Path::new("target/release-evidence/scanner-safe/bundle"),
            manifest_path: Path::new("target/release-evidence/scanner-safe/bundle/manifest.json"),
            inspect_summary_path: Path::new(
                "target/release-evidence/scanner-safe/inspect-bundle.txt",
            ),
            manifest: &manifest,
            audit_surface: &audit_surface,
            expected_artifacts: Vec::new(),
            commands: Vec::new(),
            exports_generated: Vec::new(),
        })
        .expect_err("runtime material should fail scanner-safe proof");

        assert!(
            error
                .to_string()
                .contains("all artifacts to be scanner-safe"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn bundle_proof_markdown_summarizes_exports_and_claim_boundary() {
        let manifest = scanner_safe_bundle_proof_manifest();
        let audit_surface = serde_json::json!({
            "scanner_safe": true,
            "runtime_material_count": 0,
        });
        let receipt = bundle_proof_receipt(BundleProofReceiptInput {
            profile: "scanner-safe",
            bundle_dir: Path::new("target/release-evidence/scanner-safe/bundle"),
            manifest_path: Path::new("target/release-evidence/scanner-safe/bundle/manifest.json"),
            inspect_summary_path: Path::new(
                "target/release-evidence/scanner-safe/inspect-bundle.txt",
            ),
            manifest: &manifest,
            audit_surface: &audit_surface,
            expected_artifacts: Vec::new(),
            commands: Vec::new(),
            exports_generated: vec![BundleProofExportReceipt {
                target: "vault-kv-json".to_string(),
                path: "target/release-evidence/scanner-safe/kv-v2.json".to_string(),
            }],
        })
        .expect("scanner-safe proof receipt");
        let markdown = render_bundle_proof_markdown(&receipt).expect("render proof markdown");

        assert!(markdown.contains("# Scanner-Safe Bundle Proof"));
        assert!(markdown.contains("Profile: `scanner-safe`"));
        assert!(markdown.contains("Runtime material count: `0`"));
        assert!(markdown.contains("`vault-kv-json`"));
        assert!(markdown.contains("not production key management or scanner evasion"));
    }

    #[test]
    fn bundle_proof_receipt_enforces_oidc_contract_pack_contents() {
        let manifest = oidc_bundle_proof_manifest();
        let audit_surface = serde_json::json!({
            "scanner_safe": true,
            "runtime_material_count": 0,
        });
        let receipt = bundle_proof_receipt(BundleProofReceiptInput {
            profile: "oidc",
            bundle_dir: Path::new("target/release-evidence/oidc/bundle"),
            manifest_path: Path::new("target/release-evidence/oidc/bundle/manifest.json"),
            inspect_summary_path: Path::new("target/release-evidence/oidc/inspect-bundle.txt"),
            manifest: &manifest,
            audit_surface: &audit_surface,
            expected_artifacts: bundle_proof_expected_artifacts("oidc")
                .expect("oidc expected artifacts"),
            commands: Vec::new(),
            exports_generated: Vec::new(),
        })
        .expect("oidc proof receipt");

        assert_eq!(receipt.profile, "oidc");
        assert_eq!(receipt.artifact_count, 6);
        assert_eq!(receipt.contract_pack_checks.len(), 6);
        assert!(
            receipt
                .contract_pack_checks
                .iter()
                .all(|check| check.present)
        );
        assert!(!receipt.private_key_material);
        assert!(!receipt.symmetric_secret_material);
    }

    #[test]
    fn bundle_proof_receipt_rejects_incomplete_oidc_contract_pack() {
        let mut manifest = oidc_bundle_proof_manifest();
        manifest
            .files
            .retain(|path| path != "tokens/negative-bad-audience.json");
        manifest
            .artifacts
            .retain(|artifact| artifact.path != "tokens/negative-bad-audience.json");
        let audit_surface = serde_json::json!({
            "scanner_safe": true,
            "runtime_material_count": 0,
        });
        let error = bundle_proof_receipt(BundleProofReceiptInput {
            profile: "oidc",
            bundle_dir: Path::new("target/release-evidence/oidc/bundle"),
            manifest_path: Path::new("target/release-evidence/oidc/bundle/manifest.json"),
            inspect_summary_path: Path::new("target/release-evidence/oidc/inspect-bundle.txt"),
            manifest: &manifest,
            audit_surface: &audit_surface,
            expected_artifacts: bundle_proof_expected_artifacts("oidc")
                .expect("oidc expected artifacts"),
            commands: Vec::new(),
            exports_generated: Vec::new(),
        })
        .expect_err("missing OIDC artifact should fail proof");

        assert!(
            error.to_string().contains("negative_bad_audience"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn bundle_proof_markdown_summarizes_oidc_contract_checks() {
        let manifest = oidc_bundle_proof_manifest();
        let audit_surface = serde_json::json!({
            "scanner_safe": true,
            "runtime_material_count": 0,
        });
        let receipt = bundle_proof_receipt(BundleProofReceiptInput {
            profile: "oidc",
            bundle_dir: Path::new("target/release-evidence/oidc/bundle"),
            manifest_path: Path::new("target/release-evidence/oidc/bundle/manifest.json"),
            inspect_summary_path: Path::new("target/release-evidence/oidc/inspect-bundle.txt"),
            manifest: &manifest,
            audit_surface: &audit_surface,
            expected_artifacts: bundle_proof_expected_artifacts("oidc")
                .expect("oidc expected artifacts"),
            commands: Vec::new(),
            exports_generated: Vec::new(),
        })
        .expect("oidc proof receipt");
        let markdown = render_bundle_proof_markdown(&receipt).expect("render proof markdown");

        assert!(markdown.contains("# OIDC Contract-Pack Proof"));
        assert!(markdown.contains("negative_duplicate_kid"));
        assert!(markdown.contains("tokens/negative-bad-audience.json"));
        assert!(markdown.contains("downstream validator correctness"));
    }

    fn scanner_safe_bundle_proof_manifest() -> BundleProofManifest {
        BundleProofManifest {
            profile: "scanner-safe".to_string(),
            files: vec![
                "rsa.jwk.json".to_string(),
                "hmac.jwk.json".to_string(),
                "receipts/materialization.json".to_string(),
                "receipts/audit-surface.json".to_string(),
            ],
            artifacts: vec![
                BundleProofArtifactRecord {
                    path: "rsa.jwk.json".to_string(),
                    kind: "rsa".to_string(),
                    format: "jwk".to_string(),
                    lanes: vec!["public".to_string()],
                    scanner_safe: true,
                    description: "public fixture material".to_string(),
                },
                BundleProofArtifactRecord {
                    path: "hmac.jwk.json".to_string(),
                    kind: "hmac".to_string(),
                    format: "jwk".to_string(),
                    lanes: vec!["shape-only".to_string()],
                    scanner_safe: true,
                    description: "scanner-safe symmetric JWK shape with invalid material"
                        .to_string(),
                },
            ],
            receipts: vec![
                BundleProofReceiptRecord {
                    path: "receipts/materialization.json".to_string(),
                    kind: "materialization".to_string(),
                    profile: "scanner-safe".to_string(),
                    description: "deterministic bundle materialization receipt".to_string(),
                },
                BundleProofReceiptRecord {
                    path: "receipts/audit-surface.json".to_string(),
                    kind: "audit-surface".to_string(),
                    profile: "scanner-safe".to_string(),
                    description: "scanner-safety and lane metadata receipt".to_string(),
                },
            ],
        }
    }

    fn oidc_bundle_proof_manifest() -> BundleProofManifest {
        BundleProofManifest {
            profile: "oidc".to_string(),
            files: vec![
                "jwks/valid.json".to_string(),
                "jwks/negative-duplicate-kid.json".to_string(),
                "jwks/negative-missing-kid.json".to_string(),
                "tokens/valid-rs256.json".to_string(),
                "tokens/negative-alg-none.json".to_string(),
                "tokens/negative-bad-audience.json".to_string(),
                "receipts/materialization.json".to_string(),
                "receipts/audit-surface.json".to_string(),
            ],
            artifacts: vec![
                BundleProofArtifactRecord {
                    path: "jwks/valid.json".to_string(),
                    kind: "jwks".to_string(),
                    format: "jwks".to_string(),
                    lanes: vec!["runtime".to_string(), "materialized".to_string()],
                    scanner_safe: true,
                    description: "OIDC valid JWKS fixture".to_string(),
                },
                BundleProofArtifactRecord {
                    path: "jwks/negative-duplicate-kid.json".to_string(),
                    kind: "jwks".to_string(),
                    format: "jwks".to_string(),
                    lanes: vec!["runtime".to_string(), "materialized".to_string()],
                    scanner_safe: true,
                    description: "OIDC negative JWKS with duplicate kid values".to_string(),
                },
                BundleProofArtifactRecord {
                    path: "jwks/negative-missing-kid.json".to_string(),
                    kind: "jwks".to_string(),
                    format: "jwks".to_string(),
                    lanes: vec!["runtime".to_string(), "materialized".to_string()],
                    scanner_safe: true,
                    description: "OIDC negative JWKS with missing kid".to_string(),
                },
                BundleProofArtifactRecord {
                    path: "tokens/valid-rs256.json".to_string(),
                    kind: "token".to_string(),
                    format: "json-manifest".to_string(),
                    lanes: vec!["runtime".to_string(), "materialized".to_string()],
                    scanner_safe: true,
                    description: "OIDC valid RS256 JWT-shaped token fixture".to_string(),
                },
                BundleProofArtifactRecord {
                    path: "tokens/negative-alg-none.json".to_string(),
                    kind: "token".to_string(),
                    format: "json-manifest".to_string(),
                    lanes: vec!["runtime".to_string(), "materialized".to_string()],
                    scanner_safe: true,
                    description: "OIDC negative token with alg none".to_string(),
                },
                BundleProofArtifactRecord {
                    path: "tokens/negative-bad-audience.json".to_string(),
                    kind: "token".to_string(),
                    format: "json-manifest".to_string(),
                    lanes: vec!["runtime".to_string(), "materialized".to_string()],
                    scanner_safe: true,
                    description: "OIDC negative token with bad audience".to_string(),
                },
            ],
            receipts: vec![
                BundleProofReceiptRecord {
                    path: "receipts/materialization.json".to_string(),
                    kind: "materialization".to_string(),
                    profile: "oidc".to_string(),
                    description: "deterministic bundle materialization receipt".to_string(),
                },
                BundleProofReceiptRecord {
                    path: "receipts/audit-surface.json".to_string(),
                    kind: "audit-surface".to_string(),
                    profile: "oidc".to_string(),
                    description: "scanner-safety and lane metadata receipt".to_string(),
                },
            ],
        }
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
    fn count_bdd_scenarios_ignores_comments_and_docstrings() {
        let _cwd_lock = CWD_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let features_dir = root.join("crates").join("uselesskey-bdd").join("features");
        fs::create_dir_all(&features_dir).expect("create features dir");
        let feature = features_dir.join("sample.feature");
        fs::write(
            &feature,
            r#"Feature: demo
  # Scenario: this should not count
  Scenario: one
    Given a docstring contains scenario text
      """
      Scenario: not a real scenario
      Scenario Outline: also not real
      """
  Scenario Outline: two
    Given a fenced block also contains scenario text
      ```
      Scenario: not counted
      ```
"#,
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
    fn publish_order_keeps_token_before_token_shims() {
        let token_idx = PUBLISH_CRATES
            .iter()
            .position(|name| *name == "uselesskey-token")
            .expect("token crate present");
        let base62_idx = PUBLISH_CRATES
            .iter()
            .position(|name| *name == "uselesskey-core-base62")
            .expect("base62 crate present");
        let shape_idx = PUBLISH_CRATES
            .iter()
            .position(|name| *name == "uselesskey-core-token-shape")
            .expect("token shape crate present");
        let token_spec_idx = PUBLISH_CRATES
            .iter()
            .position(|name| *name == "uselesskey-token-spec")
            .expect("token spec crate present");
        assert!(
            token_idx < base62_idx && token_idx < shape_idx && token_idx < token_spec_idx,
            "publish order must place uselesskey-token before token compatibility shims"
        );
    }

    #[test]
    fn publish_order_includes_entropy_before_facade() {
        let entropy_idx = PUBLISH_CRATES
            .iter()
            .position(|name| *name == "uselesskey-entropy")
            .expect("entropy crate present");
        let facade_idx = PUBLISH_CRATES
            .iter()
            .position(|name| *name == "uselesskey")
            .expect("facade crate present");
        assert!(
            entropy_idx < facade_idx,
            "publish order must place uselesskey-entropy before uselesskey"
        );
    }

    #[test]
    fn publish_order_includes_cli_before_facade() {
        let cli_idx = PUBLISH_CRATES
            .iter()
            .position(|name| *name == "uselesskey-cli")
            .expect("cli crate present");
        let facade_idx = PUBLISH_CRATES
            .iter()
            .position(|name| *name == "uselesskey")
            .expect("facade crate present");
        assert!(
            cli_idx < facade_idx,
            "publish order must place uselesskey-cli before uselesskey"
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

    #[test]
    fn materialize_shape_example_keeps_shape_only_contract() {
        let manifest = fs::read_to_string(
            workspace_root_path().join("crates/materialize-shape-buildrs-example/Cargo.toml"),
        )
        .expect("read shape-only materialize example manifest");

        assert!(
            manifest.contains("default-features = false"),
            "shape-only materialize example must disable default features:\n{manifest}"
        );
        assert!(
            !manifest.contains("rsa-materialize"),
            "shape-only materialize example must not opt into rsa-materialize:\n{manifest}"
        );
    }

    #[test]
    fn materialize_rsa_example_requires_explicit_rsa_feature() {
        let manifest = fs::read_to_string(
            workspace_root_path().join("crates/materialize-buildrs-example/Cargo.toml"),
        )
        .expect("read rsa materialize example manifest");

        assert!(
            manifest.contains("default-features = false"),
            "rsa materialize example must disable default features and opt in explicitly:\n{manifest}"
        );
        assert!(
            manifest.contains("features = [\"rsa-materialize\"]"),
            "rsa materialize example must opt into rsa-materialize explicitly:\n{manifest}"
        );
    }

    #[test]
    fn uselesskey_cli_keeps_rsa_materialize_optional() {
        let manifest =
            fs::read_to_string(workspace_root_path().join("crates/uselesskey-cli/Cargo.toml"))
                .expect("read uselesskey-cli manifest");

        assert!(
            manifest.contains("rsa-materialize = [\"dep:uselesskey-rsa\"]"),
            "uselesskey-cli must keep rsa-materialize as an explicit opt-in feature:\n{manifest}"
        );
        assert!(
            manifest.contains(
                "uselesskey-rsa = { workspace = true, features = [\"jwk\"], optional = true }"
            ),
            "uselesskey-cli must keep uselesskey-rsa optional:\n{manifest}"
        );
    }
}
