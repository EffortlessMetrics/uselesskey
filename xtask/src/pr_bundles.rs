use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::{self, Write as _};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde::{Deserialize, Serialize};

const DEFAULT_SNAPSHOT_PATH: &str = "target/xtask/pr-bundles/snapshot.json";
const DEFAULT_LEDGER_PATH: &str = "target/xtask/pr-bundles/ledger.md";
const DEFAULT_WORKTREE_PREFIX: &str = "uselesskey-bundle";

const PRIMARY_BUNDLE_SIZE: usize = 4;
const ATTACH_THRESHOLD: f64 = 0.68;
const TAIL_THRESHOLD: f64 = 0.60;
const DONOR_THRESHOLD: f64 = 0.52;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSnapshot {
    pub captured_at: String,
    pub repository: String,
    pub open_pull_requests: Vec<OpenPullRequestSnapshot>,
    pub closed_pull_requests: Vec<ClosedPullRequestSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequestSnapshot {
    pub number: u64,
    pub state: String,
    pub title: String,
    pub head_ref: String,
    pub base_ref: String,
    pub author_login: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub merged_at: Option<String>,
    pub closed_at: Option<String>,
    pub draft: bool,
    pub mergeable: Option<bool>,
    pub mergeable_state: Option<String>,
    pub commits: u64,
    pub changed_files: u64,
    pub additions: u64,
    pub deletions: u64,
    pub labels: Vec<String>,
    pub touched_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckSnapshot {
    pub name: String,
    pub bucket: String,
    pub state: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckSummarySnapshot {
    pub pass: u32,
    pub fail: u32,
    pub pending: u32,
    pub skipping: u32,
    pub cancel: u32,
    pub total: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPullRequestSnapshot {
    #[serde(flatten)]
    pub pr: PullRequestSnapshot,
    pub checks: Vec<CheckSnapshot>,
    pub check_summary: CheckSummarySnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosedPullRequestSnapshot {
    #[serde(flatten)]
    pub pr: PullRequestSnapshot,
}

#[derive(Debug, Clone)]
pub struct SnapshotCommand {
    pub repository: Option<String>,
    pub output_path: PathBuf,
    pub include_closed_paths: bool,
}

impl SnapshotCommand {
    pub fn new(repository: Option<String>) -> Self {
        Self {
            repository,
            output_path: PathBuf::from(DEFAULT_SNAPSHOT_PATH),
            include_closed_paths: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LedgerCommand {
    pub snapshot_path: PathBuf,
    pub output_path: Option<PathBuf>,
}

impl LedgerCommand {
    pub fn new(snapshot_path: impl Into<PathBuf>) -> Self {
        Self {
            snapshot_path: snapshot_path.into(),
            output_path: Some(PathBuf::from(DEFAULT_LEDGER_PATH)),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PrepareCommand {
    pub repo_root: PathBuf,
    pub snapshot_path: PathBuf,
    pub bundle_id: String,
    pub base_ref: String,
    pub keeper_pr: u64,
    pub branch_name: Option<String>,
    pub worktree_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct CleanupCommand {
    pub repo_root: PathBuf,
    pub worktree_path: PathBuf,
    pub base_ref: Option<String>,
    pub branch: Option<String>,
    pub force: bool,
    pub delete_branch: bool,
    pub prune: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleAnalysis {
    pub repository: String,
    pub captured_at: String,
    pub bundles: Vec<BundleCluster>,
    pub singleton_tails: Vec<OpenPullRequestSnapshot>,
    pub unmatched_closed_donors: Vec<ClosedPullRequestSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleCluster {
    pub bundle_id: String,
    pub theme: String,
    pub canonical_stem: Option<String>,
    pub open_pull_requests: Vec<OpenPullRequestSnapshot>,
    pub closed_donor_pull_requests: Vec<ClosedPullRequestSnapshot>,
    pub touched_paths: Vec<String>,
    pub risk: RiskLevel,
    pub keeper: KeeperRecommendation,
    pub harvest_list: Vec<HarvestDecision>,
    pub validation_plan: String,
    pub merge_closure_plan: String,
    pub cleanup_plan: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeeperRecommendation {
    pub pr_number: u64,
    pub title: String,
    pub branch: String,
    pub score: KeeperScore,
    pub why: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeeperScore {
    pub checks: i64,
    pub mergeable: i64,
    pub size: i64,
    pub commits: i64,
    pub stem: i64,
    pub pr_number: i64,
}

impl KeeperScore {
    fn tuple(&self) -> (i64, i64, i64, i64, i64, i64) {
        (
            self.checks,
            self.mergeable,
            self.size,
            self.commits,
            self.stem,
            self.pr_number,
        )
    }
}
impl Ord for KeeperScore {
    fn cmp(&self, other: &Self) -> Ordering {
        self.tuple().cmp(&other.tuple())
    }
}
impl PartialOrd for KeeperScore {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HarvestStatus {
    KeepVerbatim,
    PortManually,
    AlreadyOnMain,
    Stale,
    Discard,
}

impl fmt::Display for HarvestStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::KeepVerbatim => "keep verbatim",
            Self::PortManually => "port manually",
            Self::AlreadyOnMain => "already on main",
            Self::Stale => "stale / superseded",
            Self::Discard => "discard",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvestDecision {
    pub pr_number: u64,
    pub status: HarvestStatus,
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct LedgerReport {
    pub markdown: String,
    pub analysis: BundleAnalysis,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct WorktreePrepared {
    pub worktree_path: PathBuf,
    pub branch: String,
    pub base_ref: String,
}

#[derive(Debug, Clone)]
pub struct CleanupReport {
    pub worktree_path: PathBuf,
    pub branch_deleted: bool,
    pub pruned: bool,
}

#[derive(Debug, Clone)]
struct BundleProfile {
    canonical_stem: Option<String>,
    theme: String,
    touched_paths: BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GhPullList {
    number: u64,
    state: String,
    title: String,
    user: Option<GhUser>,
    created_at: String,
    updated_at: String,
    merged_at: Option<String>,
    closed_at: Option<String>,
    draft: bool,
    labels: Vec<GhLabel>,
    head: GhRef,
    base: GhRef,
}

#[derive(Debug, Clone, Deserialize)]
struct GhPull {
    number: u64,
    state: String,
    title: String,
    user: Option<GhUser>,
    created_at: String,
    updated_at: String,
    merged_at: Option<String>,
    closed_at: Option<String>,
    draft: bool,
    mergeable: Option<bool>,
    mergeable_state: Option<String>,
    commits: u64,
    changed_files: u64,
    additions: u64,
    deletions: u64,
    labels: Vec<GhLabel>,
    head: GhRef,
    base: GhRef,
}

#[derive(Debug, Clone, Deserialize)]
struct GhRef {
    #[serde(rename = "ref")]
    ref_name: String,
    #[serde(default)]
    sha: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GhUser {
    login: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GhLabel {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GhFile {
    filename: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GhCombinedStatus {
    state: String,
}

pub fn snapshot_cmd(cmd: &SnapshotCommand) -> Result<BundleSnapshot> {
    let repo = match &cmd.repository {
        Some(repo) => repo.clone(),
        None => detect_repository_name()?,
    };
    let open = fetch_prs(&repo, "open")?
        .into_iter()
        .map(|pr| fetch_open_pull_request_snapshot(&repo, pr))
        .collect::<Result<Vec<_>>>()?;
    let closed = fetch_prs(&repo, "closed")?
        .into_iter()
        .map(|pr| {
            let touched_paths = if cmd.include_closed_paths {
                fetch_pr_files(&repo, pr.number).unwrap_or_default()
            } else {
                Vec::new()
            };
            Ok(closed_snapshot(pr, touched_paths))
        })
        .collect::<Result<Vec<_>>>()?;
    let snapshot = BundleSnapshot {
        captured_at: Utc::now().to_rfc3339(),
        repository: repo,
        open_pull_requests: open,
        closed_pull_requests: closed,
    };
    write_json(&cmd.output_path, &snapshot)?;
    Ok(snapshot)
}

pub fn ledger_cmd(cmd: &LedgerCommand) -> Result<LedgerReport> {
    let snapshot = read_json::<BundleSnapshot>(&cmd.snapshot_path)?;
    let analysis = analyze_snapshot(&snapshot);
    let markdown = render_ledger(&snapshot, &analysis);
    if let Some(path) = &cmd.output_path {
        write_text(path, &markdown)?;
    }
    Ok(LedgerReport { markdown, analysis })
}

#[allow(dead_code)]
pub fn prepare_cmd(cmd: &PrepareCommand) -> Result<WorktreePrepared> {
    let snapshot = read_json::<BundleSnapshot>(&cmd.snapshot_path)?;
    let analysis = analyze_snapshot(&snapshot);
    let bundle = analysis
        .bundles
        .iter()
        .find(|bundle| bundle.bundle_id == cmd.bundle_id)
        .with_context(|| {
            format!(
                "bundle `{}` not found in {}",
                cmd.bundle_id,
                cmd.snapshot_path.display()
            )
        })?;
    let keeper = bundle
        .open_pull_requests
        .iter()
        .find(|pr| pr.pr.number == cmd.keeper_pr)
        .with_context(|| {
            format!(
                "keeper #{} is not part of bundle `{}`",
                cmd.keeper_pr, cmd.bundle_id
            )
        })?;
    let branch = cmd
        .branch_name
        .clone()
        .unwrap_or_else(|| default_keeper_branch(&cmd.bundle_id));
    let worktree_path = cmd
        .worktree_path
        .clone()
        .unwrap_or_else(|| default_worktree_path(&cmd.repo_root, &cmd.bundle_id));
    if worktree_path.exists() {
        bail!("worktree path already exists: {}", worktree_path.display());
    }
    if let Some(parent) = worktree_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let worktree = worktree_path.to_string_lossy().to_string();
    run_git(&cmd.repo_root, ["fetch", "origin", &keeper.pr.head_ref])?;
    run_git(
        &cmd.repo_root,
        ["worktree", "add", "-b", &branch, &worktree, "FETCH_HEAD"],
    )?;
    Ok(WorktreePrepared {
        worktree_path,
        branch,
        base_ref: cmd.base_ref.clone(),
    })
}

pub fn cleanup_cmd(cmd: &CleanupCommand) -> Result<CleanupReport> {
    let branch = if cmd.delete_branch && cmd.branch.is_none() {
        if cmd.worktree_path.exists() {
            Some(discover_branch(&cmd.repo_root, &cmd.worktree_path)?)
        } else {
            None
        }
    } else {
        None
    };
    if cmd.worktree_path.exists() {
        verify_worktree_is_clean(&cmd.repo_root, &cmd.worktree_path, cmd.force)?;
        let worktree = cmd.worktree_path.to_string_lossy().to_string();
        run_git(
            &cmd.repo_root,
            [
                "worktree",
                "remove",
                if cmd.force { "--force" } else { "" },
                &worktree,
            ]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>(),
        )?;
    }
    let mut branch_deleted = false;
    if cmd.delete_branch {
        let branch = cmd.branch.clone().or(branch).unwrap_or_default();
        if !branch.is_empty() {
            if !cmd.force {
                let base_ref = cmd.base_ref.as_deref().unwrap_or("origin/main");
                ensure_branch_merged(&cmd.repo_root, base_ref, &branch)?;
            }
            run_git(&cmd.repo_root, ["branch", "-D", &branch])?;
            branch_deleted = true;
        }
    }
    if cmd.prune {
        run_git(&cmd.repo_root, ["worktree", "prune"])?;
    }
    Ok(CleanupReport {
        worktree_path: cmd.worktree_path.clone(),
        branch_deleted,
        pruned: cmd.prune,
    })
}

pub fn analyze_snapshot(snapshot: &BundleSnapshot) -> BundleAnalysis {
    let mut by_stem: BTreeMap<String, Vec<OpenPullRequestSnapshot>> = BTreeMap::new();
    for pr in &snapshot.open_pull_requests {
        by_stem
            .entry(canonical_head_ref_stem(&pr.pr.head_ref))
            .or_default()
            .push(pr.clone());
    }

    let mut bundles = Vec::new();
    let mut singleton_tails = Vec::new();
    let mut seq = 1usize;
    for (stem, mut prs) in by_stem {
        prs.sort_by_key(|pr| pr.pr.number);
        while prs.len() >= PRIMARY_BUNDLE_SIZE {
            let chunk = prs.drain(..PRIMARY_BUNDLE_SIZE).collect();
            bundles.push(make_bundle(
                Some(stem.clone()),
                chunk,
                &snapshot.repository,
                &mut seq,
            ));
        }
        singleton_tails.extend(prs);
    }

    let mut seed_profiles = bundles.iter().map(bundle_profile).collect::<Vec<_>>();
    let mut tails = Vec::new();
    let primary_tails = std::mem::take(&mut singleton_tails);
    for tail in primary_tails {
        let p = pr_profile(&tail);
        let mut best = None;
        let mut best_score = 0.0;
        for (i, b) in seed_profiles.iter().enumerate() {
            let s = bundle_similarity(&p, b);
            if s > best_score {
                best_score = s;
                best = Some(i);
            }
        }
        if let Some(i) = best
            && best_score >= ATTACH_THRESHOLD
        {
            bundles[i].open_pull_requests.push(tail);
            bundles[i].touched_paths = union_paths(&bundles[i].open_pull_requests);
            seed_profiles[i] = bundle_profile(&bundles[i]);
            continue;
        }
        tails.push(tail);
    }

    for cluster in cluster_tails(tails) {
        if cluster.len() == 1 {
            singleton_tails.extend(cluster);
        } else {
            bundles.push(make_bundle(None, cluster, &snapshot.repository, &mut seq));
        }
    }

    let mut unmatched_closed = snapshot.closed_pull_requests.clone();
    for bundle in &mut bundles {
        let profile = bundle_profile(bundle);
        let mut matched = Vec::new();
        let mut rest = Vec::new();
        for donor in unmatched_closed.into_iter() {
            if closed_similarity(&donor.pr, &profile) >= DONOR_THRESHOLD {
                matched.push(donor);
            } else {
                rest.push(donor);
            }
        }
        bundle.closed_donor_pull_requests = matched;
        unmatched_closed = rest;
    }

    for bundle in &mut bundles {
        let profile = bundle_profile(bundle);
        bundle.risk = classify_risk(&profile, &bundle.open_pull_requests);
        bundle.keeper = recommend_keeper(bundle);
        bundle.harvest_list = build_harvest_list(bundle);
        bundle.validation_plan = build_validation_plan(bundle);
        bundle.merge_closure_plan = build_merge_closure_plan(bundle);
        bundle.cleanup_plan = build_cleanup_plan(bundle);
    }

    BundleAnalysis {
        repository: snapshot.repository.clone(),
        captured_at: snapshot.captured_at.clone(),
        bundles,
        singleton_tails,
        unmatched_closed_donors: unmatched_closed,
    }
}

pub fn canonical_head_ref_stem(head_ref: &str) -> String {
    let ref_name = head_ref.trim().trim_start_matches("refs/heads/");
    let mut parts = ref_name.rsplitn(2, '/');
    let tail = parts.next().unwrap_or(ref_name);
    let prefix = parts.next();
    let stem_tail = strip_codex_suffixes(tail);
    match prefix {
        Some(prefix) if !prefix.is_empty() => format!("{prefix}/{stem_tail}"),
        _ => stem_tail,
    }
}

pub fn title_similarity(left: &str, right: &str) -> f64 {
    jaccard(&tokenize(left), &tokenize(right))
}

#[allow(dead_code)]
pub fn path_similarity(left: &[String], right: &[String]) -> f64 {
    jaccard(&path_fingerprints(left), &path_fingerprints(right))
}

fn stems_related(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) if !a.is_empty() && !b.is_empty() => {
            a == b || a.starts_with(b) || b.starts_with(a)
        }
        _ => false,
    }
}

fn bundle_similarity(left: &BundleProfile, right: &BundleProfile) -> f64 {
    let title = title_similarity(&left.theme, &right.theme);
    let paths = jaccard(&left.touched_paths, &right.touched_paths);
    let stem_bonus = if stems_related(
        left.canonical_stem.as_deref(),
        right.canonical_stem.as_deref(),
    ) {
        0.15
    } else {
        0.0
    };
    title * 0.60 + paths * 0.35 + stem_bonus
}

fn pr_similarity(left: &OpenPullRequestSnapshot, right: &OpenPullRequestSnapshot) -> f64 {
    bundle_similarity(&pr_profile(left), &pr_profile(right))
}

pub fn keeper_score_for_bundle(
    bundle: &BundleCluster,
    pr: &OpenPullRequestSnapshot,
) -> KeeperScore {
    let checks = score_checks(&pr.check_summary, &pr.checks);
    let mergeable = match pr.pr.mergeable {
        Some(true) => 30,
        Some(false) => -120,
        None => -15,
    };
    let size =
        -((pr.pr.changed_files as i64 * 8) + ((pr.pr.additions + pr.pr.deletions) as i64 / 20));
    let commits = -(pr.pr.commits as i64 * 5);
    let stem = if Some(canonical_head_ref_stem(&pr.pr.head_ref)) == bundle.canonical_stem {
        40
    } else {
        0
    };
    KeeperScore {
        checks,
        mergeable,
        size,
        commits,
        stem,
        pr_number: -(pr.pr.number as i64),
    }
}

pub fn recommend_keeper(bundle: &BundleCluster) -> KeeperRecommendation {
    let mut best: Option<(KeeperScore, &OpenPullRequestSnapshot)> = None;
    for pr in &bundle.open_pull_requests {
        let score = keeper_score_for_bundle(bundle, pr);
        if best
            .as_ref()
            .is_none_or(|(s, b)| score > *s || (score == *s && pr.pr.number < b.pr.number))
        {
            best = Some((score, pr));
        }
    }
    let (score, pr) = best.expect("bundle has at least one PR");
    KeeperRecommendation {
        pr_number: pr.pr.number,
        title: pr.pr.title.clone(),
        branch: pr.pr.head_ref.clone(),
        score,
        why: keeper_reason(bundle, pr),
    }
}

pub fn render_ledger(snapshot: &BundleSnapshot, analysis: &BundleAnalysis) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# PR Bundle Ledger");
    let _ = writeln!(out, "- Repository: `{}`", snapshot.repository);
    let _ = writeln!(out, "- Captured: `{}`", snapshot.captured_at);
    let _ = writeln!(out, "- Open PRs: `{}`", snapshot.open_pull_requests.len());
    let _ = writeln!(
        out,
        "- Closed donors: `{}`",
        snapshot.closed_pull_requests.len()
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "## Bundle Ledger");
    for bundle in &analysis.bundles {
        let _ = writeln!(out);
        let _ = writeln!(out, "### `{}`", bundle.bundle_id);
        let _ = writeln!(out, "- Theme: {}", bundle.theme);
        let _ = writeln!(
            out,
            "- Open PRs: {}",
            join_numbers(&bundle.open_pull_requests)
        );
        let _ = writeln!(
            out,
            "- Closed donor PRs: {}",
            join_closed_numbers(&bundle.closed_donor_pull_requests)
        );
        let _ = writeln!(
            out,
            "- Touched paths: {}",
            join_paths(&bundle.touched_paths)
        );
        let _ = writeln!(out, "- Risk: {}", bundle.risk);
        let _ = writeln!(
            out,
            "- Recommended keeper: #{} `{}`",
            bundle.keeper.pr_number, bundle.keeper.branch
        );
        let _ = writeln!(out, "- Why this keeper: {}", bundle.keeper.why);
        let _ = writeln!(
            out,
            "- Harvest list: {}",
            render_harvest(&bundle.harvest_list)
        );
        let _ = writeln!(out, "- Validation plan: {}", bundle.validation_plan);
        let _ = writeln!(out, "- Merge/closure plan: {}", bundle.merge_closure_plan);
        let _ = writeln!(out, "- Cleanup plan: {}", bundle.cleanup_plan);
    }
    if !analysis.singleton_tails.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Singleton Tails");
        for pr in &analysis.singleton_tails {
            let _ = writeln!(
                out,
                "- #{} `{}` -> `{}`",
                pr.pr.number, pr.pr.head_ref, pr.pr.title
            );
        }
    }
    if !analysis.unmatched_closed_donors.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "## Closed Donors");
        for pr in &analysis.unmatched_closed_donors {
            let _ = writeln!(
                out,
                "- #{} `{}` -> `{}`",
                pr.pr.number, pr.pr.head_ref, pr.pr.title
            );
        }
    }
    out
}

pub fn default_worktree_path(repo_root: &Path, bundle_id: &str) -> PathBuf {
    repo_root.parent().unwrap_or(repo_root).join(format!(
        "{}-{}",
        DEFAULT_WORKTREE_PREFIX,
        sanitize(bundle_id)
    ))
}

pub fn default_keeper_branch(bundle_id: &str) -> String {
    format!("work/{}-keeper", sanitize(bundle_id))
}

pub fn detect_repository_name() -> Result<String> {
    let mut cmd = Command::new("gh");
    cmd.args([
        "repo",
        "view",
        "--json",
        "nameWithOwner",
        "--jq",
        ".nameWithOwner",
    ]);
    let out = run_capture(&mut cmd)?;
    let repo = out.trim();
    if repo.is_empty() {
        bail!("failed to resolve repository name from gh");
    }
    Ok(repo.to_string())
}

fn fetch_prs(repo: &str, state: &str) -> Result<Vec<GhPullList>> {
    let mut page = 1usize;
    let mut all = Vec::new();
    loop {
        let mut cmd = Command::new("gh");
        cmd.args([
            "api",
            &format!("repos/{repo}/pulls?state={state}&per_page=100&page={page}"),
        ]);
        let items: Vec<GhPullList> = parse_json_array(&run_capture(&mut cmd)?)?;
        let count = items.len();
        all.extend(items);
        if count < 100 {
            break;
        }
        page += 1;
    }
    Ok(all)
}

fn fetch_pr_detail(repo: &str, number: u64) -> Result<GhPull> {
    let mut cmd = Command::new("gh");
    cmd.args(["api", &format!("repos/{repo}/pulls/{number}")]);
    serde_json::from_str(&run_capture(&mut cmd)?).context("failed to parse pull detail")
}

fn fetch_open_pull_request_snapshot(repo: &str, pr: GhPullList) -> Result<OpenPullRequestSnapshot> {
    let detail = fetch_pr_detail(repo, pr.number)?;
    let touched_paths = fetch_pr_files(repo, pr.number)?;
    let checks = fetch_pr_checks(repo, pr.head.sha.as_deref())?;
    Ok(OpenPullRequestSnapshot {
        pr: pull_snapshot_from_gh(detail, touched_paths),
        checks: checks.clone(),
        check_summary: summarize_checks(&checks),
    })
}

fn closed_snapshot(pr: GhPullList, touched_paths: Vec<String>) -> ClosedPullRequestSnapshot {
    ClosedPullRequestSnapshot {
        pr: pull_snapshot_from_list(pr, touched_paths),
    }
}

fn pull_snapshot_from_gh(pr: GhPull, touched_paths: Vec<String>) -> PullRequestSnapshot {
    PullRequestSnapshot {
        number: pr.number,
        state: pr.state,
        title: pr.title,
        head_ref: pr.head.ref_name,
        base_ref: pr.base.ref_name,
        author_login: pr.user.map(|u| u.login),
        created_at: pr.created_at,
        updated_at: pr.updated_at,
        merged_at: pr.merged_at,
        closed_at: pr.closed_at,
        draft: pr.draft,
        mergeable: pr.mergeable,
        mergeable_state: pr.mergeable_state,
        commits: pr.commits,
        changed_files: pr.changed_files,
        additions: pr.additions,
        deletions: pr.deletions,
        labels: pr.labels.into_iter().map(|l| l.name).collect(),
        touched_paths,
    }
}

fn pull_snapshot_from_list(pr: GhPullList, touched_paths: Vec<String>) -> PullRequestSnapshot {
    PullRequestSnapshot {
        number: pr.number,
        state: pr.state,
        title: pr.title,
        head_ref: pr.head.ref_name,
        base_ref: pr.base.ref_name,
        author_login: pr.user.map(|u| u.login),
        created_at: pr.created_at,
        updated_at: pr.updated_at,
        merged_at: pr.merged_at,
        closed_at: pr.closed_at,
        draft: pr.draft,
        mergeable: None,
        mergeable_state: None,
        commits: 0,
        changed_files: 0,
        additions: 0,
        deletions: 0,
        labels: pr.labels.into_iter().map(|l| l.name).collect(),
        touched_paths,
    }
}

fn fetch_pr_files(repo: &str, number: u64) -> Result<Vec<String>> {
    let mut page = 1usize;
    let mut all = Vec::new();
    loop {
        let mut cmd = Command::new("gh");
        cmd.args([
            "api",
            &format!("repos/{repo}/pulls/{number}/files?per_page=100&page={page}"),
        ]);
        let items: Vec<GhFile> = parse_json_array(&run_capture(&mut cmd)?)?;
        let count = items.len();
        all.extend(items.into_iter().map(|f| f.filename));
        if count < 100 {
            break;
        }
        page += 1;
    }
    Ok(all)
}

fn fetch_pr_checks(repo: &str, head_sha: Option<&str>) -> Result<Vec<CheckSnapshot>> {
    let Some(head_sha) = head_sha.filter(|sha| !sha.is_empty()) else {
        return Ok(Vec::new());
    };

    let mut cmd = Command::new("gh");
    cmd.args(["api", &format!("repos/{repo}/commits/{head_sha}/status")]);
    let status: GhCombinedStatus =
        serde_json::from_str(&run_capture(&mut cmd)?).context("failed to parse combined status")?;

    let bucket = match status.state.as_str() {
        "success" => "pass",
        "pending" => "pending",
        "failure" | "error" => "fail",
        _ => "skipping",
    };

    Ok(vec![CheckSnapshot {
        name: "combined-status".to_string(),
        bucket: bucket.to_string(),
        state: status.state,
    }])
}

fn summarize_checks(checks: &[CheckSnapshot]) -> CheckSummarySnapshot {
    let mut out = CheckSummarySnapshot::default();
    for c in checks {
        out.total += 1;
        match c.bucket.as_str() {
            "pass" => out.pass += 1,
            "fail" => out.fail += 1,
            "pending" => out.pending += 1,
            "skipping" => out.skipping += 1,
            "cancel" => out.cancel += 1,
            _ => {}
        }
    }
    out
}

fn make_bundle_id(stem: Option<&str>, seq: usize) -> String {
    let stem = sanitize(stem.unwrap_or(""));
    if stem.is_empty() {
        format!("bundle-{seq:02}")
    } else {
        format!("bundle-{stem}-{seq:02}")
    }
}

fn make_bundle(
    stem: Option<String>,
    open_pull_requests: Vec<OpenPullRequestSnapshot>,
    repo: &str,
    seq: &mut usize,
) -> BundleCluster {
    let theme = derive_theme(&open_pull_requests, stem.as_deref(), repo);
    let bundle_id = make_bundle_id(stem.as_deref().or(Some(theme.as_str())), *seq);
    *seq += 1;
    let mut bundle = BundleCluster {
        bundle_id,
        theme,
        canonical_stem: stem,
        open_pull_requests,
        closed_donor_pull_requests: Vec::new(),
        touched_paths: Vec::new(),
        risk: RiskLevel::Medium,
        keeper: KeeperRecommendation {
            pr_number: 0,
            title: String::new(),
            branch: String::new(),
            score: KeeperScore {
                checks: 0,
                mergeable: 0,
                size: 0,
                commits: 0,
                stem: 0,
                pr_number: 0,
            },
            why: String::new(),
        },
        harvest_list: Vec::new(),
        validation_plan: String::new(),
        merge_closure_plan: String::new(),
        cleanup_plan: String::new(),
    };
    bundle.touched_paths = union_paths(&bundle.open_pull_requests);
    bundle.risk = classify_risk(&bundle_profile(&bundle), &bundle.open_pull_requests);
    bundle.keeper = recommend_keeper(&bundle);
    bundle.harvest_list = build_harvest_list(&bundle);
    bundle.validation_plan = build_validation_plan(&bundle);
    bundle.merge_closure_plan = build_merge_closure_plan(&bundle);
    bundle.cleanup_plan = build_cleanup_plan(&bundle);
    bundle
}

fn closed_similarity(donor: &PullRequestSnapshot, bundle: &BundleProfile) -> f64 {
    let donor_stem = canonical_head_ref_stem(&donor.head_ref);
    let donor_profile = BundleProfile {
        canonical_stem: Some(donor_stem.clone()),
        theme: donor.title.clone(),
        touched_paths: path_fingerprints(&donor.touched_paths),
    };
    let base = bundle_similarity(&donor_profile, bundle);
    // Closed donors are primarily identified by branch naming patterns.
    // Give an extra boost when stems share a prefix (e.g. the donor is
    // an earlier iteration of the same feature branch).
    let stem_prefix_boost =
        if stems_related(Some(donor_stem.as_str()), bundle.canonical_stem.as_deref()) {
            0.25
        } else {
            0.0
        };
    (base + stem_prefix_boost).min(1.0)
}

fn bundle_profile(bundle: &BundleCluster) -> BundleProfile {
    BundleProfile {
        canonical_stem: bundle.canonical_stem.clone(),
        theme: bundle.theme.clone(),
        touched_paths: bundle.touched_paths.iter().cloned().collect(),
    }
}

fn pr_profile(pr: &OpenPullRequestSnapshot) -> BundleProfile {
    BundleProfile {
        canonical_stem: Some(canonical_head_ref_stem(&pr.pr.head_ref)),
        theme: pr.pr.title.clone(),
        touched_paths: pr.pr.touched_paths.iter().cloned().collect(),
    }
}

fn union_paths(prs: &[OpenPullRequestSnapshot]) -> Vec<String> {
    let mut set = BTreeSet::new();
    for pr in prs {
        for path in &pr.pr.touched_paths {
            set.insert(path.clone());
        }
    }
    set.into_iter().collect()
}

fn cluster_tails(leftovers: Vec<OpenPullRequestSnapshot>) -> Vec<Vec<OpenPullRequestSnapshot>> {
    let n = leftovers.len();
    if n == 0 {
        return Vec::new();
    }
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(parent: &mut [usize], x: usize) -> usize {
        if parent[x] != x {
            let p = parent[x];
            parent[x] = find(parent, p);
        }
        parent[x]
    }
    fn union(parent: &mut [usize], a: usize, b: usize) {
        let (ra, rb) = (find(parent, a), find(parent, b));
        if ra != rb {
            parent[rb] = ra;
        }
    }
    for i in 0..n {
        for j in (i + 1)..n {
            if pr_similarity(&leftovers[i], &leftovers[j]) >= TAIL_THRESHOLD {
                union(&mut parent, i, j);
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<OpenPullRequestSnapshot>> = BTreeMap::new();
    for (i, pr) in leftovers.into_iter().enumerate() {
        let r = find(&mut parent, i);
        groups.entry(r).or_default().push(pr);
    }
    groups.into_values().collect()
}

fn classify_risk(profile: &BundleProfile, open: &[OpenPullRequestSnapshot]) -> RiskLevel {
    let docs_only = profile.touched_paths.iter().all(|p| {
        let p = p.to_ascii_lowercase();
        p.starts_with("docs/")
            || p.ends_with("readme.md")
            || p.contains("metadata/")
            || p == "xtask/src/docs_sync.rs"
            || p == "xtask/src/main.rs"
    });
    let broad = open.len() > 4
        || profile.touched_paths.len() > 8
        || open.iter().any(|pr| {
            let h = pr.pr.head_ref.to_ascii_lowercase();
            h.contains("adapter")
                || h.contains("workflow")
                || h.contains("server")
                || h.contains("pqc")
        });
    if docs_only {
        RiskLevel::Low
    } else if broad {
        RiskLevel::High
    } else {
        RiskLevel::Medium
    }
}

fn build_harvest_list(bundle: &BundleCluster) -> Vec<HarvestDecision> {
    let keeper = bundle.keeper.pr_number;
    let mut out = Vec::new();
    for pr in &bundle.open_pull_requests {
        if pr.pr.number == keeper {
            continue;
        }
        let status = if pr.pr.changed_files <= 1 && pr.check_summary.fail == 0 {
            HarvestStatus::KeepVerbatim
        } else if pr.pr.changed_files <= 4 {
            HarvestStatus::PortManually
        } else {
            HarvestStatus::Discard
        };
        out.push(HarvestDecision {
            pr_number: pr.pr.number,
            status,
            note: if bundle_similarity(&pr_profile(pr), &bundle_profile(bundle)) > 0.8 {
                "strong sibling fit".into()
            } else {
                "secondary context only".into()
            },
        });
    }
    for donor in &bundle.closed_donor_pull_requests {
        out.push(HarvestDecision {
            pr_number: donor.pr.number,
            status: if donor.pr.merged_at.is_some() {
                HarvestStatus::AlreadyOnMain
            } else {
                HarvestStatus::Stale
            },
            note: "closed donor".into(),
        });
    }
    out.sort_by_key(|h| h.pr_number);
    out
}

fn build_validation_plan(bundle: &BundleCluster) -> String {
    match bundle.risk {
        RiskLevel::Low => format!(
            "Run `cargo xtask docs-sync --check`, `cargo xtask examples-smoke`, and targeted tests for {}.",
            bundle.theme
        ),
        RiskLevel::Medium => format!(
            "Run targeted crate tests for the touched paths, then `cargo xtask gate` before merging {}.",
            bundle.bundle_id
        ),
        RiskLevel::High => format!(
            "Run targeted adapter/runtime tests first, then `cargo xtask gate`; broaden only after the keeper is stable for {}.",
            bundle.bundle_id
        ),
    }
}

fn build_merge_closure_plan(bundle: &BundleCluster) -> String {
    format!(
        "Rebase the keeper onto `origin/main`, port harvested fixes, merge the keeper, and close superseded siblings for `{}`.",
        bundle.bundle_id
    )
}

fn build_cleanup_plan(bundle: &BundleCluster) -> String {
    format!(
        "Delete the dedicated worktree, prune stale metadata, and remove the keeper branch after `{}` lands.",
        bundle.bundle_id
    )
}

fn keeper_reason(bundle: &BundleCluster, pr: &OpenPullRequestSnapshot) -> String {
    let mut parts = Vec::new();
    if pr.check_summary.fail == 0 {
        parts.push("no failing checks".to_string());
    }
    if pr.pr.mergeable == Some(true) {
        parts.push("mergeable".to_string());
    }
    parts.push(format!(
        "{} files / {} additions / {} deletions",
        pr.pr.changed_files, pr.pr.additions, pr.pr.deletions
    ));
    parts.push(format!("{} commit(s)", pr.pr.commits));
    if Some(canonical_head_ref_stem(&pr.pr.head_ref)) == bundle.canonical_stem {
        parts.push("exact stem match".to_string());
    }
    parts.join(", ")
}

fn score_checks(summary: &CheckSummarySnapshot, checks: &[CheckSnapshot]) -> i64 {
    let mut s = 0i64;
    s += summary.pass as i64 * 24;
    s -= summary.fail as i64 * 90;
    s -= summary.pending as i64 * 12;
    s -= summary.skipping as i64 * 2;
    s -= summary.cancel as i64 * 15;
    if checks.is_empty() {
        s -= 8;
    }
    s
}

fn render_harvest(items: &[HarvestDecision]) -> String {
    if items.is_empty() {
        "none".into()
    } else {
        items
            .iter()
            .map(|i| format!("#{}: {} ({})", i.pr_number, i.status, i.note))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn join_numbers(prs: &[OpenPullRequestSnapshot]) -> String {
    prs.iter()
        .map(|pr| format!("#{}", pr.pr.number))
        .collect::<Vec<_>>()
        .join(", ")
}
fn join_closed_numbers(prs: &[ClosedPullRequestSnapshot]) -> String {
    prs.iter()
        .map(|pr| format!("#{}", pr.pr.number))
        .collect::<Vec<_>>()
        .join(", ")
}
fn join_paths(paths: &[String]) -> String {
    if paths.is_empty() {
        "none".into()
    } else {
        paths.join(", ")
    }
}

fn strip_codex_suffixes(s: &str) -> String {
    let mut cur = s.to_string();
    loop {
        let Some((base, suffix)) = cur.rsplit_once('-') else {
            break;
        };
        // Codex-style suffixes are 6-char hex-like strings (e.g. "ab12cd").
        // Require at least one digit to avoid stripping English words like "branch".
        if suffix.len() == 6
            && suffix
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && suffix.chars().any(|c| c.is_ascii_digit())
        {
            cur = base.to_string();
        } else {
            break;
        }
    }
    cur
}

fn tokenize(text: &str) -> BTreeSet<String> {
    static STOP: OnceLock<HashSet<&'static str>> = OnceLock::new();
    let stop = STOP.get_or_init(|| {
        HashSet::from([
            "the",
            "and",
            "or",
            "for",
            "with",
            "from",
            "into",
            "onto",
            "add",
            "adds",
            "adding",
            "implement",
            "implements",
            "implemented",
            "enforce",
            "enforces",
            "generate",
            "generates",
            "generated",
            "support",
            "supports",
            "create",
            "new",
            "initial",
            "docs",
            "xtask",
            "feat",
            "fix",
            "test",
            "tests",
            "crate",
            "crates",
        ])
    });
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter_map(|t| {
            let t = t.trim().to_ascii_lowercase();
            if t.is_empty() || stop.contains(t.as_str()) {
                None
            } else {
                Some(t)
            }
        })
        .collect()
}

fn jaccard(left: &BTreeSet<String>, right: &BTreeSet<String>) -> f64 {
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }
    let inter = left.iter().filter(|v| right.contains(*v)).count();
    let union = left.len() + right.len() - inter;
    if union == 0 {
        1.0
    } else {
        inter as f64 / union as f64
    }
}

fn path_fingerprints(paths: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for path in paths {
        let n = path.replace('\\', "/").to_ascii_lowercase();
        out.insert(n.clone());
        if let Some(parent) = Path::new(&n).parent() {
            out.insert(parent.to_string_lossy().into_owned());
        }
        if let Some(file) = Path::new(&n).file_name() {
            out.insert(file.to_string_lossy().into_owned());
        }
        for part in n.split('/') {
            if !part.is_empty() {
                out.insert(part.to_string());
            }
        }
    }
    out
}

fn sanitize(s: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in s.chars() {
        let c = if c.is_ascii_alphanumeric() { c } else { '-' };
        if c == '-' {
            if dash {
                continue;
            }
            dash = true;
        } else {
            dash = false;
        }
        out.push(c.to_ascii_lowercase());
    }
    out.trim_matches('-').to_string()
}

fn humanize_stem(stem: &str) -> String {
    stem.trim_start_matches("codex/").replace(['-', '_'], " ")
}

fn derive_theme(prs: &[OpenPullRequestSnapshot], stem: Option<&str>, repo: &str) -> String {
    let first = prs
        .first()
        .map(|p| p.pr.title.clone())
        .or_else(|| stem.map(humanize_stem))
        .unwrap_or_else(|| repo.to_string());
    let counts =
        prs.iter()
            .flat_map(|pr| tokenize(&pr.pr.title))
            .fold(BTreeMap::new(), |mut acc, t| {
                *acc.entry(t).or_insert(0) += 1;
                acc
            });
    let threshold = prs.len().max(2).div_ceil(2);
    let keep = tokenize(&first)
        .into_iter()
        .filter(|t| counts.get(t).copied().unwrap_or(0) >= threshold)
        .collect::<Vec<_>>();
    if keep.is_empty() {
        stem.map(humanize_stem).unwrap_or(first)
    } else {
        keep.join(" ")
    }
}

fn run_capture(cmd: &mut Command) -> Result<String> {
    let out = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("failed to spawn command")?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn run_git<I, S>(cwd: &Path, args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut cmd = Command::new("git");
    cmd.current_dir(cwd);
    for arg in args {
        cmd.arg(arg.as_ref());
    }
    let out = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("failed to run git in {}", cwd.display()))?;
    if !out.status.success() {
        bail!(
            "git command failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, serde_json::to_string_pretty(value)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn write_text(path: &Path, value: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(path, value).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("failed to parse JSON from {}", path.display()))
}

fn parse_json_array<T: for<'de> Deserialize<'de>>(text: &str) -> Result<Vec<T>> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(text).context("failed to parse JSON array")
}

fn verify_worktree_is_clean(repo_root: &Path, worktree_path: &Path, force: bool) -> Result<()> {
    if !worktree_path.exists() {
        bail!("worktree path does not exist: {}", worktree_path.display());
    }
    let canonical_requested = canonicalize_path(worktree_path)?;
    let mut cmd = Command::new("git");
    cmd.current_dir(worktree_path)
        .args(["status", "--porcelain=v1", "--untracked-files=all"]);
    let dirty = !run_capture(&mut cmd)?.trim().is_empty();
    if dirty && !force {
        bail!(
            "refusing to remove dirty worktree {}; pass force to override",
            worktree_path.display()
        );
    }
    let registered = list_worktrees(repo_root)?;
    if !registered.contains(&canonical_requested) {
        bail!(
            "worktree path is not registered with this repository: {}",
            worktree_path.display()
        );
    }
    Ok(())
}

fn list_worktrees(repo_root: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root)
        .args(["worktree", "list", "--porcelain"]);
    let out = run_capture(&mut cmd)?;
    Ok(out
        .lines()
        .filter_map(|line| line.strip_prefix("worktree ").map(PathBuf::from))
        .map(|path| canonicalize_path(&path).unwrap_or(path))
        .collect())
}

fn discover_branch(repo_root: &Path, worktree_path: &Path) -> Result<String> {
    let requested = canonicalize_path(worktree_path)?;
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root)
        .args(["worktree", "list", "--porcelain"]);
    let out = run_capture(&mut cmd)?;
    let mut cur_path = None::<PathBuf>;
    let mut cur_branch = None::<String>;
    for line in out.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            cur_path = Some(PathBuf::from(path));
            cur_branch = None;
            continue;
        }
        if let Some(branch) = line.strip_prefix("branch ") {
            cur_branch = Some(branch.trim_start_matches("refs/heads/").to_string());
        }
        if line.is_empty()
            && cur_path
                .as_ref()
                .and_then(|path| canonicalize_path(path).ok())
                .as_ref()
                == Some(&requested)
        {
            return Ok(cur_branch.unwrap_or_default());
        }
    }
    if cur_path
        .as_ref()
        .and_then(|path| canonicalize_path(path).ok())
        .as_ref()
        == Some(&requested)
    {
        Ok(cur_branch.unwrap_or_default())
    } else {
        bail!(
            "could not discover branch for worktree {}",
            worktree_path.display()
        )
    }
}

fn canonicalize_path(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("failed to canonicalize {}", path.display()))
}

fn ensure_branch_merged(repo_root: &Path, base_ref: &str, branch: &str) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root)
        .args(["branch", "--merged", base_ref]);
    let out = run_capture(&mut cmd)?;
    if !out
        .lines()
        .map(strip_status_prefix)
        .any(|line| line == branch)
    {
        bail!(
            "refusing to delete branch `{}` because it is not merged into `{}`",
            branch,
            base_ref
        );
    }
    Ok(())
}

fn strip_status_prefix(line: &str) -> &str {
    line.trim().trim_start_matches('*').trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn open_pr(
        num: u64,
        title: &str,
        stem: &str,
        paths: &[&str],
        pass: u32,
        fail: u32,
        mergeable: Option<bool>,
        files: u64,
        additions: u64,
        deletions: u64,
        commits: u64,
    ) -> OpenPullRequestSnapshot {
        OpenPullRequestSnapshot {
            pr: PullRequestSnapshot {
                number: num,
                state: "open".into(),
                title: title.into(),
                head_ref: stem.into(),
                base_ref: "main".into(),
                author_login: Some("codex".into()),
                created_at: "2026-03-28T00:00:00Z".into(),
                updated_at: "2026-03-28T00:00:00Z".into(),
                merged_at: None,
                closed_at: None,
                draft: false,
                mergeable,
                mergeable_state: mergeable
                    .map(|m| if m { "clean".into() } else { "unstable".into() }),
                commits,
                changed_files: files,
                additions,
                deletions,
                labels: Vec::new(),
                touched_paths: paths.iter().map(|p| p.to_string()).collect(),
            },
            checks: vec![CheckSnapshot {
                name: "ci".into(),
                bucket: if fail > 0 {
                    "fail".into()
                } else {
                    "pass".into()
                },
                state: "completed".into(),
            }],
            check_summary: CheckSummarySnapshot {
                pass,
                fail,
                pending: 0,
                skipping: 0,
                cancel: 0,
                total: pass + fail,
            },
        }
    }

    #[test]
    fn stem_normalization_strips_codex_suffix() {
        assert_eq!(
            canonical_head_ref_stem("codex/implement-version-drift-enforcement-for-docs-othe10"),
            "codex/implement-version-drift-enforcement-for-docs"
        );
    }

    #[test]
    fn similarity_rewards_related_titles() {
        assert!(
            title_similarity(
                "Enforce docs/version snippet sync",
                "xtask: enforce docs snippet/version drift checks"
            ) > 0.25
        );
    }

    #[test]
    fn keeper_prefers_clean_mergeable_smaller_change() {
        let bundle = BundleCluster {
            bundle_id: "bundle-test-01".into(),
            theme: "docs drift".into(),
            canonical_stem: Some("codex/implement-version-drift-enforcement-for-docs".into()),
            open_pull_requests: vec![
                open_pr(
                    377,
                    "Enforce docs/version snippet sync",
                    "codex/implement-version-drift-enforcement-for-docs",
                    &["docs/a.md"],
                    3,
                    0,
                    Some(true),
                    4,
                    100,
                    10,
                    1,
                ),
                open_pr(
                    380,
                    "xtask: enforce docs snippet/version drift checks",
                    "codex/implement-version-drift-enforcement-for-docs-zftywx",
                    &["docs/b.md"],
                    2,
                    1,
                    Some(false),
                    10,
                    300,
                    20,
                    2,
                ),
            ],
            closed_donor_pull_requests: Vec::new(),
            touched_paths: vec![],
            risk: RiskLevel::Low,
            keeper: KeeperRecommendation {
                pr_number: 0,
                title: String::new(),
                branch: String::new(),
                score: KeeperScore {
                    checks: 0,
                    mergeable: 0,
                    size: 0,
                    commits: 0,
                    stem: 0,
                    pr_number: 0,
                },
                why: String::new(),
            },
            harvest_list: Vec::new(),
            validation_plan: String::new(),
            merge_closure_plan: String::new(),
            cleanup_plan: String::new(),
        };
        assert_eq!(recommend_keeper(&bundle).pr_number, 377);
    }

    #[test]
    fn analyze_snapshot_keeps_singletons_visible() {
        let snapshot = BundleSnapshot {
            captured_at: "2026-03-28T00:00:00Z".into(),
            repository: "EffortlessMetrics/uselesskey".into(),
            open_pull_requests: vec![
                open_pr(
                    377,
                    "Enforce docs/version snippet sync",
                    "codex/implement-version-drift-enforcement-for-docs",
                    &["docs/a.md"],
                    3,
                    0,
                    Some(true),
                    4,
                    100,
                    10,
                    1,
                ),
                open_pr(
                    378,
                    "xtask: enforce docs/version drift",
                    "codex/implement-version-drift-enforcement-for-docs-othe10",
                    &["docs/b.md"],
                    3,
                    0,
                    Some(true),
                    5,
                    200,
                    20,
                    2,
                ),
                open_pr(
                    379,
                    "Enforce docs snippet/version sync",
                    "codex/implement-version-drift-enforcement-for-docs-yjn64l",
                    &["docs/c.md"],
                    2,
                    1,
                    Some(false),
                    6,
                    300,
                    30,
                    1,
                ),
                open_pr(
                    380,
                    "xtask: enforce docs snippet/version drift checks",
                    "codex/implement-version-drift-enforcement-for-docs-zftywx",
                    &["docs/d.md"],
                    2,
                    1,
                    Some(false),
                    10,
                    400,
                    40,
                    1,
                ),
                open_pr(
                    372,
                    "Add versioned public corpus generation",
                    "codex/add-versioned-fixture-corpus",
                    &["xtask/src/main.rs"],
                    2,
                    0,
                    Some(true),
                    2,
                    50,
                    10,
                    1,
                ),
            ],
            closed_pull_requests: vec![],
        };
        let analysis = analyze_snapshot(&snapshot);
        assert!(!analysis.bundles.is_empty());
        assert!(!analysis.singleton_tails.is_empty());
        assert!(render_ledger(&snapshot, &analysis).contains("## Bundle Ledger"));
    }

    // ---------------------------------------------------------------
    // Snapshot parsing
    // ---------------------------------------------------------------

    const SAMPLE_SNAPSHOT_JSON: &str = r#"{
      "captured_at": "2026-03-28T12:00:00Z",
      "repository": "EffortlessMetrics/uselesskey",
      "open_pull_requests": [
        {
          "number": 100,
          "state": "open",
          "title": "Add RSA adapter",
          "head_ref": "codex/add-rsa-adapter-ab12cd",
          "base_ref": "main",
          "author_login": "codex",
          "created_at": "2026-03-20T00:00:00Z",
          "updated_at": "2026-03-28T00:00:00Z",
          "merged_at": null,
          "closed_at": null,
          "draft": false,
          "mergeable": true,
          "mergeable_state": "clean",
          "commits": 1,
          "changed_files": 2,
          "additions": 40,
          "deletions": 5,
          "labels": ["enhancement"],
          "touched_paths": ["crates/uselesskey-rsa/src/lib.rs"],
          "checks": [
            { "name": "ci", "bucket": "pass", "state": "success" }
          ],
          "check_summary": { "pass": 1, "fail": 0, "pending": 0, "skipping": 0, "cancel": 0, "total": 1 }
        }
      ],
      "closed_pull_requests": [
        {
          "number": 90,
          "state": "closed",
          "title": "Draft RSA adapter",
          "head_ref": "codex/add-rsa-adapter-old",
          "base_ref": "main",
          "author_login": "codex",
          "created_at": "2026-03-15T00:00:00Z",
          "updated_at": "2026-03-18T00:00:00Z",
          "merged_at": null,
          "closed_at": "2026-03-18T00:00:00Z",
          "draft": true,
          "mergeable": null,
          "mergeable_state": null,
          "commits": 0,
          "changed_files": 0,
          "additions": 0,
          "deletions": 0,
          "labels": [],
          "touched_paths": []
        }
      ]
    }"#;

    #[test]
    fn snapshot_round_trip_json() {
        let snapshot: BundleSnapshot =
            serde_json::from_str(SAMPLE_SNAPSHOT_JSON).expect("deserialize sample snapshot");
        assert_eq!(snapshot.repository, "EffortlessMetrics/uselesskey");
        assert_eq!(snapshot.captured_at, "2026-03-28T12:00:00Z");
        assert_eq!(snapshot.open_pull_requests.len(), 1);
        assert_eq!(snapshot.closed_pull_requests.len(), 1);

        let open = &snapshot.open_pull_requests[0];
        assert_eq!(open.pr.number, 100);
        assert_eq!(open.pr.title, "Add RSA adapter");
        assert_eq!(open.pr.head_ref, "codex/add-rsa-adapter-ab12cd");
        assert_eq!(open.pr.mergeable, Some(true));
        assert_eq!(open.pr.labels, vec!["enhancement"]);
        assert_eq!(open.check_summary.pass, 1);
        assert_eq!(open.check_summary.total, 1);

        let closed = &snapshot.closed_pull_requests[0];
        assert_eq!(closed.pr.number, 90);
        assert!(closed.pr.draft);

        // Round-trip: serialize then deserialize
        let json = serde_json::to_string_pretty(&snapshot).unwrap();
        let round_tripped: BundleSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(round_tripped.repository, snapshot.repository);
        assert_eq!(
            round_tripped.open_pull_requests.len(),
            snapshot.open_pull_requests.len()
        );
    }

    #[test]
    fn snapshot_deserialize_minimal_open_pr() {
        // Verify nullable fields work
        let json = r#"{
          "captured_at": "2026-01-01T00:00:00Z",
          "repository": "owner/repo",
          "open_pull_requests": [{
            "number": 1, "state": "open", "title": "t",
            "head_ref": "branch", "base_ref": "main",
            "author_login": null,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "merged_at": null, "closed_at": null,
            "draft": false, "mergeable": null, "mergeable_state": null,
            "commits": 0, "changed_files": 0, "additions": 0, "deletions": 0,
            "labels": [], "touched_paths": [],
            "checks": [],
            "check_summary": { "pass": 0, "fail": 0, "pending": 0, "skipping": 0, "cancel": 0, "total": 0 }
          }],
          "closed_pull_requests": []
        }"#;
        let snap: BundleSnapshot = serde_json::from_str(json).unwrap();
        assert_eq!(snap.open_pull_requests[0].pr.author_login, None);
        assert_eq!(snap.open_pull_requests[0].pr.mergeable, None);
    }

    // ---------------------------------------------------------------
    // Bundle analysis: grouping by stem
    // ---------------------------------------------------------------

    /// Build a snapshot with 4 PRs sharing a stem plus 1 unrelated PR.
    /// The 4 should form a bundle, and the unrelated one becomes a singleton.
    fn four_stem_snapshot() -> BundleSnapshot {
        BundleSnapshot {
            captured_at: "2026-04-01T00:00:00Z".into(),
            repository: "owner/repo".into(),
            open_pull_requests: vec![
                open_pr(
                    10,
                    "Add ECDSA P-256 support",
                    "codex/add-ecdsa-support-aaa111",
                    &["crates/uselesskey-ecdsa/src/lib.rs"],
                    1,
                    0,
                    Some(true),
                    3,
                    80,
                    10,
                    1,
                ),
                open_pr(
                    11,
                    "Add ECDSA P-384 support",
                    "codex/add-ecdsa-support-bbb222",
                    &[
                        "crates/uselesskey-ecdsa/src/lib.rs",
                        "crates/uselesskey-ecdsa/src/p384.rs",
                    ],
                    1,
                    0,
                    Some(true),
                    4,
                    120,
                    15,
                    2,
                ),
                open_pr(
                    12,
                    "ECDSA factory extension trait",
                    "codex/add-ecdsa-support-ccc333",
                    &["crates/uselesskey-ecdsa/src/lib.rs"],
                    1,
                    0,
                    Some(true),
                    2,
                    50,
                    5,
                    1,
                ),
                open_pr(
                    13,
                    "ECDSA negative fixtures",
                    "codex/add-ecdsa-support-ddd444",
                    &["crates/uselesskey-ecdsa/src/negative.rs"],
                    0,
                    1,
                    Some(false),
                    5,
                    200,
                    30,
                    3,
                ),
                open_pr(
                    50,
                    "Improve README badges",
                    "codex/improve-readme-badges",
                    &["README.md"],
                    1,
                    0,
                    Some(true),
                    1,
                    10,
                    2,
                    1,
                ),
            ],
            closed_pull_requests: vec![],
        }
    }

    #[test]
    fn analyze_groups_four_same_stem_prs_into_one_bundle() {
        let snapshot = four_stem_snapshot();
        let analysis = analyze_snapshot(&snapshot);

        // Four ECDSA PRs share the canonical stem "codex/add-ecdsa-support"
        // => PRIMARY_BUNDLE_SIZE = 4 => exactly one bundle.
        assert_eq!(analysis.bundles.len(), 1);
        let bundle = &analysis.bundles[0];
        assert_eq!(bundle.open_pull_requests.len(), 4);

        // All four PR numbers should be present
        let nums: Vec<u64> = bundle
            .open_pull_requests
            .iter()
            .map(|p| p.pr.number)
            .collect();
        assert!(nums.contains(&10));
        assert!(nums.contains(&11));
        assert!(nums.contains(&12));
        assert!(nums.contains(&13));

        // The fifth PR (#50) with a different stem should be a singleton
        assert_eq!(analysis.singleton_tails.len(), 1);
        assert_eq!(analysis.singleton_tails[0].pr.number, 50);
    }

    #[test]
    fn bundle_id_contains_sanitized_stem() {
        let snapshot = four_stem_snapshot();
        let analysis = analyze_snapshot(&snapshot);
        let bundle = &analysis.bundles[0];
        // Bundle ID should contain "ecdsa-support" from the stem
        assert!(
            bundle.bundle_id.starts_with("bundle-"),
            "bundle_id should start with 'bundle-': {}",
            bundle.bundle_id,
        );
        assert!(
            bundle.bundle_id.contains("ecdsa"),
            "bundle_id should reflect the stem: {}",
            bundle.bundle_id,
        );
    }

    #[test]
    fn bundle_touched_paths_is_union_of_all_prs() {
        let snapshot = four_stem_snapshot();
        let analysis = analyze_snapshot(&snapshot);
        let bundle = &analysis.bundles[0];
        // Should contain all paths from the four PRs
        assert!(
            bundle
                .touched_paths
                .contains(&"crates/uselesskey-ecdsa/src/lib.rs".to_string())
        );
        assert!(
            bundle
                .touched_paths
                .contains(&"crates/uselesskey-ecdsa/src/negative.rs".to_string())
        );
    }

    #[test]
    fn analyze_assigns_keeper_with_best_score() {
        let snapshot = four_stem_snapshot();
        let analysis = analyze_snapshot(&snapshot);
        let bundle = &analysis.bundles[0];
        // PR #12 should be the keeper: passing checks, mergeable, smallest size (2 files, 50+5),
        // 1 commit, exact stem match, and lower PR number breaks ties.
        assert_eq!(bundle.keeper.pr_number, 12);
    }

    #[test]
    fn analyze_harvest_list_excludes_keeper() {
        let snapshot = four_stem_snapshot();
        let analysis = analyze_snapshot(&snapshot);
        let bundle = &analysis.bundles[0];
        let keeper = bundle.keeper.pr_number;
        // Harvest list should not contain the keeper
        assert!(
            bundle.harvest_list.iter().all(|h| h.pr_number != keeper),
            "harvest list should not include the keeper PR",
        );
        // But should contain the other 3
        assert_eq!(bundle.harvest_list.len(), 3);
    }

    // ---------------------------------------------------------------
    // Closed donor matching
    // ---------------------------------------------------------------

    #[test]
    fn closed_donors_attach_to_matching_bundle() {
        let snapshot = BundleSnapshot {
            captured_at: "2026-04-01T00:00:00Z".into(),
            repository: "owner/repo".into(),
            open_pull_requests: vec![
                open_pr(
                    10,
                    "Add ECDSA P-256",
                    "codex/add-ecdsa-support-aaa111",
                    &["crates/uselesskey-ecdsa/src/lib.rs"],
                    1,
                    0,
                    Some(true),
                    3,
                    80,
                    10,
                    1,
                ),
                open_pr(
                    11,
                    "Add ECDSA P-384",
                    "codex/add-ecdsa-support-bbb222",
                    &["crates/uselesskey-ecdsa/src/lib.rs"],
                    1,
                    0,
                    Some(true),
                    4,
                    120,
                    15,
                    2,
                ),
                open_pr(
                    12,
                    "ECDSA factory trait",
                    "codex/add-ecdsa-support-ccc333",
                    &["crates/uselesskey-ecdsa/src/lib.rs"],
                    1,
                    0,
                    Some(true),
                    2,
                    50,
                    5,
                    1,
                ),
                open_pr(
                    13,
                    "ECDSA negative",
                    "codex/add-ecdsa-support-ddd444",
                    &["crates/uselesskey-ecdsa/src/negative.rs"],
                    0,
                    1,
                    Some(false),
                    5,
                    200,
                    30,
                    3,
                ),
            ],
            closed_pull_requests: vec![ClosedPullRequestSnapshot {
                pr: PullRequestSnapshot {
                    number: 5,
                    state: "closed".into(),
                    title: "Draft ECDSA support".into(),
                    head_ref: "codex/add-ecdsa-support-old".into(),
                    base_ref: "main".into(),
                    author_login: Some("codex".into()),
                    created_at: "2026-03-01T00:00:00Z".into(),
                    updated_at: "2026-03-05T00:00:00Z".into(),
                    merged_at: None,
                    closed_at: Some("2026-03-05T00:00:00Z".into()),
                    draft: true,
                    mergeable: None,
                    mergeable_state: None,
                    commits: 0,
                    changed_files: 0,
                    additions: 0,
                    deletions: 0,
                    labels: Vec::new(),
                    touched_paths: Vec::new(),
                },
            }],
        };
        let analysis = analyze_snapshot(&snapshot);
        assert_eq!(analysis.bundles.len(), 1);
        // The closed donor shares the ECDSA stem so it should be attached to the bundle
        assert_eq!(analysis.bundles[0].closed_donor_pull_requests.len(), 1);
        assert_eq!(
            analysis.bundles[0].closed_donor_pull_requests[0].pr.number,
            5
        );
        assert!(analysis.unmatched_closed_donors.is_empty());
    }

    // ---------------------------------------------------------------
    // Default path/branch computation
    // ---------------------------------------------------------------

    #[test]
    fn default_worktree_path_sibling_of_repo() {
        let repo = Path::new("/home/user/code/uselesskey");
        let path = default_worktree_path(repo, "bundle-ecdsa-01");
        // Should be alongside the repo directory, not inside it
        assert_eq!(
            path,
            PathBuf::from("/home/user/code/uselesskey-bundle-bundle-ecdsa-01")
        );
    }

    #[test]
    fn default_worktree_path_sanitizes_special_chars() {
        let repo = Path::new("/repo");
        let path = default_worktree_path(repo, "bundle foo/bar#1");
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        // Special characters get replaced with dashes and deduplicated
        assert!(!name.contains(' '));
        assert!(!name.contains('/'));
        assert!(!name.contains('#'));
    }

    #[test]
    fn default_worktree_path_for_root_repo() {
        // Edge case: repo is at filesystem root
        let repo = Path::new("/");
        let path = default_worktree_path(repo, "b-01");
        // parent of "/" is "/" itself, so path should still work
        assert!(path.to_string_lossy().contains("uselesskey-bundle"));
    }

    #[test]
    fn default_keeper_branch_format() {
        let branch = default_keeper_branch("bundle-ecdsa-01");
        assert_eq!(branch, "work/bundle-ecdsa-01-keeper");
    }

    #[test]
    fn default_keeper_branch_sanitizes_input() {
        let branch = default_keeper_branch("bundle foo/bar");
        assert_eq!(branch, "work/bundle-foo-bar-keeper");
    }

    // ---------------------------------------------------------------
    // Ledger rendering
    // ---------------------------------------------------------------

    #[test]
    fn ledger_contains_expected_sections() {
        let snapshot = four_stem_snapshot();
        let analysis = analyze_snapshot(&snapshot);
        let md = render_ledger(&snapshot, &analysis);

        assert!(md.starts_with("# PR Bundle Ledger\n"));
        assert!(md.contains("- Repository: `owner/repo`"));
        assert!(md.contains("- Captured: `2026-04-01T00:00:00Z`"));
        assert!(md.contains("- Open PRs: `5`"));
        assert!(md.contains("## Bundle Ledger"));
    }

    #[test]
    fn ledger_renders_bundle_details() {
        let snapshot = four_stem_snapshot();
        let analysis = analyze_snapshot(&snapshot);
        let md = render_ledger(&snapshot, &analysis);

        // Each bundle section includes these fields
        assert!(md.contains("- Theme:"));
        assert!(md.contains("- Open PRs:"));
        assert!(md.contains("- Closed donor PRs:"));
        assert!(md.contains("- Touched paths:"));
        assert!(md.contains("- Risk:"));
        assert!(md.contains("- Recommended keeper:"));
        assert!(md.contains("- Why this keeper:"));
        assert!(md.contains("- Harvest list:"));
        assert!(md.contains("- Validation plan:"));
        assert!(md.contains("- Merge/closure plan:"));
        assert!(md.contains("- Cleanup plan:"));
    }

    #[test]
    fn ledger_renders_singleton_tails_section() {
        let snapshot = four_stem_snapshot();
        let analysis = analyze_snapshot(&snapshot);
        let md = render_ledger(&snapshot, &analysis);

        // Should have singleton tails section with PR #50
        assert!(md.contains("## Singleton Tails"));
        assert!(md.contains("#50"));
    }

    #[test]
    fn ledger_omits_singleton_section_when_empty() {
        // 4 PRs with same stem, no leftover
        let snapshot = BundleSnapshot {
            captured_at: "2026-04-01T00:00:00Z".into(),
            repository: "owner/repo".into(),
            open_pull_requests: vec![
                open_pr(
                    1,
                    "A fix",
                    "codex/fix-aaa111",
                    &["a.rs"],
                    1,
                    0,
                    Some(true),
                    1,
                    10,
                    1,
                    1,
                ),
                open_pr(
                    2,
                    "A fix",
                    "codex/fix-bbb222",
                    &["a.rs"],
                    1,
                    0,
                    Some(true),
                    1,
                    10,
                    1,
                    1,
                ),
                open_pr(
                    3,
                    "A fix",
                    "codex/fix-ccc333",
                    &["a.rs"],
                    1,
                    0,
                    Some(true),
                    1,
                    10,
                    1,
                    1,
                ),
                open_pr(
                    4,
                    "A fix",
                    "codex/fix-ddd444",
                    &["a.rs"],
                    1,
                    0,
                    Some(true),
                    1,
                    10,
                    1,
                    1,
                ),
            ],
            closed_pull_requests: vec![],
        };
        let analysis = analyze_snapshot(&snapshot);
        let md = render_ledger(&snapshot, &analysis);
        assert!(!md.contains("## Singleton Tails"));
    }

    #[test]
    fn ledger_renders_closed_donors_section() {
        let snapshot = BundleSnapshot {
            captured_at: "2026-04-01T00:00:00Z".into(),
            repository: "owner/repo".into(),
            open_pull_requests: vec![],
            closed_pull_requests: vec![ClosedPullRequestSnapshot {
                pr: PullRequestSnapshot {
                    number: 99,
                    state: "closed".into(),
                    title: "Old draft".into(),
                    head_ref: "codex/old-draft".into(),
                    base_ref: "main".into(),
                    author_login: None,
                    created_at: "2026-01-01T00:00:00Z".into(),
                    updated_at: "2026-01-01T00:00:00Z".into(),
                    merged_at: None,
                    closed_at: Some("2026-01-02T00:00:00Z".into()),
                    draft: true,
                    mergeable: None,
                    mergeable_state: None,
                    commits: 0,
                    changed_files: 0,
                    additions: 0,
                    deletions: 0,
                    labels: Vec::new(),
                    touched_paths: Vec::new(),
                },
            }],
        };
        let analysis = analyze_snapshot(&snapshot);
        let md = render_ledger(&snapshot, &analysis);
        // No bundles to match against, so closed donor is unmatched
        assert!(md.contains("## Closed Donors"));
        assert!(md.contains("#99"));
    }

    // ---------------------------------------------------------------
    // Helper function coverage
    // ---------------------------------------------------------------

    #[test]
    fn sanitize_replaces_non_alnum_with_dashes() {
        assert_eq!(sanitize("hello world"), "hello-world");
        assert_eq!(sanitize("foo/bar#baz"), "foo-bar-baz");
        assert_eq!(sanitize("---leading---trailing---"), "leading-trailing");
        assert_eq!(sanitize("UPPER"), "upper");
        assert_eq!(sanitize(""), "");
    }

    #[test]
    fn strip_codex_suffixes_removes_six_char_hex_like_tails() {
        assert_eq!(
            strip_codex_suffixes("add-ecdsa-support-ab12cd"),
            "add-ecdsa-support"
        );
        assert_eq!(
            strip_codex_suffixes("add-ecdsa-support-ab12cd-ef34gh"),
            "add-ecdsa-support"
        );
        assert_eq!(
            strip_codex_suffixes("add-ecdsa-support"),
            "add-ecdsa-support"
        );
        // Suffix with uppercase or non-alnum is not stripped
        assert_eq!(
            strip_codex_suffixes("add-ecdsa-support-AB12CD"),
            "add-ecdsa-support-AB12CD"
        );
        // Shorter than 6 chars is not stripped
        assert_eq!(
            strip_codex_suffixes("add-ecdsa-support-abc"),
            "add-ecdsa-support-abc"
        );
        // All-letter suffix (no digits) is not stripped — avoids stripping English words
        assert_eq!(strip_codex_suffixes("feature-branch"), "feature-branch");
        assert_eq!(strip_codex_suffixes("add-ecdsa-abcdef"), "add-ecdsa-abcdef");
    }

    #[test]
    fn canonical_head_ref_stem_with_refs_heads_prefix() {
        assert_eq!(
            canonical_head_ref_stem("refs/heads/codex/something-ab12cd"),
            "codex/something"
        );
    }

    #[test]
    fn canonical_head_ref_stem_simple_branch() {
        assert_eq!(canonical_head_ref_stem("main"), "main");
        assert_eq!(canonical_head_ref_stem("feature-branch"), "feature-branch");
    }

    #[test]
    fn tokenize_removes_stop_words() {
        let tokens = tokenize("Add initial support for the new crate");
        // "add", "initial", "support", "for", "the", "new", "crate" are all stop words
        assert!(tokens.is_empty());
    }

    #[test]
    fn tokenize_keeps_meaningful_words() {
        let tokens = tokenize("ECDSA P-256 adapter integration");
        assert!(tokens.contains("ecdsa"));
        assert!(tokens.contains("p"));
        assert!(tokens.contains("256"));
        assert!(tokens.contains("adapter"));
        assert!(tokens.contains("integration"));
    }

    #[test]
    fn jaccard_identical_sets_is_one() {
        let a: BTreeSet<String> = ["x", "y"].iter().map(|s| s.to_string()).collect();
        assert_eq!(jaccard(&a, &a), 1.0);
    }

    #[test]
    fn jaccard_disjoint_sets_is_zero() {
        let a: BTreeSet<String> = ["x"].iter().map(|s| s.to_string()).collect();
        let b: BTreeSet<String> = ["y"].iter().map(|s| s.to_string()).collect();
        assert_eq!(jaccard(&a, &b), 0.0);
    }

    #[test]
    fn jaccard_both_empty_is_one() {
        let empty: BTreeSet<String> = BTreeSet::new();
        assert_eq!(jaccard(&empty, &empty), 1.0);
    }

    #[test]
    fn jaccard_partial_overlap() {
        let a: BTreeSet<String> = ["x", "y", "z"].iter().map(|s| s.to_string()).collect();
        let b: BTreeSet<String> = ["y", "z", "w"].iter().map(|s| s.to_string()).collect();
        // intersection = {y, z} = 2, union = {x, y, z, w} = 4
        assert!((jaccard(&a, &b) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn path_fingerprints_includes_components() {
        let paths = vec!["crates/uselesskey-rsa/src/lib.rs".to_string()];
        let fps = path_fingerprints(&paths);
        assert!(fps.contains("crates/uselesskey-rsa/src/lib.rs"));
        assert!(fps.contains("lib.rs"));
        assert!(fps.contains("crates"));
        assert!(fps.contains("uselesskey-rsa"));
        assert!(fps.contains("src"));
    }

    #[test]
    fn summarize_checks_tallies_buckets() {
        let checks = vec![
            CheckSnapshot {
                name: "a".into(),
                bucket: "pass".into(),
                state: "s".into(),
            },
            CheckSnapshot {
                name: "b".into(),
                bucket: "pass".into(),
                state: "s".into(),
            },
            CheckSnapshot {
                name: "c".into(),
                bucket: "fail".into(),
                state: "s".into(),
            },
            CheckSnapshot {
                name: "d".into(),
                bucket: "pending".into(),
                state: "s".into(),
            },
        ];
        let summary = summarize_checks(&checks);
        assert_eq!(
            summary,
            CheckSummarySnapshot {
                pass: 2,
                fail: 1,
                pending: 1,
                skipping: 0,
                cancel: 0,
                total: 4,
            }
        );
    }

    #[test]
    fn make_bundle_id_with_stem() {
        assert_eq!(
            make_bundle_id(Some("ecdsa-support"), 1),
            "bundle-ecdsa-support-01"
        );
        assert_eq!(
            make_bundle_id(Some("ecdsa-support"), 12),
            "bundle-ecdsa-support-12"
        );
    }

    #[test]
    fn make_bundle_id_without_stem() {
        assert_eq!(make_bundle_id(None, 1), "bundle-01");
        assert_eq!(make_bundle_id(Some(""), 3), "bundle-03");
    }

    #[test]
    fn risk_level_display() {
        assert_eq!(format!("{}", RiskLevel::Low), "low");
        assert_eq!(format!("{}", RiskLevel::Medium), "medium");
        assert_eq!(format!("{}", RiskLevel::High), "high");
    }

    #[test]
    fn harvest_status_display() {
        assert_eq!(format!("{}", HarvestStatus::KeepVerbatim), "keep verbatim");
        assert_eq!(format!("{}", HarvestStatus::PortManually), "port manually");
        assert_eq!(
            format!("{}", HarvestStatus::AlreadyOnMain),
            "already on main"
        );
        assert_eq!(format!("{}", HarvestStatus::Stale), "stale / superseded");
        assert_eq!(format!("{}", HarvestStatus::Discard), "discard");
    }

    #[test]
    fn render_harvest_empty() {
        assert_eq!(render_harvest(&[]), "none");
    }

    #[test]
    fn render_harvest_formats_items() {
        let items = vec![
            HarvestDecision {
                pr_number: 10,
                status: HarvestStatus::KeepVerbatim,
                note: "good".into(),
            },
            HarvestDecision {
                pr_number: 11,
                status: HarvestStatus::Discard,
                note: "stale".into(),
            },
        ];
        let rendered = render_harvest(&items);
        assert_eq!(rendered, "#10: keep verbatim (good); #11: discard (stale)");
    }

    #[test]
    fn classify_risk_docs_only_is_low() {
        let profile = BundleProfile {
            canonical_stem: None,
            theme: "docs update".into(),
            touched_paths: ["docs/guide.md", "README.md"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };
        assert_eq!(classify_risk(&profile, &[]), RiskLevel::Low);
    }

    #[test]
    fn classify_risk_adapter_keyword_is_high() {
        let profile = BundleProfile {
            canonical_stem: None,
            theme: "adapter work".into(),
            touched_paths: ["crates/uselesskey-rsa/src/lib.rs"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };
        let prs = vec![open_pr(
            1,
            "RSA adapter",
            "codex/rsa-adapter-ab12cd",
            &["crates/uselesskey-rsa/src/lib.rs"],
            1,
            0,
            Some(true),
            1,
            10,
            1,
            1,
        )];
        assert_eq!(classify_risk(&profile, &prs), RiskLevel::High);
    }

    #[test]
    fn classify_risk_many_paths_is_high() {
        let paths: BTreeSet<String> = (0..10)
            .map(|i| format!("crates/crate-{i}/src/lib.rs"))
            .collect();
        let profile = BundleProfile {
            canonical_stem: None,
            theme: "big change".into(),
            touched_paths: paths,
        };
        assert_eq!(classify_risk(&profile, &[]), RiskLevel::High);
    }

    #[test]
    fn classify_risk_normal_code_change_is_medium() {
        let profile = BundleProfile {
            canonical_stem: None,
            theme: "feature".into(),
            touched_paths: ["crates/uselesskey-core/src/lib.rs"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };
        assert_eq!(classify_risk(&profile, &[]), RiskLevel::Medium);
    }

    #[test]
    fn keeper_score_ordering() {
        let better = KeeperScore {
            checks: 24,
            mergeable: 30,
            size: -16,
            commits: -5,
            stem: 40,
            pr_number: -10,
        };
        let worse = KeeperScore {
            checks: -90,
            mergeable: -120,
            size: -80,
            commits: -10,
            stem: 0,
            pr_number: -20,
        };
        assert!(better > worse);
    }

    #[test]
    fn score_checks_penalizes_empty() {
        let summary = CheckSummarySnapshot::default();
        let score = score_checks(&summary, &[]);
        assert_eq!(score, -8);
    }

    #[test]
    fn score_checks_rewards_passes_penalizes_failures() {
        let summary = CheckSummarySnapshot {
            pass: 3,
            fail: 1,
            pending: 0,
            skipping: 0,
            cancel: 0,
            total: 4,
        };
        let checks = vec![CheckSnapshot {
            name: "a".into(),
            bucket: "pass".into(),
            state: "s".into(),
        }];
        let score = score_checks(&summary, &checks);
        // 3*24 - 1*90 = 72 - 90 = -18
        assert_eq!(score, -18);
    }

    #[test]
    fn humanize_stem_strips_codex_prefix_and_replaces_separators() {
        assert_eq!(
            humanize_stem("codex/add-ecdsa-support"),
            "add ecdsa support"
        );
        assert_eq!(humanize_stem("feature_branch"), "feature branch");
    }

    #[test]
    fn title_similarity_identical_is_one() {
        assert_eq!(title_similarity("ECDSA adapter", "ECDSA adapter"), 1.0);
    }

    #[test]
    fn title_similarity_completely_different_is_zero() {
        // Words that are not stop words and share nothing
        assert_eq!(title_similarity("ECDSA adapter", "HMAC integration"), 0.0);
    }

    #[test]
    fn join_paths_empty_returns_none_string() {
        assert_eq!(join_paths(&[]), "none");
    }

    #[test]
    fn join_paths_multiple() {
        let paths = vec!["a.rs".to_string(), "b.rs".to_string()];
        assert_eq!(join_paths(&paths), "a.rs, b.rs");
    }

    // ---------------------------------------------------------------
    // Snapshot/Ledger command constructors
    // ---------------------------------------------------------------

    #[test]
    fn snapshot_command_defaults() {
        let cmd = SnapshotCommand::new(None);
        assert_eq!(
            cmd.output_path,
            PathBuf::from("target/xtask/pr-bundles/snapshot.json")
        );
        assert!(cmd.repository.is_none());
        assert!(!cmd.include_closed_paths);
    }

    #[test]
    fn ledger_command_defaults() {
        let cmd = LedgerCommand::new("my-snapshot.json");
        assert_eq!(cmd.snapshot_path, PathBuf::from("my-snapshot.json"));
        assert_eq!(
            cmd.output_path,
            Some(PathBuf::from("target/xtask/pr-bundles/ledger.md"))
        );
    }

    // ---------------------------------------------------------------
    // End-to-end: snapshot JSON -> analysis -> ledger
    // ---------------------------------------------------------------

    #[test]
    fn end_to_end_snapshot_to_ledger() {
        let snapshot: BundleSnapshot =
            serde_json::from_str(SAMPLE_SNAPSHOT_JSON).expect("parse fixture");
        let analysis = analyze_snapshot(&snapshot);
        let md = render_ledger(&snapshot, &analysis);

        // Single PR is a singleton (not enough for a bundle)
        assert!(analysis.bundles.is_empty());
        assert_eq!(analysis.singleton_tails.len(), 1);
        assert_eq!(analysis.singleton_tails[0].pr.number, 100);

        // Ledger still renders the header properly
        assert!(md.contains("# PR Bundle Ledger"));
        assert!(md.contains("EffortlessMetrics/uselesskey"));
    }
}
