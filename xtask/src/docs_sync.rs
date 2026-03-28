use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const METADATA_PATH: &str = "docs/metadata/workspace-docs.json";
const MARKER_PREFIX: &str = "docs-sync:";

#[derive(Debug, Deserialize)]
struct DocsMetadata {
    workspace_crates: Vec<CrateEntry>,
    adapter_crates: Vec<CrateEntry>,
    runnable_examples: Vec<ExampleEntry>,
    facade_feature_matrix: Vec<FeatureMatrixEntry>,
    adapter_feature_matrix: Vec<AdapterMatrixEntry>,
    dependency_snippets: Vec<DependencySnippet>,
    crate_support_matrix: Vec<SupportMatrixEntry>,
}

#[derive(Debug, Deserialize)]
struct CrateEntry {
    name: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct ExampleEntry {
    name: String,
    path: String,
    feature_set: String,
    description: String,
    run_smoke: bool,
}

#[derive(Debug, Deserialize)]
struct FeatureMatrixEntry {
    feature: String,
    extension_trait: String,
    algorithms: String,
    implies: String,
}

#[derive(Debug, Deserialize)]
struct AdapterMatrixEntry {
    adapter: String,
    rsa: bool,
    ecdsa: bool,
    ed25519: bool,
    hmac: bool,
    x509_tls: bool,
    extra_features: String,
}

#[derive(Debug, Deserialize)]
struct DependencySnippet {
    name: String,
    snippet: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
enum SupportTier {
    Stable,
    Incubating,
    Experimental,
}

impl SupportTier {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Incubating => "incubating",
            Self::Experimental => "experimental",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
enum PublishStatus {
    Published,
    Internal,
    TestOnly,
}

impl PublishStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Internal => "internal",
            Self::TestOnly => "test-only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
enum IntendedAudience {
    MostUsers,
    AdapterUsers,
    RepoInternal,
}

impl IntendedAudience {
    fn as_str(self) -> &'static str {
        match self {
            Self::MostUsers => "most-users",
            Self::AdapterUsers => "adapter-users",
            Self::RepoInternal => "repo-internal",
        }
    }
}

#[derive(Debug, Deserialize)]
struct SupportMatrixEntry {
    name: String,
    support_tier: SupportTier,
    publish_status: PublishStatus,
    facade_exposed: bool,
    semver_expectation: String,
    msrv_policy: String,
    intended_audience: IntendedAudience,
    replacement_path: Option<String>,
    deprecation_note: Option<String>,
}

pub fn docs_sync_cmd(check: bool) -> Result<()> {
    run_docs_sync(check)?;
    Ok(())
}

pub fn examples_smoke_cmd(run: bool) -> Result<()> {
    run_docs_sync(true)?;

    let root = crate::workspace_root_path();
    let metadata = load_metadata(&root)?;
    validate_examples_match_workspace(&root, &metadata)?;

    for example in &metadata.runnable_examples {
        compile_example(&root, example)?;
        if run && example.run_smoke {
            run_example(&root, example)?;
        }
    }

    Ok(())
}

fn run_docs_sync(check: bool) -> Result<()> {
    let root = crate::workspace_root_path();
    let metadata = load_metadata(&root)?;
    validate_crate_support_metadata(&root, &metadata)?;
    let readme_path = root.join("README.md");
    let support_matrix_path = root.join("docs/reference/support-matrix.md");
    let original = fs::read_to_string(&readme_path).context("failed to read README.md")?;
    let updated = rewrite_document(&original, &metadata)?;
    let support_matrix = render_support_matrix_doc(&metadata);

    let matrix_needs_update = match fs::read_to_string(&support_matrix_path) {
        Ok(existing) => existing != support_matrix,
        Err(_) => true,
    };

    if updated == original && !matrix_needs_update {
        if check {
            println!("docs-sync: docs are already synchronized");
            return Ok(());
        }
        return Ok(());
    }

    if check {
        bail!(
            "docs-sync check failed: generated docs are out of sync with docs/metadata/workspace-docs.json"
        );
    }

    if updated != original {
        fs::write(&readme_path, updated).context("failed to write README.md")?;
        println!("docs-sync: updated README.md");
    }
    if matrix_needs_update {
        fs::write(&support_matrix_path, support_matrix)
            .context("failed to write docs/reference/support-matrix.md")?;
        println!("docs-sync: updated docs/reference/support-matrix.md");
    }
    Ok(())
}

fn load_metadata(root: &Path) -> Result<DocsMetadata> {
    let path = root.join(METADATA_PATH);
    let raw = fs::read_to_string(&path).context("failed to read docs metadata file")?;
    serde_json::from_str(&raw).context("invalid docs metadata JSON")
}

fn crate_link(name: &str) -> String {
    format!("[`{}`](https://crates.io/crates/{})", name, name)
}

fn rewrite_document(input: &str, metadata: &DocsMetadata) -> Result<String> {
    let dependency_snippets = render_dependency_snippets(metadata);
    let examples = render_example_table(metadata);
    let workspace_crates = render_crate_table("workspace crate", &metadata.workspace_crates);
    let adapter_crates = render_crate_table("adapter crate", &metadata.adapter_crates);
    let feature_facade = render_facade_feature_matrix(metadata);
    let feature_adapters = render_adapter_feature_matrix(metadata);
    let support_summary = render_support_summary(metadata);

    let mut output = replace_block(input, "dependency-snippets", &dependency_snippets)?;
    output = replace_block(&output, "runnable-examples", &examples)?;
    output = replace_block(&output, "workspace-crates", &workspace_crates)?;
    output = replace_block(&output, "adapter-crates", &adapter_crates)?;
    output = replace_block(&output, "feature-matrix-facade", &feature_facade)?;
    output = replace_block(&output, "feature-matrix-adapters", &feature_adapters)?;
    output = replace_block(&output, "support-matrix-summary", &support_summary)?;
    Ok(output)
}

fn render_dependency_snippets(metadata: &DocsMetadata) -> String {
    let mut output = String::new();
    output.push_str("Dependency snippets:");
    output.push('\n');
    for item in &metadata.dependency_snippets {
        writeln!(
            output,
            "- **{}**\n  ```toml\n{}\n  ```\n",
            item.name,
            indent_lines(&item.snippet, "  ")
        )
        .expect("write to string");
        output.push('\n');
    }
    output
}

fn render_crate_table(_kind: &str, entries: &[CrateEntry]) -> String {
    let mut output = String::new();
    output.push_str("| Crate | Description |\n|-------|-------------|\n");
    for entry in entries {
        let _ = writeln!(
            output,
            "| {} | {} |",
            crate_link(&entry.name),
            entry.description
        );
    }
    output
}

fn render_example_table(metadata: &DocsMetadata) -> String {
    let mut output = String::new();
    output.push_str(
        "| Example | Feature(s) | Description |\n|---------|------------|-------------|\n",
    );

    for example in &metadata.runnable_examples {
        let feature_set = if example.feature_set.trim().is_empty() {
            "—".to_string()
        } else {
            format!("`{}`", example.feature_set)
        };
        let _ = writeln!(
            output,
            "| [{}]({}) | {} | {} |",
            example.name, example.path, feature_set, example.description
        );
    }

    output
}

fn render_facade_feature_matrix(metadata: &DocsMetadata) -> String {
    let mut output = String::new();
    output.push_str("| Feature | Extension Trait | Algorithms / Outputs | Implies |\n|---------|----------------|---------------------|---------|\n");

    for feature in &metadata.facade_feature_matrix {
        let trait_value = if feature.extension_trait == "-" {
            "—".to_string()
        } else {
            format!("`{}`", feature.extension_trait)
        };
        let implies_value = if feature.implies == "-" {
            "—".to_string()
        } else {
            format!("`{}`", feature.implies.replace(' ', "` `"))
        };

        let _ = writeln!(
            output,
            "| `{}` | {} | {} | {} |",
            feature.feature, trait_value, feature.algorithms, implies_value
        );
    }

    output
}

fn render_adapter_feature_matrix(metadata: &DocsMetadata) -> String {
    let mut output = String::new();
    output.push_str(
        "| Adapter | RSA | ECDSA | Ed25519 | HMAC | X.509 / TLS | Extra features |\n|---------|:---:|:-----:|:-------:|:----:|:-----------:|----------------|\n",
    );
    for row in &metadata.adapter_feature_matrix {
        let _ = writeln!(
            output,
            "| `{}` | {} | {} | {} | {} | {} | {} |",
            row.adapter,
            checkmark(row.rsa),
            checkmark(row.ecdsa),
            checkmark(row.ed25519),
            checkmark(row.hmac),
            checkmark(row.x509_tls),
            if row.extra_features.trim().is_empty() {
                "—".to_string()
            } else {
                format!("`{}`", row.extra_features)
            }
        );
    }

    output
}

fn render_support_summary(metadata: &DocsMetadata) -> String {
    let mut by_tier = BTreeMap::<&str, usize>::new();
    let mut by_status = BTreeMap::<&str, usize>::new();

    for row in &metadata.crate_support_matrix {
        *by_tier.entry(row.support_tier.as_str()).or_default() += 1;
        *by_status.entry(row.publish_status.as_str()).or_default() += 1;
    }

    let mut output = String::new();
    output.push_str("| Contract | Count |\n|----------|------:|\n");
    for tier in ["stable", "incubating", "experimental"] {
        let _ = writeln!(
            output,
            "| `support_tier={tier}` | {} |",
            by_tier.get(tier).copied().unwrap_or_default()
        );
    }
    for status in ["published", "internal", "test-only"] {
        let _ = writeln!(
            output,
            "| `publish_status={status}` | {} |",
            by_status.get(status).copied().unwrap_or_default()
        );
    }
    output.push_str("\nSee [Support matrix](docs/reference/support-matrix.md) for crate-level details.");
    output
}

fn render_support_matrix_doc(metadata: &DocsMetadata) -> String {
    let mut rows = metadata.crate_support_matrix.iter().collect::<Vec<_>>();
    rows.sort_by(|left, right| left.name.cmp(&right.name));

    let mut output = String::new();
    output.push_str("# Support Matrix\n\n");
    output.push_str(
        "_Generated from `docs/metadata/workspace-docs.json` by `cargo xtask docs-sync`._\n\n",
    );
    output.push_str("| Crate | support_tier | publish_status | facade_exposed | intended_audience | semver_expectation | msrv_policy | replacement/deprecation |\n");
    output.push_str("|-------|--------------|----------------|:--------------:|-------------------|--------------------|-------------|-------------------------|\n");

    for row in rows {
        let replacement = row
            .replacement_path
            .as_deref()
            .or(row.deprecation_note.as_deref())
            .unwrap_or("—");
        let _ = writeln!(
            output,
            "| `{}` | `{}` | `{}` | {} | `{}` | {} | {} | {} |",
            row.name,
            row.support_tier.as_str(),
            row.publish_status.as_str(),
            checkmark(row.facade_exposed),
            row.intended_audience.as_str(),
            row.semver_expectation,
            row.msrv_policy,
            replacement
        );
    }

    output
}

fn checkmark(enabled: bool) -> String {
    if enabled {
        "✓".to_string()
    } else {
        "—".to_string()
    }
}

fn replace_block(input: &str, marker: &str, replacement: &str) -> Result<String> {
    let start_marker = format!("<!-- {MARKER_PREFIX}{marker}-start -->");
    let end_marker = format!("<!-- {MARKER_PREFIX}{marker}-end -->");
    let start_pos = input
        .find(&start_marker)
        .with_context(|| format!("missing start marker {start_marker}"))?;
    let rest = &input[(start_pos + start_marker.len())..];
    let end_pos = rest
        .find(&end_marker)
        .with_context(|| format!("missing end marker {end_marker}"))?;
    let end_pos_abs = start_pos + start_marker.len() + end_pos;
    let replacement_block = replacement.trim_end();
    let before = &input[..start_pos];
    let after = &input[end_pos_abs + end_marker.len()..];
    Ok(format!(
        "{before}{start_marker}\n{replacement_block}\n{end_marker}{after}"
    ))
}

fn compile_example(root: &Path, example: &ExampleEntry) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root);
    cmd.args([
        "build",
        "-p",
        "uselesskey",
        "--example",
        &example.name,
        "--no-default-features",
    ]);
    if !example.feature_set.trim().is_empty() {
        cmd.args(["--features", &example.feature_set]);
    }
    crate::run(&mut cmd).with_context(|| format!("cargo build failed for example {}", example.name))
}

fn run_example(root: &Path, example: &ExampleEntry) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root);
    cmd.args([
        "run",
        "-p",
        "uselesskey",
        "--example",
        &example.name,
        "--no-default-features",
    ]);
    if !example.feature_set.trim().is_empty() {
        cmd.args(["--features", &example.feature_set]);
    }
    crate::run(&mut cmd).with_context(|| format!("cargo run failed for example {}", example.name))
}

fn validate_examples_match_workspace(root: &Path, metadata: &DocsMetadata) -> Result<()> {
    let mut seen_paths = BTreeSet::new();
    let mut metadata_paths = BTreeSet::new();
    let mut errors = Vec::new();

    for entry in &metadata.runnable_examples {
        let normalized_path = normalize_path_string(Path::new(&entry.path));
        if !seen_paths.insert(normalized_path.clone()) {
            errors.push(format!(
                "metadata contains duplicate example path: {normalized_path}"
            ));
        }

        let file_stem = Path::new(&entry.path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if file_stem != entry.name {
            errors.push(format!(
                "example name mismatch: metadata name '{}' does not match file stem '{}'",
                entry.name, file_stem
            ));
        }

        metadata_paths.insert(normalized_path);
    }

    let examples_dir = root.join("crates/uselesskey/examples");
    let mut filesystem_paths = BTreeSet::new();
    for entry in fs::read_dir(&examples_dir).context("failed to read example directory")? {
        let path = entry.context("failed to read example entry")?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .context("example file is outside workspace root")?;
        filesystem_paths.insert(normalize_path_string(relative));
    }

    let missing_in_metadata: Vec<String> = filesystem_paths
        .difference(&metadata_paths)
        .cloned()
        .collect();
    let missing_in_filesystem: Vec<String> = metadata_paths
        .iter()
        .filter(|path| !root.join(path).exists())
        .cloned()
        .collect();

    if !missing_in_metadata.is_empty() {
        errors.push(format!(
            "examples found on disk but missing from metadata:\n- {}",
            missing_in_metadata.join("\n- ")
        ));
    }
    if !missing_in_filesystem.is_empty() {
        errors.push(format!(
            "metadata paths missing on disk:\n- {}",
            missing_in_filesystem.join("\n- ")
        ));
    }

    if !errors.is_empty() {
        bail!("example metadata drift:\n{}", errors.join("\n"));
    }

    Ok(())
}

fn validate_crate_support_metadata(root: &Path, metadata: &DocsMetadata) -> Result<()> {
    let workspace_crates = workspace_package_names(root)?;
    let errors = collect_support_metadata_errors(&workspace_crates, &metadata.crate_support_matrix);

    if !errors.is_empty() {
        bail!("support metadata drift:\n{}", errors.join("\n"));
    }
    Ok(())
}

fn collect_support_metadata_errors(
    workspace_crates: &BTreeSet<String>,
    entries: &[SupportMatrixEntry],
) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut errors = Vec::new();

    for entry in entries {
        if !seen.insert(entry.name.clone()) {
            errors.push(format!("duplicate support metadata entry for crate '{}'", entry.name));
        }
        if entry.publish_status == PublishStatus::TestOnly
            && (entry.intended_audience == IntendedAudience::MostUsers
                || entry.intended_audience == IntendedAudience::AdapterUsers)
        {
            errors.push(format!(
                "illegal support metadata combination for '{}': test-only crates cannot target {}",
                entry.name,
                entry.intended_audience.as_str()
            ));
        }
    }

    let metadata_crates: BTreeSet<String> = entries.iter().map(|entry| entry.name.clone()).collect();
    let missing: Vec<String> = workspace_crates
        .difference(&metadata_crates)
        .cloned()
        .collect();
    let unknown: Vec<String> = metadata_crates
        .difference(workspace_crates)
        .cloned()
        .collect();

    if !missing.is_empty() {
        errors.push(format!(
            "workspace crates missing from crate_support_matrix:\n- {}",
            missing.join("\n- ")
        ));
    }
    if !unknown.is_empty() {
        errors.push(format!(
            "crate_support_matrix contains unknown crates:\n- {}",
            unknown.join("\n- ")
        ));
    }

    errors
}

fn workspace_package_names(root: &Path) -> Result<BTreeSet<String>> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .context("failed to run `cargo metadata` for support matrix validation")?;

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
        .filter_map(|item| item.as_str())
        .collect::<BTreeSet<_>>();

    let mut names = BTreeSet::new();
    for pkg in meta["packages"]
        .as_array()
        .context("missing 'packages' in cargo metadata")?
    {
        let Some(id) = pkg["id"].as_str() else {
            continue;
        };
        if workspace_members.contains(id)
            && let Some(name) = pkg["name"].as_str()
        {
            names.insert(name.to_string());
        }
    }
    Ok(names)
}

fn normalize_path_string(path: &Path) -> String {
    path.iter()
        .map(|part| part.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn indent_lines(text: &str, indent: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let _ = writeln!(out, "{}{}", indent, line);
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(name: &str) -> SupportMatrixEntry {
        SupportMatrixEntry {
            name: name.to_string(),
            support_tier: SupportTier::Stable,
            publish_status: PublishStatus::Published,
            facade_exposed: false,
            semver_expectation: "semver".to_string(),
            msrv_policy: "msrv".to_string(),
            intended_audience: IntendedAudience::RepoInternal,
            replacement_path: None,
            deprecation_note: None,
        }
    }

    #[test]
    fn support_matrix_snapshot_render() {
        let metadata = DocsMetadata {
            workspace_crates: Vec::new(),
            adapter_crates: Vec::new(),
            runnable_examples: Vec::new(),
            facade_feature_matrix: Vec::new(),
            adapter_feature_matrix: Vec::new(),
            dependency_snippets: Vec::new(),
            crate_support_matrix: vec![sample_entry("a-crate"), sample_entry("b-crate")],
        };

        let rendered = render_support_matrix_doc(&metadata);
        assert!(rendered.contains("| `a-crate` | `stable` | `published` | — | `repo-internal`"));
        assert!(rendered.contains("# Support Matrix"));
    }

    #[test]
    fn support_summary_counts_by_tier_and_status() {
        let mut stable = sample_entry("stable");
        stable.support_tier = SupportTier::Stable;
        stable.publish_status = PublishStatus::Published;
        let mut incubating = sample_entry("incubating");
        incubating.support_tier = SupportTier::Incubating;
        incubating.publish_status = PublishStatus::Internal;
        let mut experimental = sample_entry("experimental");
        experimental.support_tier = SupportTier::Experimental;
        experimental.publish_status = PublishStatus::TestOnly;

        let metadata = DocsMetadata {
            workspace_crates: Vec::new(),
            adapter_crates: Vec::new(),
            runnable_examples: Vec::new(),
            facade_feature_matrix: Vec::new(),
            adapter_feature_matrix: Vec::new(),
            dependency_snippets: Vec::new(),
            crate_support_matrix: vec![stable, incubating, experimental],
        };

        let rendered = render_support_summary(&metadata);
        assert!(rendered.contains("`support_tier=stable` | 1"));
        assert!(rendered.contains("`support_tier=incubating` | 1"));
        assert!(rendered.contains("`support_tier=experimental` | 1"));
        assert!(rendered.contains("`publish_status=test-only` | 1"));
    }

    #[test]
    fn metadata_completeness_validation_reports_missing_and_unknown_crates() {
        let workspace = BTreeSet::from(["crate-a".to_string(), "crate-b".to_string()]);
        let entries = vec![sample_entry("crate-a"), sample_entry("crate-c")];
        let errors = collect_support_metadata_errors(&workspace, &entries);

        assert!(
            errors.iter().any(|item| item.contains("missing from crate_support_matrix")),
            "expected missing crate error, got: {errors:#?}"
        );
        assert!(
            errors.iter().any(|item| item.contains("contains unknown crates")),
            "expected unknown crate error, got: {errors:#?}"
        );
    }

    #[test]
    fn illegal_combination_validation_rejects_test_only_for_most_users() {
        let workspace = BTreeSet::from(["crate-a".to_string()]);
        let mut entry = sample_entry("crate-a");
        entry.publish_status = PublishStatus::TestOnly;
        entry.intended_audience = IntendedAudience::MostUsers;
        let errors = collect_support_metadata_errors(&workspace, &[entry]);

        assert!(
            errors
                .iter()
                .any(|item| item.contains("test-only crates cannot target most-users")),
            "expected illegal-combination error, got: {errors:#?}"
        );
    }
}
