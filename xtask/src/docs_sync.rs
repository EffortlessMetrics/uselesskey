use std::collections::BTreeSet;
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
    crate_support_matrix: Vec<SupportEntry>,
    runnable_examples: Vec<ExampleEntry>,
    facade_feature_matrix: Vec<FeatureMatrixEntry>,
    adapter_feature_matrix: Vec<AdapterMatrixEntry>,
    dependency_snippets: Vec<DependencySnippet>,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SupportTier {
    Stable,
    Incubating,
    Experimental,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum PublishStatus {
    Published,
    Internal,
    TestOnly,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum IntendedAudience {
    MostUsers,
    AdapterUsers,
    RepoInternal,
}

#[derive(Debug, Deserialize)]
struct SupportEntry {
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
    validate_support_matrix(&root, &metadata)?;
    let readme_path = root.join("README.md");
    let support_matrix_path = root.join("docs/reference/support-matrix.md");
    let original = fs::read_to_string(&readme_path).context("failed to read README.md")?;
    let updated = rewrite_document(&original, &metadata)?;
    let support_matrix = render_support_matrix_document(&metadata);
    let support_original = fs::read_to_string(&support_matrix_path)
        .context("failed to read docs/reference/support-matrix.md")?;

    if updated == original && support_matrix == support_original {
        if check {
            println!("docs-sync: README.md and support-matrix.md are already synchronized");
            return Ok(());
        }
        return Ok(());
    }

    if check {
        let mut messages = Vec::new();
        if updated != original {
            messages.push("README.md");
        }
        if support_matrix != support_original {
            messages.push("docs/reference/support-matrix.md");
        }
        bail!(
            "docs-sync check failed: {} out of sync with docs/metadata/workspace-docs.json",
            messages.join(", ")
        );
    }

    if updated != original {
        fs::write(&readme_path, updated).context("failed to write README.md")?;
        println!("docs-sync: updated README.md");
    }
    if support_matrix != support_original {
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

    let mut output = replace_block(input, "dependency-snippets", &dependency_snippets)?;
    output = replace_block(&output, "runnable-examples", &examples)?;
    output = replace_block(&output, "workspace-crates", &workspace_crates)?;
    output = replace_block(&output, "adapter-crates", &adapter_crates)?;
    output = replace_block(&output, "feature-matrix-facade", &feature_facade)?;
    output = replace_block(&output, "feature-matrix-adapters", &feature_adapters)?;
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

fn render_support_matrix_document(metadata: &DocsMetadata) -> String {
    let mut output = String::new();
    output.push_str("# Support matrix\n\n");
    output.push_str(
        "This page is generated from `docs/metadata/workspace-docs.json` by `cargo xtask docs-sync`.\n\n",
    );
    output.push_str("| Crate | Support tier | Publish status | Facade exposed | Intended audience | SemVer expectation | MSRV policy | Replacement / deprecation |\n");
    output.push_str("|-------|--------------|----------------|----------------|-------------------|--------------------|-------------|---------------------------|\n");

    for entry in &metadata.crate_support_matrix {
        let _ = writeln!(
            output,
            "| {} | `{}` | `{}` | {} | `{}` | {} | {} | {} |",
            crate_link(&entry.name),
            support_tier_label(&entry.support_tier),
            publish_status_label(&entry.publish_status),
            checkmark(entry.facade_exposed),
            audience_label(&entry.intended_audience),
            entry.semver_expectation,
            entry.msrv_policy,
            replacement_or_deprecation(entry)
        );
    }

    output
}

fn replacement_or_deprecation(entry: &SupportEntry) -> String {
    match (&entry.replacement_path, &entry.deprecation_note) {
        (Some(path), Some(note)) => format!("{path}; {note}"),
        (Some(path), None) => path.clone(),
        (None, Some(note)) => note.clone(),
        (None, None) => "—".to_string(),
    }
}

fn support_tier_label(tier: &SupportTier) -> &'static str {
    match tier {
        SupportTier::Stable => "stable",
        SupportTier::Incubating => "incubating",
        SupportTier::Experimental => "experimental",
    }
}

fn publish_status_label(status: &PublishStatus) -> &'static str {
    match status {
        PublishStatus::Published => "published",
        PublishStatus::Internal => "internal",
        PublishStatus::TestOnly => "test-only",
    }
}

fn audience_label(audience: &IntendedAudience) -> &'static str {
    match audience {
        IntendedAudience::MostUsers => "most-users",
        IntendedAudience::AdapterUsers => "adapter-users",
        IntendedAudience::RepoInternal => "repo-internal",
    }
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

fn validate_support_matrix(root: &Path, metadata: &DocsMetadata) -> Result<()> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .context("failed to run `cargo metadata` for support matrix validation")?;
    if !output.status.success() {
        bail!(
            "`cargo metadata` failed during support matrix validation: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    #[derive(Deserialize)]
    struct CargoMeta {
        packages: Vec<CargoPkg>,
    }
    #[derive(Deserialize)]
    struct CargoPkg {
        name: String,
    }

    let cargo_meta: CargoMeta = serde_json::from_slice(&output.stdout)
        .context("failed to parse cargo metadata JSON for support matrix validation")?;
    let workspace_crates: BTreeSet<String> = cargo_meta.packages.into_iter().map(|p| p.name).collect();
    let support_crates: BTreeSet<String> = metadata
        .crate_support_matrix
        .iter()
        .map(|entry| entry.name.clone())
        .collect();

    let mut errors = Vec::new();
    for missing in workspace_crates.difference(&support_crates) {
        errors.push(format!("missing support metadata for workspace crate `{missing}`"));
    }
    for extra in support_crates.difference(&workspace_crates) {
        errors.push(format!("support metadata includes unknown crate `{extra}`"));
    }

    for entry in &metadata.crate_support_matrix {
        if entry.publish_status == PublishStatus::TestOnly
            && entry.intended_audience != IntendedAudience::RepoInternal
        {
            errors.push(format!(
                "illegal combination for `{}`: `test-only` crates must use `repo-internal` audience",
                entry.name
            ));
        }
        if entry.publish_status != PublishStatus::Published && entry.facade_exposed {
            errors.push(format!(
                "illegal combination for `{}`: only `published` crates can be facade-exposed",
                entry.name
            ));
        }
        if entry.semver_expectation.trim().is_empty() {
            errors.push(format!(
                "invalid metadata for `{}`: `semver_expectation` cannot be empty",
                entry.name
            ));
        }
        if entry.msrv_policy.trim().is_empty() {
            errors.push(format!(
                "invalid metadata for `{}`: `msrv_policy` cannot be empty",
                entry.name
            ));
        }
    }

    if !errors.is_empty() {
        bail!("support matrix metadata errors:\n- {}", errors.join("\n- "));
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_matrix_requires_repo_internal_for_test_only() {
        let metadata: DocsMetadata =
            serde_json::from_str(include_str!("../../docs/metadata/workspace-docs.json"))
                .expect("metadata JSON should parse");
        let invalid = SupportEntry {
            name: "invalid-crate".to_string(),
            support_tier: SupportTier::Stable,
            publish_status: PublishStatus::TestOnly,
            facade_exposed: false,
            semver_expectation: "test".to_string(),
            msrv_policy: "test".to_string(),
            intended_audience: IntendedAudience::MostUsers,
            replacement_path: None,
            deprecation_note: None,
        };
        let mut with_invalid = metadata.crate_support_matrix;
        with_invalid.push(invalid);
        let metadata = DocsMetadata {
            workspace_crates: Vec::new(),
            adapter_crates: Vec::new(),
            crate_support_matrix: with_invalid,
            runnable_examples: Vec::new(),
            facade_feature_matrix: Vec::new(),
            adapter_feature_matrix: Vec::new(),
            dependency_snippets: Vec::new(),
        };

        let err = validate_support_matrix(Path::new("."), &metadata).expect_err("must fail");
        assert!(err
            .to_string()
            .contains("`test-only` crates must use `repo-internal` audience"));
    }

    #[test]
    fn support_matrix_render_snapshot_contains_expected_columns() {
        let metadata: DocsMetadata =
            serde_json::from_str(include_str!("../../docs/metadata/workspace-docs.json"))
                .expect("metadata JSON should parse");
        let rendered = render_support_matrix_document(&metadata);
        assert!(rendered.contains("| Crate | Support tier | Publish status | Facade exposed |"));
        assert!(rendered.contains("[`uselesskey`](https://crates.io/crates/uselesskey)"));
    }
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
