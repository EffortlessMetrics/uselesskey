use std::collections::BTreeSet;
use std::fmt::Write;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const METADATA_PATH: &str = "docs/metadata/workspace-docs.json";
const SUPPORT_MATRIX_PATH: &str = "docs/reference/support-matrix.md";
const MARKER_PREFIX: &str = "docs-sync:";

#[derive(Debug, Deserialize)]
struct DocsMetadata {
    workspace_crates: Vec<CrateEntry>,
    adapter_crates: Vec<CrateEntry>,
    runnable_examples: Vec<ExampleEntry>,
    facade_feature_matrix: Vec<FeatureMatrixEntry>,
    adapter_feature_matrix: Vec<AdapterMatrixEntry>,
    dependency_snippets: Vec<DependencySnippet>,
    crate_support_matrix: Vec<CrateSupportEntry>,
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
struct CrateSupportEntry {
    name: String,
    description: String,
    support_tier: String,
    publish_status: String,
    facade_exposed: bool,
    semver_expectation: String,
    msrv_policy: String,
    intended_audience: String,
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
    validate_crate_support_matrix(&root, &metadata)?;
    let readme_path = root.join("README.md");
    let support_matrix_path = root.join(SUPPORT_MATRIX_PATH);
    let original = fs::read_to_string(&readme_path).context("failed to read README.md")?;
    let updated = rewrite_document(&original, &metadata)?;
    let support_matrix_updated = render_support_matrix_doc(&metadata);
    let support_matrix_original = if support_matrix_path.exists() {
        fs::read_to_string(&support_matrix_path).context("failed to read support-matrix.md")?
    } else {
        String::new()
    };

    if updated == original && support_matrix_updated == support_matrix_original {
        if check {
            println!("docs-sync: README.md and support-matrix.md are already synchronized");
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
    if support_matrix_updated != support_matrix_original {
        fs::write(&support_matrix_path, support_matrix_updated)
            .context("failed to write support-matrix.md")?;
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
    let support_summary = render_support_summary_table(metadata);
    let feature_facade = render_facade_feature_matrix(metadata);
    let feature_adapters = render_adapter_feature_matrix(metadata);

    let mut output = replace_block(input, "dependency-snippets", &dependency_snippets)?;
    output = replace_block(&output, "runnable-examples", &examples)?;
    output = replace_block(&output, "workspace-crates", &workspace_crates)?;
    output = replace_block(&output, "adapter-crates", &adapter_crates)?;
    output = replace_block(&output, "support-summary", &support_summary)?;
    output = replace_block(&output, "feature-matrix-facade", &feature_facade)?;
    output = replace_block(&output, "feature-matrix-adapters", &feature_adapters)?;
    Ok(output)
}

fn render_support_summary_table(metadata: &DocsMetadata) -> String {
    let mut output = String::new();
    output.push_str("| Crate | Support tier | Publish status | Audience |\n");
    output.push_str("|------|--------------|----------------|----------|\n");
    for row in metadata
        .crate_support_matrix
        .iter()
        .filter(|entry| entry.intended_audience == "most-users" || entry.intended_audience == "adapter-users")
    {
        let _ = writeln!(
            output,
            "| `{}` | `{}` | `{}` | `{}` |",
            row.name, row.support_tier, row.publish_status, row.intended_audience
        );
    }
    output
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

fn render_support_matrix_doc(metadata: &DocsMetadata) -> String {
    let mut output = String::new();
    output.push_str("# Support matrix\n\n");
    output.push_str(
        "This page is generated from `docs/metadata/workspace-docs.json` by `cargo xtask docs-sync`.\n\n",
    );
    output.push_str("| Crate | Description | support_tier | publish_status | facade_exposed | semver_expectation | msrv_policy | intended_audience | Notes |\n");
    output.push_str("|------|-------------|--------------|----------------|----------------|--------------------|-------------|-------------------|-------|\n");
    for entry in &metadata.crate_support_matrix {
        let notes = match (&entry.replacement_path, &entry.deprecation_note) {
            (Some(path), Some(note)) => format!("replacement: `{path}`; {note}"),
            (Some(path), None) => format!("replacement: `{path}`"),
            (None, Some(note)) => note.clone(),
            (None, None) => "—".to_string(),
        };
        let _ = writeln!(
            output,
            "| `{}` | {} | `{}` | `{}` | `{}` | {} | {} | `{}` | {} |",
            entry.name,
            entry.description,
            entry.support_tier,
            entry.publish_status,
            entry.facade_exposed,
            entry.semver_expectation,
            entry.msrv_policy,
            entry.intended_audience,
            notes
        );
    }
    output
}

fn validate_crate_support_matrix(root: &Path, metadata: &DocsMetadata) -> Result<()> {
    let known = workspace_crate_names(root)?;
    validate_support_entries(&known, &metadata.crate_support_matrix)
}

fn validate_support_entries(
    known: &BTreeSet<String>,
    entries: &[CrateSupportEntry],
) -> Result<()> {
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();

    for entry in entries {
        if !seen.insert(entry.name.clone()) {
            errors.push(format!("duplicate support-matrix entry for `{}`", entry.name));
        }
        if !known.contains(&entry.name) {
            errors.push(format!(
                "support-matrix entry `{}` does not match a workspace crate",
                entry.name
            ));
        }

        if !matches!(
            entry.support_tier.as_str(),
            "stable" | "incubating" | "experimental"
        ) {
            errors.push(format!(
                "{}: invalid support_tier `{}`",
                entry.name, entry.support_tier
            ));
        }
        if !matches!(entry.publish_status.as_str(), "published" | "internal" | "test-only") {
            errors.push(format!(
                "{}: invalid publish_status `{}`",
                entry.name, entry.publish_status
            ));
        }
        if !matches!(
            entry.intended_audience.as_str(),
            "most-users" | "adapter-users" | "repo-internal"
        ) {
            errors.push(format!(
                "{}: invalid intended_audience `{}`",
                entry.name, entry.intended_audience
            ));
        }
        if entry.publish_status == "test-only" && entry.intended_audience != "repo-internal" {
            errors.push(format!(
                "{}: illegal combination `test-only` + `{}`",
                entry.name, entry.intended_audience
            ));
        }
        if entry.facade_exposed && entry.intended_audience != "most-users" {
            errors.push(format!(
                "{}: facade_exposed=true requires intended_audience `most-users`",
                entry.name
            ));
        }
        if entry.intended_audience == "most-users" && entry.publish_status != "published" {
            errors.push(format!(
                "{}: intended_audience `most-users` requires publish_status `published`",
                entry.name
            ));
        }
    }

    let missing: Vec<_> = known.difference(&seen).cloned().collect();
    if !missing.is_empty() {
        errors.push(format!(
            "missing support-matrix entries for workspace crates:\n- {}",
            missing.join("\n- ")
        ));
    }

    if !errors.is_empty() {
        bail!("support-matrix metadata validation failed:\n{}", errors.join("\n"));
    }
    Ok(())
}

fn workspace_crate_names(root: &Path) -> Result<BTreeSet<String>> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .context("failed to run `cargo metadata` for support matrix validation")?;
    if !output.status.success() {
        bail!(
            "`cargo metadata` failed for support matrix validation: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let meta: serde_json::Value = serde_json::from_slice(&output.stdout)
        .context("failed to parse cargo metadata JSON for support matrix validation")?;
    let workspace_members = meta["workspace_members"]
        .as_array()
        .context("missing workspace_members in cargo metadata")?
        .iter()
        .filter_map(|m| m.as_str())
        .collect::<BTreeSet<_>>();
    let packages = meta["packages"]
        .as_array()
        .context("missing packages in cargo metadata")?;
    let names = packages
        .iter()
        .filter(|pkg| pkg["id"].as_str().is_some_and(|id| workspace_members.contains(id)))
        .filter_map(|pkg| pkg["name"].as_str().map(ToOwned::to_owned))
        .collect::<BTreeSet<_>>();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_matrix_render_includes_header_and_notes() {
        let metadata = DocsMetadata {
            workspace_crates: vec![],
            adapter_crates: vec![],
            runnable_examples: vec![],
            facade_feature_matrix: vec![],
            adapter_feature_matrix: vec![],
            dependency_snippets: vec![],
            crate_support_matrix: vec![CrateSupportEntry {
                name: "uselesskey-demo".to_string(),
                description: "demo crate".to_string(),
                support_tier: "stable".to_string(),
                publish_status: "published".to_string(),
                facade_exposed: true,
                semver_expectation: "SemVer.".to_string(),
                msrv_policy: "Tracks workspace.".to_string(),
                intended_audience: "most-users".to_string(),
                replacement_path: Some("uselesskey".to_string()),
                deprecation_note: Some("Prefer facade.".to_string()),
            }],
        };

        let rendered = render_support_matrix_doc(&metadata);
        assert!(rendered.contains("# Support matrix"));
        assert!(rendered.contains("replacement: `uselesskey`; Prefer facade."));
    }

    #[test]
    fn support_matrix_validation_rejects_illegal_combinations() {
        let known = BTreeSet::from(["uselesskey-demo".to_string()]);
        let entries = vec![CrateSupportEntry {
            name: "uselesskey-demo".to_string(),
            description: "demo crate".to_string(),
            support_tier: "stable".to_string(),
            publish_status: "test-only".to_string(),
            facade_exposed: false,
            semver_expectation: "none".to_string(),
            msrv_policy: "none".to_string(),
            intended_audience: "most-users".to_string(),
            replacement_path: None,
            deprecation_note: None,
        }];

        let err = validate_support_entries(&known, &entries).expect_err("must fail");
        assert!(err
            .to_string()
            .contains("illegal combination `test-only` + `most-users`"));
    }
}
