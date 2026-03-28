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
    #[serde(default)]
    public_snippets: Vec<PublicSnippet>,
    #[serde(default)]
    snippet_blocks: Vec<SnippetBlock>,
    #[serde(default)]
    root_dependency_snippet_ids: Vec<String>,
    workspace_crates: Vec<CrateEntry>,
    adapter_crates: Vec<CrateEntry>,
    runnable_examples: Vec<ExampleEntry>,
    facade_feature_matrix: Vec<FeatureMatrixEntry>,
    adapter_feature_matrix: Vec<AdapterMatrixEntry>,
    #[serde(default)]
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

#[derive(Debug, Deserialize, Clone)]
struct PublicSnippet {
    id: String,
    name: String,
    dependencies: Vec<SnippetDependency>,
    supported_feature_flags: Vec<String>,
    minimal_example_command: String,
}

#[derive(Debug, Deserialize, Clone)]
struct SnippetDependency {
    crate_name: String,
    release_version: String,
    #[serde(default)]
    default_features: Option<bool>,
    #[serde(default)]
    features: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SnippetBlock {
    path: String,
    marker: String,
    snippet_ids: Vec<String>,
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
    let package_info = load_workspace_package_info(&root)?;
    validate_docs_metadata(&metadata, &package_info)?;
    let mut updated_paths = Vec::new();

    let readme_path = root.join("README.md");
    let original = fs::read_to_string(&readme_path).context("failed to read README.md")?;
    let updated = rewrite_root_readme(&original, &metadata)?;
    if updated != original {
        if check {
            bail!(
                "docs-sync check failed: README.md is out of sync with docs/metadata/workspace-docs.json"
            );
        }
        fs::write(&readme_path, updated).context("failed to write README.md")?;
        updated_paths.push("README.md".to_string());
    }

    let rendered_snippets = render_public_snippet_map(&metadata.public_snippets);
    for block in &metadata.snippet_blocks {
        rewrite_snippet_block(&root, block, &rendered_snippets, check, &mut updated_paths)?;
    }

    print_snippet_inventory(&metadata, &updated_paths);
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

fn rewrite_root_readme(input: &str, metadata: &DocsMetadata) -> Result<String> {
    let dependency_snippets = if metadata.public_snippets.is_empty() {
        render_dependency_snippets(metadata)
    } else {
        let snippets = select_public_snippets_for_root(metadata)?;
        render_dependency_snippets_from_public(&snippets)
    };
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

fn select_public_snippets_for_root(metadata: &DocsMetadata) -> Result<Vec<PublicSnippet>> {
    if metadata.root_dependency_snippet_ids.is_empty() {
        return Ok(metadata.public_snippets.clone());
    }
    let by_id: BTreeMap<&str, &PublicSnippet> = metadata
        .public_snippets
        .iter()
        .map(|snippet| (snippet.id.as_str(), snippet))
        .collect();
    let mut selected = Vec::new();
    for snippet_id in &metadata.root_dependency_snippet_ids {
        let snippet = by_id
            .get(snippet_id.as_str())
            .with_context(|| format!("unknown root dependency snippet id '{}'", snippet_id))?;
        selected.push((*snippet).clone());
    }
    Ok(selected)
}

fn rewrite_snippet_block(
    root: &Path,
    block: &SnippetBlock,
    rendered_snippets: &BTreeMap<String, String>,
    check: bool,
    updated_paths: &mut Vec<String>,
) -> Result<()> {
    let path = root.join(&block.path);
    let original =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", block.path))?;
    let replacement = render_snippet_block(block, rendered_snippets)?;
    let updated = replace_block(&original, &block.marker, &replacement)?;
    if updated == original {
        return Ok(());
    }
    if check {
        bail!(
            "docs-sync check failed: {} marker '{}' is out of sync with docs/metadata/workspace-docs.json",
            block.path,
            block.marker
        );
    }
    fs::write(&path, updated).with_context(|| format!("failed to write {}", block.path))?;
    updated_paths.push(block.path.clone());
    Ok(())
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

fn render_dependency_snippets_from_public(snippets: &[PublicSnippet]) -> String {
    let mut output = String::new();
    output.push_str("Dependency snippets:");
    output.push('\n');
    for snippet in snippets {
        writeln!(
            output,
            "- **{}**\n  ```toml\n{}\n  ```\n",
            snippet.name,
            indent_lines(&render_public_snippet_toml(snippet), "  ")
        )
        .expect("write to string");
        output.push('\n');
    }
    output
}

fn render_public_snippet_map(snippets: &[PublicSnippet]) -> BTreeMap<String, String> {
    snippets
        .iter()
        .map(|snippet| (snippet.id.clone(), render_public_snippet_markdown(snippet)))
        .collect()
}

fn render_public_snippet_markdown(snippet: &PublicSnippet) -> String {
    format!(
        "### {}\n\n```toml\n{}\n```\n\nMinimal example command:\n\n```bash\n{}\n```",
        snippet.name,
        render_public_snippet_toml(snippet),
        snippet.minimal_example_command
    )
}

fn render_public_snippet_toml(snippet: &PublicSnippet) -> String {
    let mut lines = Vec::new();
    lines.push("[dev-dependencies]".to_string());
    for dep in &snippet.dependencies {
        let mut parts = vec![format!("version = \"{}\"", dep.release_version)];
        if let Some(default_features) = dep.default_features {
            parts.push(format!("default-features = {default_features}"));
        }
        if !dep.features.is_empty() {
            parts.push(format!(
                "features = [{}]",
                dep.features
                    .iter()
                    .map(|feature| format!("\"{feature}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        lines.push(format!("{} = {{ {} }}", dep.crate_name, parts.join(", ")));
    }
    lines.join("\n")
}

fn render_snippet_block(
    block: &SnippetBlock,
    rendered_snippets: &BTreeMap<String, String>,
) -> Result<String> {
    let mut out = String::new();
    for snippet_id in &block.snippet_ids {
        let rendered = rendered_snippets
            .get(snippet_id)
            .with_context(|| format!("unknown snippet id '{snippet_id}' in {}", block.path))?;
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        out.push_str(rendered);
    }
    Ok(out)
}

#[derive(Debug)]
struct PackageInfo {
    version: String,
    features: BTreeSet<String>,
}

fn load_workspace_package_info(root: &Path) -> Result<BTreeMap<String, PackageInfo>> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .context("failed to run `cargo metadata` for docs-sync validation")?;
    if !output.status.success() {
        bail!(
            "`cargo metadata` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("invalid cargo metadata JSON")?;
    let packages = value["packages"]
        .as_array()
        .context("cargo metadata missing packages array")?;
    let mut info = BTreeMap::new();
    for package in packages {
        let Some(name) = package["name"].as_str() else {
            continue;
        };
        let Some(version) = package["version"].as_str() else {
            continue;
        };
        let features = package["features"]
            .as_object()
            .map(|obj| obj.keys().cloned().collect::<BTreeSet<_>>())
            .unwrap_or_default();
        info.insert(
            name.to_string(),
            PackageInfo {
                version: version.to_string(),
                features,
            },
        );
    }
    Ok(info)
}

fn validate_docs_metadata(
    metadata: &DocsMetadata,
    package_info: &BTreeMap<String, PackageInfo>,
) -> Result<()> {
    let mut errors = Vec::new();
    let mut seen_snippet_ids = BTreeSet::new();

    for snippet in &metadata.public_snippets {
        if !seen_snippet_ids.insert(snippet.id.clone()) {
            errors.push(format!("duplicate public snippet id '{}'", snippet.id));
        }
        validate_public_snippet(snippet, package_info, &mut errors);
    }

    let known_snippets = seen_snippet_ids;
    for block in &metadata.snippet_blocks {
        for snippet_id in &block.snippet_ids {
            if !known_snippets.contains(snippet_id) {
                errors.push(format!(
                    "snippet block '{}#{}' references unknown snippet id '{}'",
                    block.path, block.marker, snippet_id
                ));
            }
        }
    }

    if let Some(facade) = package_info.get("uselesskey") {
        for row in &metadata.facade_feature_matrix {
            if !facade.features.contains(&row.feature) {
                errors.push(format!(
                    "facade feature matrix references unknown uselesskey feature '{}'",
                    row.feature
                ));
            }
        }
        for example in &metadata.runnable_examples {
            for feature in parse_csv_features(&example.feature_set) {
                if !facade.features.contains(&feature) {
                    errors.push(format!(
                        "example '{}' references unknown uselesskey feature '{}'",
                        example.name, feature
                    ));
                }
            }
        }
    }

    if !errors.is_empty() {
        bail!("docs metadata validation failed:\n- {}", errors.join("\n- "));
    }
    Ok(())
}

fn validate_public_snippet(
    snippet: &PublicSnippet,
    package_info: &BTreeMap<String, PackageInfo>,
    errors: &mut Vec<String>,
) {
    for dep in &snippet.dependencies {
        let Some(package) = package_info.get(&dep.crate_name) else {
            errors.push(format!(
                "snippet '{}' references unknown crate '{}'",
                snippet.id, dep.crate_name
            ));
            continue;
        };
        if dep.release_version != package.version {
            errors.push(format!(
                "snippet '{}' has stale version for '{}': metadata {}, workspace {}",
                snippet.id, dep.crate_name, dep.release_version, package.version
            ));
        }
        for feature in &dep.features {
            if !package.features.contains(feature) {
                errors.push(format!(
                    "snippet '{}' references unknown feature '{}' for crate '{}'",
                    snippet.id, feature, dep.crate_name
                ));
            }
        }
    }

    let Some(primary_dep) = snippet.dependencies.first() else {
        errors.push(format!("snippet '{}' has no dependencies", snippet.id));
        return;
    };
    let Some(primary_package) = package_info.get(&primary_dep.crate_name) else {
        return;
    };
    for feature in &snippet.supported_feature_flags {
        if !primary_package.features.contains(feature) {
            errors.push(format!(
                "snippet '{}' has unsupported feature '{}' for crate '{}'",
                snippet.id, feature, primary_dep.crate_name
            ));
        }
    }
    for feature in parse_features_from_command(&snippet.minimal_example_command) {
        if !primary_package.features.contains(&feature) {
            errors.push(format!(
                "snippet '{}' command uses unsupported feature '{}' for crate '{}'",
                snippet.id, feature, primary_dep.crate_name
            ));
        }
    }
}

fn parse_features_from_command(command: &str) -> BTreeSet<String> {
    if let Some((_, tail)) = command.split_once("--features") {
        let raw = tail
            .trim()
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .trim_matches('"')
            .trim_matches('\'');
        parse_csv_features(raw)
            .into_iter()
            .collect()
    } else {
        BTreeSet::new()
    }
}

fn parse_csv_features(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|feature| !feature.is_empty())
        .map(str::to_string)
        .collect()
}

fn print_snippet_inventory(metadata: &DocsMetadata, updated_paths: &[String]) {
    println!("docs-sync snippet inventory:");
    for block in &metadata.snippet_blocks {
        println!(
            "  - {}#{} [{}]",
            block.path,
            block.marker,
            block.snippet_ids.join(", ")
        );
    }
    if updated_paths.is_empty() {
        println!("docs-sync: no files changed");
    } else {
        println!("docs-sync: updated {} file(s)", updated_paths.len());
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn package(version: &str, features: &[&str]) -> PackageInfo {
        PackageInfo {
            version: version.to_string(),
            features: features.iter().map(|v| (*v).to_string()).collect(),
        }
    }

    #[test]
    fn renders_public_snippet_markdown_with_command() {
        let snippet = PublicSnippet {
            id: "rsa-quickstart".to_string(),
            name: "Quick start".to_string(),
            dependencies: vec![SnippetDependency {
                crate_name: "uselesskey".to_string(),
                release_version: "0.5.1".to_string(),
                default_features: Some(false),
                features: vec!["rsa".to_string()],
            }],
            supported_feature_flags: vec!["rsa".to_string()],
            minimal_example_command:
                "cargo run -p uselesskey --example basic_rsa --no-default-features --features rsa"
                    .to_string(),
        };

        let rendered = render_public_snippet_markdown(&snippet);
        assert!(rendered.contains("### Quick start"));
        assert!(rendered.contains("uselesskey = { version = \"0.5.1\""));
        assert!(rendered.contains("Minimal example command"));
    }

    #[test]
    fn validate_public_snippet_rejects_stale_versions_and_unknown_features() {
        let snippet = PublicSnippet {
            id: "bad".to_string(),
            name: "Bad".to_string(),
            dependencies: vec![SnippetDependency {
                crate_name: "uselesskey".to_string(),
                release_version: "0.5.0".to_string(),
                default_features: None,
                features: vec!["rsa".to_string(), "nope".to_string()],
            }],
            supported_feature_flags: vec!["rsa".to_string(), "ghost".to_string()],
            minimal_example_command:
                "cargo run -p uselesskey --example basic_rsa --features rsa,unknown".to_string(),
        };

        let mut packages = BTreeMap::new();
        packages.insert("uselesskey".to_string(), package("0.5.1", &["rsa", "jwk"]));

        let mut errors = Vec::new();
        validate_public_snippet(&snippet, &packages, &mut errors);
        assert!(errors.iter().any(|msg| msg.contains("stale version")));
        assert!(
            errors
                .iter()
                .any(|msg| msg.contains("unknown feature 'nope'"))
        );
        assert!(
            errors
                .iter()
                .any(|msg| msg.contains("command uses unsupported feature 'unknown'"))
        );
    }

    #[test]
    fn parse_features_from_command_handles_missing_flag() {
        assert!(parse_features_from_command("cargo run -p uselesskey").is_empty());
        let features =
            parse_features_from_command("cargo run --features rsa,ecdsa --example basic_usage");
        assert!(features.contains("rsa"));
        assert!(features.contains("ecdsa"));
    }
}
