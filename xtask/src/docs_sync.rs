use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Deserialize;

const METADATA_PATH: &str = "docs/metadata/workspace-docs.json";
const MARKER_PREFIX: &str = "docs-sync:";
const DOCS_LINT_PATHS: &[&str] = &[
    "README.md",
    "docs/how-to/choose-features.md",
    "crates/uselesskey/README.md",
    "crates/uselesskey-jsonwebtoken/README.md",
    "crates/uselesskey-rustls/README.md",
    "crates/uselesskey-ring/README.md",
    "crates/uselesskey-rustcrypto/README.md",
    "crates/uselesskey-aws-lc-rs/README.md",
];

#[derive(Debug, Deserialize)]
struct DocsMetadata {
    workspace_crates: Vec<CrateEntry>,
    adapter_crates: Vec<CrateEntry>,
    runnable_examples: Vec<ExampleEntry>,
    facade_feature_matrix: Vec<FeatureMatrixEntry>,
    adapter_feature_matrix: Vec<AdapterMatrixEntry>,
    dependency_snippets: Vec<DependencySnippet>,
    public_snippets: Vec<PublicSnippet>,
    docs_sync_targets: Vec<DocsSyncTarget>,
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
    snippet_id: String,
}

#[derive(Debug, Deserialize)]
struct PublicSnippet {
    id: String,
    crate_name: String,
    current_release_version: String,
    supported_feature_flags: Vec<String>,
    minimal_example_command: String,
    dependency_snippet: String,
}

#[derive(Debug, Deserialize)]
struct DocsSyncTarget {
    path: String,
    blocks: Vec<DocsSyncBlock>,
}

#[derive(Debug, Deserialize)]
struct DocsSyncBlock {
    marker: String,
    kind: String,
    snippet_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    features: BTreeMap<String, Vec<String>>,
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
    let workspace = load_workspace_packages(&root)?;
    let snippet_lookup = snippet_lookup(&metadata)?;

    validate_snippet_metadata(&metadata, &workspace)?;
    validate_examples_match_workspace(&root, &metadata)?;

    let mut inventory = Vec::new();
    let mut changed = Vec::new();

    for target in &metadata.docs_sync_targets {
        let path = root.join(&target.path);
        let original = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", target.path))?;
        let updated = rewrite_document(&original, &metadata, &snippet_lookup, target, &mut inventory)?;

        if updated != original {
            changed.push(target.path.clone());
            if check {
                bail!("docs-sync check failed: {} is out of sync", target.path);
            }
            fs::write(&path, updated).with_context(|| format!("failed to write {}", target.path))?;
        }
    }

    validate_public_feature_flags(&root, &workspace)?;
    validate_versioned_snippets_and_commands(&root, &metadata, &snippet_lookup)?;

    if inventory.is_empty() {
        println!("docs-sync inventory: no managed snippets found");
    } else {
        println!("docs-sync inventory:");
        for item in inventory {
            println!("- {}", item);
        }
    }

    if changed.is_empty() {
        println!("docs-sync: all targets already synchronized");
    } else {
        println!("docs-sync: updated {}", changed.join(", "));
    }

    Ok(())
}

fn load_metadata(root: &Path) -> Result<DocsMetadata> {
    let path = root.join(METADATA_PATH);
    let raw = fs::read_to_string(&path).context("failed to read docs metadata file")?;
    serde_json::from_str(&raw).context("invalid docs metadata JSON")
}

fn load_workspace_packages(root: &Path) -> Result<BTreeMap<String, CargoPackage>> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .context("failed to run cargo metadata")?;

    if !output.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let parsed: CargoMetadata =
        serde_json::from_slice(&output.stdout).context("failed to parse cargo metadata json")?;
    Ok(parsed
        .packages
        .into_iter()
        .map(|package| (package.name.clone(), package))
        .collect())
}

fn snippet_lookup<'a>(metadata: &'a DocsMetadata) -> Result<BTreeMap<&'a str, &'a PublicSnippet>> {
    let mut lookup = BTreeMap::new();
    for snippet in &metadata.public_snippets {
        if lookup.insert(snippet.id.as_str(), snippet).is_some() {
            bail!("duplicate public snippet id '{}'", snippet.id);
        }
    }
    Ok(lookup)
}

fn validate_snippet_metadata(
    metadata: &DocsMetadata,
    workspace: &BTreeMap<String, CargoPackage>,
) -> Result<()> {
    for snippet in &metadata.public_snippets {
        let package = workspace.get(&snippet.crate_name).with_context(|| {
            format!(
                "public snippet '{}' references unknown crate '{}'",
                snippet.id, snippet.crate_name
            )
        })?;

        if snippet.current_release_version != package.version {
            bail!(
                "public snippet '{}' version drift: metadata={} workspace={}",
                snippet.id,
                snippet.current_release_version,
                package.version
            );
        }

        for feature in &snippet.supported_feature_flags {
            if !package.features.contains_key(feature) {
                bail!(
                    "public snippet '{}' references unknown feature '{}' for crate '{}'",
                    snippet.id,
                    feature,
                    snippet.crate_name
                );
            }
        }

        if snippet.minimal_example_command.trim().is_empty() {
            bail!("public snippet '{}' has empty minimal example command", snippet.id);
        }
    }

    for dep in &metadata.dependency_snippets {
        if !metadata.public_snippets.iter().any(|s| s.id == dep.snippet_id) {
            bail!(
                "dependency_snippets entry '{}' references unknown snippet_id '{}'",
                dep.name,
                dep.snippet_id
            );
        }
    }

    Ok(())
}

fn crate_link(name: &str) -> String {
    format!("[`{}`](https://crates.io/crates/{})", name, name)
}

fn rewrite_document(
    input: &str,
    metadata: &DocsMetadata,
    snippets: &BTreeMap<&str, &PublicSnippet>,
    target: &DocsSyncTarget,
    inventory: &mut Vec<String>,
) -> Result<String> {
    let examples = render_example_table(metadata);
    let workspace_crates = render_crate_table("workspace crate", &metadata.workspace_crates);
    let adapter_crates = render_crate_table("adapter crate", &metadata.adapter_crates);
    let feature_facade = render_facade_feature_matrix(metadata);
    let feature_adapters = render_adapter_feature_matrix(metadata);

    let mut output = input.to_string();
    for block in &target.blocks {
        let replacement = match block.kind.as_str() {
            "dependency-list" => render_dependency_snippets(metadata, snippets)?,
            "single-snippet" => {
                let snippet_id = block
                    .snippet_id
                    .as_deref()
                    .context("single-snippet block missing snippet_id")?;
                render_snippet(snippets, snippet_id)?
            }
            other => bail!("unknown docs sync block kind '{other}'"),
        };

        output = replace_block(&output, &block.marker, &replacement)?;
        inventory.push(format!(
            "{} :: {} ({})",
            target.path,
            block.marker,
            match block.snippet_id.as_deref() {
                Some(id) => id,
                None => block.kind.as_str(),
            }
        ));
    }

    if target.path == "README.md" {
        output = replace_block(&output, "runnable-examples", &examples)?;
        output = replace_block(&output, "workspace-crates", &workspace_crates)?;
        output = replace_block(&output, "adapter-crates", &adapter_crates)?;
        output = replace_block(&output, "feature-matrix-facade", &feature_facade)?;
        output = replace_block(&output, "feature-matrix-adapters", &feature_adapters)?;
        inventory.push("README.md :: runnable-examples (table)".to_string());
        inventory.push("README.md :: workspace-crates (table)".to_string());
        inventory.push("README.md :: adapter-crates (table)".to_string());
        inventory.push("README.md :: feature-matrix-facade (table)".to_string());
        inventory.push("README.md :: feature-matrix-adapters (table)".to_string());
    }

    Ok(output)
}

fn render_dependency_snippets(
    metadata: &DocsMetadata,
    snippets: &BTreeMap<&str, &PublicSnippet>,
) -> Result<String> {
    let mut output = String::new();
    output.push_str("Dependency snippets:");
    output.push('\n');
    for item in &metadata.dependency_snippets {
        let snippet = snippets
            .get(item.snippet_id.as_str())
            .with_context(|| format!("unknown dependency snippet id '{}'", item.snippet_id))?;

        writeln!(
            output,
            "- **{}**\n  ```toml\n{}\n  ```\n\n  Minimal command: `{}`\n",
            item.name,
            indent_lines(&render_snippet(snippets, &snippet.id)?, "  "),
            snippet.minimal_example_command
        )
        .expect("write to string");
        output.push('\n');
    }
    Ok(output)
}

fn render_snippet(snippets: &BTreeMap<&str, &PublicSnippet>, snippet_id: &str) -> Result<String> {
    let snippet = snippets
        .get(snippet_id)
        .with_context(|| format!("unknown snippet id '{snippet_id}'"))?;
    Ok(snippet
        .dependency_snippet
        .replace("{{version}}", &snippet.current_release_version))
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

fn validate_public_feature_flags(root: &Path, workspace: &BTreeMap<String, CargoPackage>) -> Result<()> {
    let feature_list_regex = Regex::new(
        r#"(?m)^\s*([a-zA-Z0-9_-]+)\s*=\s*\{[^\n}]*features\s*=\s*\[([^\]]*)\]"#,
    )
    .expect("valid regex");
    let feature_regex = Regex::new(r#"\"([^\"]+)\""#).expect("valid regex");

    let mut errors = Vec::new();
    for rel_path in DOCS_LINT_PATHS {
        let path = root.join(rel_path);
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read docs linter path {}", rel_path))?;

        for caps in feature_list_regex.captures_iter(&content) {
            let crate_name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let feature_blob = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            let Some(package) = workspace.get(crate_name) else {
                continue;
            };

            for feature_cap in feature_regex.captures_iter(feature_blob) {
                let feature_name = feature_cap.get(1).map(|m| m.as_str()).unwrap_or_default();
                if !package.features.contains_key(feature_name) {
                    errors.push(format!(
                        "{rel_path}: unknown feature '{feature_name}' for crate '{crate_name}'"
                    ));
                }
            }
        }
    }

    if !errors.is_empty() {
        bail!("feature flag docs lint failed:\n{}", errors.join("\n"));
    }

    Ok(())
}

fn validate_versioned_snippets_and_commands(
    root: &Path,
    metadata: &DocsMetadata,
    snippets: &BTreeMap<&str, &PublicSnippet>,
) -> Result<()> {
    let mut errors = Vec::new();

    let known_versions: BTreeMap<&str, &str> = metadata
        .public_snippets
        .iter()
        .map(|snippet| {
            (
                snippet.crate_name.as_str(),
                snippet.current_release_version.as_str(),
            )
        })
        .collect();

    let dep_regex = Regex::new(
        r#"(?m)^\s*([a-zA-Z0-9_-]+)\s*=\s*\{[^\n}]*version\s*=\s*\"([^\"]+)\""#,
    )
    .expect("valid regex");

    for rel_path in DOCS_LINT_PATHS {
        let content = fs::read_to_string(root.join(rel_path))
            .with_context(|| format!("failed to read docs linter path {}", rel_path))?;

        for caps in dep_regex.captures_iter(&content) {
            let crate_name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let version = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            if let Some(expected) = known_versions.get(crate_name)
                && version != *expected
            {
                errors.push(format!(
                    "{rel_path}: stale version for crate '{crate_name}': found {version}, expected {expected}"
                ));
            }
        }

    }

    errors.extend(validate_minimal_example_commands(metadata, snippets));

    if !errors.is_empty() {
        bail!("version/command docs lint failed:\n{}", errors.join("\n"));
    }

    Ok(())
}

fn validate_minimal_example_commands(
    metadata: &DocsMetadata,
    snippets: &BTreeMap<&str, &PublicSnippet>,
) -> Vec<String> {
    let command_regex = Regex::new(
        r#"cargo\s+(?:run|build|test)\s+-p\s+([a-zA-Z0-9_-]+)(?:\s+--example\s+([a-zA-Z0-9_-]+))?(?:\s+--no-default-features)?(?:\s+--features\s+([a-zA-Z0-9_,-]+))?"#,
    )
    .expect("valid regex");
    let example_features: BTreeMap<&str, &str> = metadata
        .runnable_examples
        .iter()
        .map(|entry| (entry.name.as_str(), entry.feature_set.as_str()))
        .collect();

    let mut errors = Vec::new();
    for snippet in snippets.values() {
        let command = snippet.minimal_example_command.trim();
        let Some(caps) = command_regex.captures(command) else {
            errors.push(format!(
                "public snippet '{}' has an invalid minimal example command: {}",
                snippet.id, snippet.minimal_example_command
            ));
            continue;
        };

        let package = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        if package != "uselesskey" && package != snippet.crate_name {
            errors.push(format!(
                "public snippet '{}' minimal command package '{}' does not match crate '{}'",
                snippet.id, package, snippet.crate_name
            ));
        }

        if let Some(example) = caps.get(2).map(|m| m.as_str())
            && let Some(expected_features) = example_features.get(example)
        {
            let actual_features = normalize_feature_csv(caps.get(3).map(|m| m.as_str()).unwrap_or(""));
            let expected_features = normalize_feature_csv(expected_features);
            if !expected_features.is_empty() && actual_features != expected_features {
                errors.push(format!(
                    "public snippet '{}' command for example '{}' has stale features '{}' (expected '{}')",
                    snippet.id, example, actual_features, expected_features
                ));
            }
        }
    }

    errors
}

fn normalize_feature_csv(features: &str) -> String {
    let mut items: Vec<String> = features
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    items.sort();
    items.join(",")
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

    #[test]
    fn normalize_feature_csv_orders_and_trims() {
        assert_eq!(normalize_feature_csv("rsa, jwk,ecdsa"), "ecdsa,jwk,rsa");
        assert_eq!(normalize_feature_csv(""), "");
    }

    #[test]
    fn replace_block_rewrites_managed_region() {
        let input = "before\n<!-- docs-sync:demo-start -->\nold\n<!-- docs-sync:demo-end -->\nafter\n";
        let output = replace_block(input, "demo", "new line").expect("replace should succeed");
        assert!(output.contains("new line"));
        assert!(!output.contains("\nold\n"));
    }
}
