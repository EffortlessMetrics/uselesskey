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
    primary_dependency: DependencyEntry,
    #[serde(default)]
    extra_dependencies: Vec<DependencyEntry>,
    minimal_example_command: String,
}

#[derive(Debug, Deserialize)]
struct DependencyEntry {
    crate_name: String,
    version: String,
    #[serde(default)]
    default_features: Option<bool>,
    #[serde(default)]
    features: Vec<String>,
}

#[derive(Debug)]
struct SnippetInventoryEntry {
    path: String,
    markers: Vec<String>,
}

#[derive(Debug)]
struct WorkspaceCrateInfo {
    version: String,
    features: BTreeSet<String>,
}

pub fn docs_sync_cmd(check: bool) -> Result<()> {
    run_docs_sync(check)?;
    Ok(())
}

pub fn examples_smoke_cmd(run: bool) -> Result<()> {
    run_docs_sync(true)?;

    let root = crate::workspace_root_path();
    let metadata = load_metadata(&root)?;
    let workspace = load_workspace_crate_info(&root)?;
    validate_metadata_against_workspace(&metadata, &workspace)?;
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
    let workspace = load_workspace_crate_info(&root)?;
    validate_metadata_against_workspace(&metadata, &workspace)?;

    let targets = docs_targets();
    let mut changed = Vec::new();

    for target in targets {
        let path = root.join(target.path);
        let original =
            fs::read_to_string(&path).with_context(|| format!("failed to read {}", target.path))?;
        let updated = rewrite_document(&original, &metadata, &target.blocks)?;
        if updated != original {
            changed.push(SnippetInventoryEntry {
                path: target.path.to_string(),
                markers: target
                    .blocks
                    .iter()
                    .map(|block| block.marker.to_string())
                    .collect(),
            });
            if !check {
                fs::write(&path, updated)
                    .with_context(|| format!("failed to write {}", target.path))?;
            }
        }
    }

    print_snippet_inventory(&changed, check);

    if check && !changed.is_empty() {
        bail!(
            "docs-sync check failed: {} file(s) contain stale snippets. Run `cargo xtask docs-sync`.",
            changed.len()
        );
    }

    if check && changed.is_empty() {
        println!("docs-sync: all managed snippets are synchronized");
    }

    Ok(())
}

fn load_metadata(root: &Path) -> Result<DocsMetadata> {
    let path = root.join(METADATA_PATH);
    let raw = fs::read_to_string(&path).context("failed to read docs metadata file")?;
    serde_json::from_str(&raw).context("invalid docs metadata JSON")
}

fn load_workspace_crate_info(root: &Path) -> Result<BTreeMap<String, WorkspaceCrateInfo>> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .context("failed to run `cargo metadata`")?;

    if !output.status.success() {
        bail!(
            "`cargo metadata` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("invalid cargo metadata JSON")?;

    let workspace_members: BTreeSet<String> = value["workspace_members"]
        .as_array()
        .context("cargo metadata missing workspace_members")?
        .iter()
        .filter_map(|v| v.as_str())
        .map(str::to_owned)
        .collect();

    let mut out = BTreeMap::new();
    for package in value["packages"]
        .as_array()
        .context("cargo metadata missing packages")?
    {
        let id = package["id"]
            .as_str()
            .context("package missing id in cargo metadata")?;
        if !workspace_members.contains(id) {
            continue;
        }

        let name = package["name"]
            .as_str()
            .context("package missing name")?
            .to_string();
        let version = package["version"]
            .as_str()
            .context("package missing version")?
            .to_string();
        let features_obj = package["features"]
            .as_object()
            .context("package missing features")?;
        let features = features_obj.keys().cloned().collect::<BTreeSet<_>>();

        out.insert(name, WorkspaceCrateInfo { version, features });
    }

    Ok(out)
}

fn validate_metadata_against_workspace(
    metadata: &DocsMetadata,
    workspace: &BTreeMap<String, WorkspaceCrateInfo>,
) -> Result<()> {
    let mut errors = Vec::new();

    for snippet in &metadata.dependency_snippets {
        validate_dependency_entry(
            &snippet.primary_dependency,
            workspace,
            &format!("dependency_snippets.{}.primary_dependency", snippet.name),
            &mut errors,
        );

        for (idx, dep) in snippet.extra_dependencies.iter().enumerate() {
            validate_dependency_entry(
                dep,
                workspace,
                &format!(
                    "dependency_snippets.{}.extra_dependencies[{idx}]",
                    snippet.name
                ),
                &mut errors,
            );
        }

        validate_example_command(&snippet.minimal_example_command, &snippet.name, &mut errors);
    }

    if let Some(info) = workspace.get("uselesskey") {
        for example in &metadata.runnable_examples {
            for feature in parse_feature_set(&example.feature_set) {
                if !info.features.contains(&feature) {
                    errors.push(format!(
                        "runnable_examples.{} uses unknown facade feature `{}`",
                        example.name, feature
                    ));
                }
            }
        }

        for feature in metadata
            .facade_feature_matrix
            .iter()
            .map(|entry| entry.feature.clone())
        {
            if !info.features.contains(&feature) {
                errors.push(format!(
                    "facade_feature_matrix contains unknown facade feature `{feature}`"
                ));
            }
        }
    } else {
        errors.push("workspace crate `uselesskey` not found in cargo metadata".to_string());
    }

    if !errors.is_empty() {
        bail!(
            "docs metadata validation failed:\n- {}",
            errors.join("\n- ")
        );
    }

    Ok(())
}

fn validate_dependency_entry(
    dep: &DependencyEntry,
    workspace: &BTreeMap<String, WorkspaceCrateInfo>,
    context: &str,
    errors: &mut Vec<String>,
) {
    let Some(info) = workspace.get(&dep.crate_name) else {
        errors.push(format!(
            "{context}: unknown workspace crate `{}`",
            dep.crate_name
        ));
        return;
    };

    if dep.version != info.version {
        errors.push(format!(
            "{context}: stale version `{}` (workspace has `{}`)",
            dep.version, info.version
        ));
    }

    for feature in &dep.features {
        if !info.features.contains(feature) {
            errors.push(format!(
                "{context}: unknown feature `{feature}` for crate `{}`",
                dep.crate_name
            ));
        }
    }
}

fn validate_example_command(command: &str, name: &str, errors: &mut Vec<String>) {
    let trimmed = command.trim();
    if !trimmed.starts_with("cargo run -p uselesskey --example ") {
        errors.push(format!(
            "dependency_snippets.{name}.minimal_example_command must start with `cargo run -p uselesskey --example ...`"
        ));
    }

    if !trimmed.contains("--no-default-features") {
        errors.push(format!(
            "dependency_snippets.{name}.minimal_example_command must include `--no-default-features`"
        ));
    }
}

fn parse_feature_set(feature_set: &str) -> Vec<String> {
    feature_set
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn crate_link(name: &str) -> String {
    format!("[`{}`](https://crates.io/crates/{})", name, name)
}

struct DocTarget {
    path: &'static str,
    blocks: Vec<BlockTarget>,
}

struct BlockTarget {
    marker: &'static str,
    renderer: fn(&DocsMetadata) -> String,
}

fn docs_targets() -> Vec<DocTarget> {
    vec![
        DocTarget {
            path: "README.md",
            blocks: vec![
                BlockTarget {
                    marker: "dependency-snippets",
                    renderer: render_dependency_snippets,
                },
                BlockTarget {
                    marker: "runnable-examples",
                    renderer: render_example_table,
                },
                BlockTarget {
                    marker: "workspace-crates",
                    renderer: |metadata| {
                        render_crate_table("workspace crate", &metadata.workspace_crates)
                    },
                },
                BlockTarget {
                    marker: "adapter-crates",
                    renderer: |metadata| {
                        render_crate_table("adapter crate", &metadata.adapter_crates)
                    },
                },
                BlockTarget {
                    marker: "feature-matrix-facade",
                    renderer: render_facade_feature_matrix,
                },
                BlockTarget {
                    marker: "feature-matrix-adapters",
                    renderer: render_adapter_feature_matrix,
                },
            ],
        },
        DocTarget {
            path: "crates/uselesskey/README.md",
            blocks: vec![BlockTarget {
                marker: "facade-dependency-snippets",
                renderer: render_facade_readme_snippets,
            }],
        },
        DocTarget {
            path: "docs/how-to/choose-features.md",
            blocks: vec![BlockTarget {
                marker: "choose-features-snippets",
                renderer: render_choose_features_snippets,
            }],
        },
    ]
}

fn rewrite_document(
    input: &str,
    metadata: &DocsMetadata,
    blocks: &[BlockTarget],
) -> Result<String> {
    let mut output = input.to_string();
    for block in blocks {
        let rendered = (block.renderer)(metadata);
        output = replace_block(&output, block.marker, &rendered)?;
    }
    Ok(output)
}

fn render_dependency_snippets(metadata: &DocsMetadata) -> String {
    let mut output = String::new();
    output.push_str("Dependency snippets:\n");
    for item in &metadata.dependency_snippets {
        writeln!(
            output,
            "- **{}**\n  ```toml\n{}\n  ```\n\n  Minimal run command: `{}`\n",
            item.name,
            indent_lines(&render_dependency_toml(item), "  "),
            item.minimal_example_command
        )
        .expect("write to string");
    }
    output
}

fn render_facade_readme_snippets(metadata: &DocsMetadata) -> String {
    let mut output = String::new();
    output.push_str("### Synced dependency snippets\n\n");
    for target_name in ["Token-only", "Quick start (RSA)"] {
        if let Some(item) = metadata
            .dependency_snippets
            .iter()
            .find(|snippet| snippet.name == target_name)
        {
            writeln!(
                output,
                "#### {}\n\n```toml\n{}\n```\n",
                item.name,
                render_dependency_toml(item)
            )
            .expect("write to string");
        }
    }
    output
}

fn render_choose_features_snippets(metadata: &DocsMetadata) -> String {
    let mut output = String::new();
    output.push_str("## Synced snippets\n\n");

    for target_name in [
        "Quick start (RSA)",
        "JWT/JWK",
        "X.509 + rustls",
        "Token-only",
    ] {
        if let Some(item) = metadata
            .dependency_snippets
            .iter()
            .find(|snippet| snippet.name == target_name)
        {
            writeln!(
                output,
                "### {}\n\n```toml\n{}\n```\n",
                item.name,
                render_dependency_toml(item)
            )
            .expect("write to string");
        }
    }

    output
}

fn render_dependency_toml(snippet: &DependencySnippet) -> String {
    let mut output = String::new();
    output.push_str("[dev-dependencies]\n");
    let all = std::iter::once(&snippet.primary_dependency).chain(snippet.extra_dependencies.iter());
    for dep in all {
        output.push_str(&render_dependency_line(dep));
        output.push('\n');
    }
    output.trim_end().to_string()
}

fn render_dependency_line(dep: &DependencyEntry) -> String {
    let mut attrs = vec![format!("version = \"{}\"", dep.version)];
    if dep.default_features == Some(false) {
        attrs.push("default-features = false".to_string());
    }
    if !dep.features.is_empty() {
        attrs.push(format!(
            "features = [{}]",
            dep.features
                .iter()
                .map(|feature| format!("\"{feature}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    format!("{} = {{ {} }}", dep.crate_name, attrs.join(", "))
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
        "| Example | Feature(s) | Command | Description |\n|---------|------------|---------|-------------|\n",
    );

    for example in &metadata.runnable_examples {
        let feature_set = if example.feature_set.trim().is_empty() {
            "—".to_string()
        } else {
            format!("`{}`", example.feature_set)
        };

        let command = if example.feature_set.trim().is_empty() {
            format!("`cargo run -p uselesskey --example {}`", example.name)
        } else {
            format!(
                "`cargo run -p uselesskey --example {} --no-default-features --features \"{}\"`",
                example.name, example.feature_set
            )
        };

        let _ = writeln!(
            output,
            "| [{}]({}) | {} | {} | {} |",
            example.name, example.path, feature_set, command, example.description
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

fn print_snippet_inventory(changed: &[SnippetInventoryEntry], check: bool) {
    if changed.is_empty() {
        println!("docs-sync: snippet inventory: no changes");
        return;
    }

    let mode = if check { "stale" } else { "rewritten" };
    println!("docs-sync: snippet inventory ({mode}):");
    for entry in changed {
        println!("  - {} [{}]", entry.path, entry.markers.join(", "));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn snapshot_dependency_render_includes_commands() {
        let metadata = DocsMetadata {
            workspace_crates: vec![],
            adapter_crates: vec![],
            runnable_examples: vec![],
            facade_feature_matrix: vec![],
            adapter_feature_matrix: vec![],
            dependency_snippets: vec![DependencySnippet {
                name: "Quick start (RSA)".to_string(),
                primary_dependency: DependencyEntry {
                    crate_name: "uselesskey".to_string(),
                    version: "1.2.3".to_string(),
                    default_features: None,
                    features: vec!["rsa".to_string()],
                },
                extra_dependencies: vec![],
                minimal_example_command:
                    "cargo run -p uselesskey --example basic_rsa --no-default-features --features \"rsa\""
                        .to_string(),
            }],
        };

        let rendered = render_dependency_snippets(&metadata);
        assert_eq!(
            rendered,
            "Dependency snippets:\n- **Quick start (RSA)**\n  ```toml\n  [dev-dependencies]\n  uselesskey = { version = \"1.2.3\", features = [\"rsa\"] }\n  ```\n\n  Minimal run command: `cargo run -p uselesskey --example basic_rsa --no-default-features --features \"rsa\"`\n\n"
        );
    }

    #[test]
    fn rejects_unknown_feature_flags_in_docs_metadata() {
        let metadata = DocsMetadata {
            workspace_crates: vec![],
            adapter_crates: vec![],
            runnable_examples: vec![],
            facade_feature_matrix: vec![],
            adapter_feature_matrix: vec![],
            dependency_snippets: vec![DependencySnippet {
                name: "bad".to_string(),
                primary_dependency: DependencyEntry {
                    crate_name: "uselesskey".to_string(),
                    version: "0.5.1".to_string(),
                    default_features: None,
                    features: vec!["not-a-feature".to_string()],
                },
                extra_dependencies: vec![],
                minimal_example_command:
                    "cargo run -p uselesskey --example bad --no-default-features --features \"rsa\""
                        .to_string(),
            }],
        };

        let mut workspace = BTreeMap::new();
        workspace.insert(
            "uselesskey".to_string(),
            WorkspaceCrateInfo {
                version: "0.5.1".to_string(),
                features: ["rsa".to_string()].into_iter().collect(),
            },
        );

        let error = validate_metadata_against_workspace(&metadata, &workspace)
            .expect_err("validation should fail");
        let text = format!("{error:#}");
        assert!(text.contains("unknown feature `not-a-feature`"), "{text}");
    }

    #[test]
    fn rejects_stale_versions_in_docs_metadata() {
        let metadata = DocsMetadata {
            workspace_crates: vec![],
            adapter_crates: vec![],
            runnable_examples: vec![],
            facade_feature_matrix: vec![],
            adapter_feature_matrix: vec![],
            dependency_snippets: vec![DependencySnippet {
                name: "bad".to_string(),
                primary_dependency: DependencyEntry {
                    crate_name: "uselesskey".to_string(),
                    version: "0.5.0".to_string(),
                    default_features: None,
                    features: vec![],
                },
                extra_dependencies: vec![],
                minimal_example_command:
                    "cargo run -p uselesskey --example bad --no-default-features".to_string(),
            }],
        };

        let mut workspace = BTreeMap::new();
        workspace.insert(
            "uselesskey".to_string(),
            WorkspaceCrateInfo {
                version: "0.5.1".to_string(),
                features: BTreeSet::new(),
            },
        );

        let error = validate_metadata_against_workspace(&metadata, &workspace)
            .expect_err("validation should fail");
        let text = format!("{error:#}");
        assert!(text.contains("stale version"), "{text}");
    }

    #[test]
    fn rejects_duplicate_example_paths_in_docs_metadata() {
        let root = tempdir().expect("tempdir");
        let examples_dir = root.path().join("crates/uselesskey/examples");
        fs::create_dir_all(&examples_dir).expect("create examples dir");
        fs::write(examples_dir.join("basic_rsa.rs"), "// smoke").expect("write example");

        let metadata = DocsMetadata {
            workspace_crates: vec![],
            adapter_crates: vec![],
            runnable_examples: vec![
                ExampleEntry {
                    name: "basic_rsa".to_string(),
                    path: "crates/uselesskey/examples/basic_rsa.rs".to_string(),
                    description: "one".to_string(),
                    feature_set: "rsa".to_string(),
                    run_smoke: false,
                },
                ExampleEntry {
                    name: "basic_rsa".to_string(),
                    path: "crates/uselesskey/examples/basic_rsa.rs".to_string(),
                    description: "two".to_string(),
                    feature_set: "rsa".to_string(),
                    run_smoke: false,
                },
            ],
            facade_feature_matrix: vec![],
            adapter_feature_matrix: vec![],
            dependency_snippets: vec![],
        };

        let error = validate_examples_match_workspace(root.path(), &metadata)
            .expect_err("validation should fail");
        let text = format!("{error:#}");
        assert!(text.contains("duplicate example path"), "{text}");
    }

    #[test]
    fn rejects_example_name_mismatch_in_docs_metadata() {
        let root = tempdir().expect("tempdir");
        let examples_dir = root.path().join("crates/uselesskey/examples");
        fs::create_dir_all(&examples_dir).expect("create examples dir");
        fs::write(examples_dir.join("basic_rsa.rs"), "// smoke").expect("write example");

        let metadata = DocsMetadata {
            workspace_crates: vec![],
            adapter_crates: vec![],
            runnable_examples: vec![ExampleEntry {
                name: "wrong_name".to_string(),
                path: "crates/uselesskey/examples/basic_rsa.rs".to_string(),
                description: "mismatch".to_string(),
                feature_set: "rsa".to_string(),
                run_smoke: false,
            }],
            facade_feature_matrix: vec![],
            adapter_feature_matrix: vec![],
            dependency_snippets: vec![],
        };

        let error = validate_examples_match_workspace(root.path(), &metadata)
            .expect_err("validation should fail");
        let text = format!("{error:#}");
        assert!(text.contains("example name mismatch"), "{text}");
    }
}
