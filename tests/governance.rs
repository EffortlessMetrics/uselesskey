//! Workspace governance tests.
//!
//! These tests read `Cargo.toml`, `clippy.toml`, and source files to ensure
//! the workspace stays consistent. They intentionally avoid hard-coding
//! expectations and instead derive ground-truth from configuration files.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde::Deserialize;
use toml::Table;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tests crate must live one level below workspace root")
        .to_path_buf()
}

fn read_toml(path: &Path) -> Table {
    let content =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    content
        .parse::<Table>()
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn workspace_toml() -> Table {
    read_toml(&workspace_root().join("Cargo.toml"))
}

fn run_cargo(args: &[&str]) -> Output {
    Command::new("cargo")
        .args(args)
        .current_dir(workspace_root())
        .output()
        .unwrap_or_else(|e| panic!("failed to run cargo {}: {e}", args.join(" ")))
}

fn token_only_fixture_manifest() -> PathBuf {
    workspace_root().join("tests/fixtures/token_only_facade/Cargo.toml")
}

#[derive(Debug, Deserialize)]
struct Metadata {
    packages: Vec<MetadataPackage>,
    resolve: MetadataResolve,
}

#[derive(Debug, Deserialize)]
struct MetadataPackage {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct MetadataResolve {
    root: Option<String>,
    nodes: Vec<MetadataNode>,
}

#[derive(Debug, Deserialize)]
struct MetadataNode {
    id: String,
    dependencies: Vec<String>,
}

fn reachable_package_names(metadata: &Metadata, root_id: &str) -> BTreeSet<String> {
    let node_map = metadata
        .resolve
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node.dependencies.as_slice()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let package_names = metadata
        .packages
        .iter()
        .map(|pkg| (pkg.id.as_str(), pkg.name.as_str()))
        .collect::<std::collections::BTreeMap<_, _>>();

    let mut seen = BTreeSet::new();
    let mut stack = vec![root_id.to_string()];

    while let Some(id) = stack.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }

        if let Some(deps) = node_map.get(id.as_str()) {
            stack.extend(deps.iter().map(|dep| dep.to_string()));
        }
    }

    seen.into_iter()
        .filter_map(|id| {
            package_names
                .get(id.as_str())
                .map(|name| (*name).to_string())
        })
        .collect()
}

/// Return workspace member directory names listed in `[workspace] members`.
fn workspace_members(ws: &Table) -> Vec<String> {
    ws["workspace"]["members"]
        .as_array()
        .expect("workspace.members must be an array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

/// Canonical workspace version from `[workspace.package] version`.
fn workspace_version(ws: &Table) -> &str {
    ws["workspace"]["package"]["version"]
        .as_str()
        .unwrap_or_else(|| {
            // No workspace-level version; derive from first publishable crate.
            panic!("no workspace.package.version found")
        })
}

// ---------------------------------------------------------------------------
// 1. All crate versions are consistent
// ---------------------------------------------------------------------------

#[test]
fn all_crate_versions_match_workspace() {
    let root = workspace_root();
    let ws = workspace_toml();
    let members = workspace_members(&ws);

    // Determine expected version. If `workspace.package.version` exists, use it.
    // Otherwise, collect all publishable crate versions and assert they agree.
    let expected_version: String = if let Some(v) = ws
        .get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("version"))
        .and_then(|v| v.as_str())
    {
        v.to_string()
    } else {
        // Fall back: read the facade crate version.
        let facade = read_toml(&root.join("crates/uselesskey/Cargo.toml"));
        facade["package"]["version"]
            .as_str()
            .expect("facade must have a version")
            .to_string()
    };

    let mut mismatches = Vec::new();

    for member in &members {
        let manifest = read_toml(&root.join(member).join("Cargo.toml"));
        let pkg = match manifest.get("package") {
            Some(p) => p,
            None => continue,
        };

        // Skip crates that opt out of publishing.
        if pkg.get("publish").and_then(|v| v.as_bool()) == Some(false) {
            continue;
        }

        // Version may be inherited from workspace.
        if pkg.get("version").and_then(|v| v.as_str()) == Some("0.0.0") {
            continue; // internal-only sentinel
        }

        // If version.workspace = true, it inherits — that's fine.
        if let Some(tbl) = pkg.get("version").and_then(|v| v.as_table())
            && tbl.get("workspace").and_then(|v| v.as_bool()) == Some(true)
        {
            continue; // inherits workspace version
        }

        if let Some(ver) = pkg.get("version").and_then(|v| v.as_str())
            && ver != expected_version
        {
            let name = pkg["name"].as_str().unwrap_or(member);
            mismatches.push(format!("{name}: {ver} (expected {expected_version})"));
        }
    }

    assert!(
        mismatches.is_empty(),
        "version mismatches:\n  {}",
        mismatches.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 2. Workspace dependency versions match referenced crate versions
// ---------------------------------------------------------------------------

#[test]
fn workspace_dep_versions_match_crate_versions() {
    let root = workspace_root();
    let ws = workspace_toml();
    let deps = match ws
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(|d| d.as_table())
    {
        Some(d) => d,
        None => return,
    };

    let mut mismatches = Vec::new();

    for (name, spec) in deps {
        // Only check path dependencies (internal crates).
        let tbl = match spec.as_table() {
            Some(t) => t,
            None => continue,
        };
        let path_str = match tbl.get("path").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => continue,
        };
        let dep_version = match tbl.get("version").and_then(|v| v.as_str()) {
            Some(v) => v,
            None => continue,
        };

        let crate_toml_path = root.join(path_str).join("Cargo.toml");
        if !crate_toml_path.exists() {
            mismatches.push(format!("{name}: path {path_str} does not exist"));
            continue;
        }

        let crate_toml = read_toml(&crate_toml_path);
        // The crate may inherit its version from workspace. In that case, check
        // against `workspace.package.version`.
        let crate_version = crate_toml
            .get("package")
            .and_then(|p| p.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| {
                // version.workspace = true — use workspace version
                workspace_version(&ws)
            });

        if dep_version != crate_version {
            mismatches.push(format!(
                "{name}: workspace dep says {dep_version}, crate has {crate_version}"
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "workspace dependency version mismatches:\n  {}",
        mismatches.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 3. Facade re-exports all optional key-type sub-crates
// ---------------------------------------------------------------------------

#[test]
fn facade_reexports_all_key_type_crates() {
    let root = workspace_root();
    let facade_toml = read_toml(&root.join("crates/uselesskey/Cargo.toml"));
    let lib_rs =
        std::fs::read_to_string(root.join("crates/uselesskey/src/lib.rs")).expect("read lib.rs");

    // Collect optional dependencies that are key-type crates.
    let deps = facade_toml["dependencies"]
        .as_table()
        .expect("facade must have [dependencies]");

    let mut missing = Vec::new();

    for (dep_name, spec) in deps {
        // Skip uselesskey-core (always present, not optional).
        if dep_name == "uselesskey-core" {
            continue;
        }

        let is_optional = spec
            .as_table()
            .and_then(|t| t.get("optional"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !is_optional {
            continue;
        }

        // Convert dep name to the Rust identifier form (hyphens → underscores).
        let ident = dep_name.replace('-', "_");

        // The facade should reference this crate somewhere (pub use, pub mod, or cfg).
        if !lib_rs.contains(&ident) {
            missing.push(dep_name.clone());
        }
    }

    assert!(
        missing.is_empty(),
        "facade lib.rs does not reference these optional deps:\n  {}",
        missing.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 4. Feature flags correctly gate dependencies
// ---------------------------------------------------------------------------

#[test]
fn facade_features_gate_correct_deps() {
    let root = workspace_root();
    let facade_toml = read_toml(&root.join("crates/uselesskey/Cargo.toml"));

    let features = facade_toml["features"]
        .as_table()
        .expect("facade must have [features]");

    let deps = facade_toml["dependencies"]
        .as_table()
        .expect("facade must have [dependencies]");

    // For each optional dep, verify there's a feature that activates it.
    let mut ungated = Vec::new();

    for (dep_name, spec) in deps {
        let is_optional = spec
            .as_table()
            .and_then(|t| t.get("optional"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !is_optional {
            continue;
        }

        let dep_ref = format!("dep:{dep_name}");

        // Check if any feature activates this dep.
        let activated = features.values().any(|feat_list| {
            feat_list
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .any(|v| v.as_str().map(|s| s == dep_ref).unwrap_or(false))
                })
                .unwrap_or(false)
        });

        if !activated {
            ungated.push(dep_name.clone());
        }
    }

    assert!(
        ungated.is_empty(),
        "optional deps with no activating feature:\n  {}",
        ungated.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 5. MSRV in clippy.toml matches workspace Cargo.toml
// ---------------------------------------------------------------------------

#[test]
fn msrv_consistent_across_config_files() {
    let root = workspace_root();
    let ws = workspace_toml();

    // workspace Cargo.toml rust-version
    let cargo_msrv = ws
        .get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("rust-version"))
        .and_then(|v| v.as_str())
        .expect("workspace.package.rust-version must be set");

    // clippy.toml msrv
    let clippy_toml = read_toml(&root.join("clippy.toml"));
    let clippy_msrv = clippy_toml
        .get("msrv")
        .and_then(|v| v.as_str())
        .expect("clippy.toml must have msrv");

    assert_eq!(
        cargo_msrv, clippy_msrv,
        "MSRV mismatch: Cargo.toml says {cargo_msrv}, clippy.toml says {clippy_msrv}"
    );

    // rust-toolchain.toml channel (if present)
    let toolchain_path = root.join("rust-toolchain.toml");
    if toolchain_path.exists() {
        let tc = read_toml(&toolchain_path);
        if let Some(channel) = tc
            .get("toolchain")
            .and_then(|t| t.get("channel"))
            .and_then(|v| v.as_str())
        {
            assert_eq!(
                cargo_msrv, channel,
                "MSRV mismatch: Cargo.toml says {cargo_msrv}, rust-toolchain.toml channel is {channel}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 6. PUBLISH_CRATES list covers all publishable workspace members
// ---------------------------------------------------------------------------

#[test]
fn publish_crates_list_is_complete() {
    let root = workspace_root();
    let ws = workspace_toml();
    let members = workspace_members(&ws);

    // Determine which workspace members are publishable.
    let mut publishable: BTreeSet<String> = BTreeSet::new();

    for member in &members {
        let manifest_path = root.join(member).join("Cargo.toml");
        if !manifest_path.exists() {
            continue;
        }
        let manifest = read_toml(&manifest_path);
        let pkg = match manifest.get("package") {
            Some(p) => p,
            None => continue,
        };

        if pkg.get("publish").and_then(|v| v.as_bool()) == Some(false) {
            continue;
        }

        if let Some(arr) = pkg.get("publish").and_then(|v| v.as_array())
            && arr.is_empty()
        {
            continue;
        }

        if let Some(name) = pkg.get("name").and_then(|v| v.as_str()) {
            publishable.insert(name.to_string());
        }
    }

    // Parse PUBLISH_CRATES from xtask/src/main.rs.
    let xtask_src =
        std::fs::read_to_string(root.join("xtask/src/main.rs")).expect("read xtask main.rs");

    let publish_list: BTreeSet<String> = extract_publish_crates(&xtask_src);

    let missing_from_xtask: Vec<_> = publishable.difference(&publish_list).collect();
    let extra_in_xtask: Vec<_> = publish_list.difference(&publishable).collect();

    let mut problems = Vec::new();
    if !missing_from_xtask.is_empty() {
        problems.push(format!(
            "publishable crates missing from PUBLISH_CRATES: {:?}",
            missing_from_xtask
        ));
    }
    if !extra_in_xtask.is_empty() {
        problems.push(format!(
            "PUBLISH_CRATES entries not in workspace (or marked publish=false): {:?}",
            extra_in_xtask
        ));
    }

    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Extract crate names from the `PUBLISH_CRATES` const in xtask source.
fn extract_publish_crates(source: &str) -> BTreeSet<String> {
    let mut result = BTreeSet::new();

    // Find the const declaration line.
    let marker = "const PUBLISH_CRATES";
    let start = match source.find(marker) {
        Some(idx) => idx,
        None => return result,
    };
    let block = &source[start..];

    // Find the opening `&[` and closing `];`.
    let array_start = match block.find("&[") {
        Some(idx) => idx,
        None => return result,
    };
    let block = &block[array_start..];
    let array_end = match block.find("];") {
        Some(idx) => idx,
        None => return result,
    };
    let block = &block[..array_end];

    // Extract quoted strings — only names starting with "uselesskey".
    for line in block.lines() {
        let trimmed = line.trim();
        if let Some(start_q) = trimmed.find('"')
            && let Some(end_q) = trimmed[start_q + 1..].find('"')
        {
            let name = &trimmed[start_q + 1..start_q + 1 + end_q];
            if name.starts_with("uselesskey") {
                result.insert(name.to_string());
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// 7. All publishable crates have required metadata
// ---------------------------------------------------------------------------

#[test]
fn publishable_crates_have_required_metadata() {
    let root = workspace_root();
    let ws = workspace_toml();
    let members = workspace_members(&ws);

    // Collect workspace-level defaults.
    let ws_pkg = ws
        .get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|v| v.as_table());

    let mut problems = Vec::new();

    for member in &members {
        let manifest_path = root.join(member).join("Cargo.toml");
        if !manifest_path.exists() {
            continue;
        }
        let manifest = read_toml(&manifest_path);
        let pkg = match manifest.get("package") {
            Some(p) => p,
            None => continue,
        };

        // Skip non-publishable crates.
        if pkg.get("publish").and_then(|v| v.as_bool()) == Some(false) {
            continue;
        }
        if let Some(arr) = pkg.get("publish").and_then(|v| v.as_array())
            && arr.is_empty()
        {
            continue;
        }

        let crate_name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or(member);

        // Check required fields (may be inherited from workspace).
        for field in &["license", "description", "repository"] {
            let has_own = pkg.get(*field).is_some();
            let inherits_ws = pkg
                .get(*field)
                .and_then(|v| v.as_table())
                .and_then(|t| t.get("workspace"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let ws_has = ws_pkg
                .and_then(|wp| wp.get(*field))
                .and_then(|v| v.as_str())
                .is_some();

            if !has_own && !ws_has {
                problems.push(format!("{crate_name}: missing `{field}`"));
            }
            if inherits_ws && !ws_has {
                problems.push(format!(
                    "{crate_name}: inherits `{field}` from workspace but workspace doesn't define it"
                ));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "metadata problems:\n  {}",
        problems.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 8. Facade defaults stay lightweight
// ---------------------------------------------------------------------------

#[test]
fn facade_default_feature_set_is_empty() {
    let root = workspace_root();
    let facade_toml = read_toml(&root.join("crates/uselesskey/Cargo.toml"));
    let default_features = facade_toml["features"]["default"]
        .as_array()
        .expect("facade features.default must be an array");

    assert!(
        default_features.is_empty(),
        "facade default features should stay empty, got {:?}",
        default_features
    );
}

// ---------------------------------------------------------------------------
// 9. Token-only facade fixture compiles and stays RSA-free
// ---------------------------------------------------------------------------

#[test]
fn token_only_facade_fixture_compiles() {
    let manifest = token_only_fixture_manifest();
    let manifest_str = manifest.display().to_string();
    let output = run_cargo(&["test", "--manifest-path", &manifest_str, "--quiet"]);

    assert!(
        output.status.success(),
        "token-only fixture failed to compile and test\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn token_only_facade_fixture_does_not_resolve_rsa() {
    let manifest = token_only_fixture_manifest();
    let manifest_str = manifest.display().to_string();
    let output = run_cargo(&[
        "metadata",
        "--manifest-path",
        &manifest_str,
        "--format-version",
        "1",
    ]);

    assert!(
        output.status.success(),
        "cargo metadata failed for token-only fixture\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: Metadata = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("failed to parse cargo metadata output: {e}"));
    let root_id = metadata
        .resolve
        .root
        .clone()
        .or_else(|| {
            metadata
                .packages
                .iter()
                .find(|pkg| pkg.name == "uselesskey-token-only-fixture")
                .map(|pkg| pkg.id.clone())
        })
        .expect("token-only fixture root package must be present in metadata");
    let reachable = reachable_package_names(&metadata, &root_id);

    assert!(
        reachable.contains("uselesskey"),
        "expected uselesskey facade in token-only fixture graph, got {reachable:?}"
    );
    assert!(
        reachable.contains("uselesskey-token"),
        "expected token crate in token-only fixture graph, got {reachable:?}"
    );
    assert!(
        !reachable.contains("uselesskey-rsa"),
        "token-only fixture unexpectedly resolved uselesskey-rsa: {reachable:?}"
    );
    assert!(
        !reachable.contains("rsa"),
        "token-only fixture unexpectedly resolved rsa: {reachable:?}"
    );
}
