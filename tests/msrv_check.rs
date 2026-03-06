//! MSRV (Minimum Supported Rust Version) and edition consistency tests.
//!
//! Verifies that every workspace member declares a consistent `rust-version`
//! and `edition`, and that auxiliary config files (`clippy.toml`,
//! `rust-toolchain.toml`) agree with the workspace declaration.

use std::path::{Path, PathBuf};

use toml::Table;
use toml::Value;

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

fn workspace_members(ws: &Table) -> Vec<String> {
    ws["workspace"]["members"]
        .as_array()
        .expect("workspace.members must be an array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

/// Returns `true` when `val` is a table containing `{ workspace = true }`.
fn inherits_workspace(val: &Value) -> bool {
    val.as_table()
        .and_then(|t| t.get("workspace"))
        .and_then(|v| v.as_bool())
        == Some(true)
}

// ---------------------------------------------------------------------------
// 1. All workspace members have consistent rust-version
// ---------------------------------------------------------------------------

#[test]
fn all_members_have_consistent_rust_version() {
    let root = workspace_root();
    let ws = workspace_toml();
    let members = workspace_members(&ws);

    let expected_msrv = ws["workspace"]["package"]["rust-version"]
        .as_str()
        .expect("workspace.package.rust-version must be set");

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

        let crate_name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or(member);

        match pkg.get("rust-version") {
            Some(v) if inherits_workspace(v) => {
                // Good — inherits from workspace.
            }
            Some(v) if v.as_str() == Some(expected_msrv) => {
                // Good — explicit value matches.
            }
            Some(v) => {
                problems.push(format!(
                    "{crate_name}: rust-version is `{}`, expected `{expected_msrv}` \
                     or `{{ workspace = true }}`",
                    v.as_str().unwrap_or("<non-string>")
                ));
            }
            None => {
                problems.push(format!("{crate_name}: missing `rust-version` field"));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "rust-version inconsistencies:\n  {}",
        problems.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 2. Declared MSRV matches clippy.toml
// ---------------------------------------------------------------------------

#[test]
fn msrv_matches_clippy_toml() {
    let root = workspace_root();
    let ws = workspace_toml();

    let cargo_msrv = ws["workspace"]["package"]["rust-version"]
        .as_str()
        .expect("workspace.package.rust-version must be set");

    let clippy_toml = read_toml(&root.join("clippy.toml"));
    let clippy_msrv = clippy_toml
        .get("msrv")
        .and_then(|v| v.as_str())
        .expect("clippy.toml must have msrv");

    assert_eq!(
        cargo_msrv, clippy_msrv,
        "MSRV mismatch: workspace Cargo.toml says `{cargo_msrv}`, \
         clippy.toml says `{clippy_msrv}`"
    );
}

// ---------------------------------------------------------------------------
// 3. Edition is 2024 across all crates
// ---------------------------------------------------------------------------

#[test]
fn all_members_use_edition_2024() {
    let root = workspace_root();
    let ws = workspace_toml();
    let members = workspace_members(&ws);

    let expected_edition = ws["workspace"]["package"]["edition"]
        .as_str()
        .expect("workspace.package.edition must be set");

    assert_eq!(
        expected_edition, "2024",
        "workspace edition should be 2024, got `{expected_edition}`"
    );

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

        let crate_name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or(member);

        match pkg.get("edition") {
            Some(v) if inherits_workspace(v) => {
                // Good — inherits workspace edition 2024.
            }
            Some(v) if v.as_str() == Some(expected_edition) => {
                // Good — explicit value matches.
            }
            Some(v) => {
                problems.push(format!(
                    "{crate_name}: edition is `{}`, expected `{expected_edition}` \
                     or `{{ workspace = true }}`",
                    v.as_str().unwrap_or("<non-string>")
                ));
            }
            None => {
                problems.push(format!("{crate_name}: missing `edition` field"));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "edition inconsistencies:\n  {}",
        problems.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 4. rust-toolchain.toml channel matches workspace MSRV
// ---------------------------------------------------------------------------

#[test]
fn rust_toolchain_channel_matches_msrv() {
    let root = workspace_root();
    let ws = workspace_toml();

    let cargo_msrv = ws["workspace"]["package"]["rust-version"]
        .as_str()
        .expect("workspace.package.rust-version must be set");

    let toolchain_path = root.join("rust-toolchain.toml");
    if !toolchain_path.exists() {
        // No toolchain file — nothing to check.
        return;
    }

    let tc = read_toml(&toolchain_path);
    if let Some(channel) = tc
        .get("toolchain")
        .and_then(|t| t.get("channel"))
        .and_then(|v| v.as_str())
    {
        assert_eq!(
            cargo_msrv, channel,
            "MSRV mismatch: workspace Cargo.toml says `{cargo_msrv}`, \
             rust-toolchain.toml channel is `{channel}`"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. No crate overrides edition or rust-version with a non-workspace value
// ---------------------------------------------------------------------------

#[test]
fn no_crate_overrides_workspace_metadata() {
    let root = workspace_root();
    let ws = workspace_toml();
    let members = workspace_members(&ws);

    let mut overrides = Vec::new();

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

        let crate_name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or(member);

        for field in &["edition", "rust-version"] {
            if let Some(val) = pkg.get(*field) {
                // String literals mean the crate hardcodes a value instead of
                // inheriting from the workspace.
                if val.is_str() {
                    overrides.push(format!(
                        "{crate_name}: `{field}` is hardcoded to `{}`; \
                         prefer `{field}.workspace = true`",
                        val.as_str().unwrap()
                    ));
                }
            }
        }
    }

    assert!(
        overrides.is_empty(),
        "crates override workspace edition/rust-version:\n  {}",
        overrides.join("\n  ")
    );
}
