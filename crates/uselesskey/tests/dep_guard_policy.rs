//! Dependency-guard and license-policy tests.
//!
//! These tests parse `Cargo.lock` and `deny.toml` programmatically to verify:
//! - No duplicate semver-major versions of critical RNG dependencies
//! - No duplicate semver-major versions of critical crypto dependencies
//! - All direct workspace dependencies use only approved licenses

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find the workspace root by walking up from the test binary's manifest dir.
fn workspace_root() -> PathBuf {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .expect("cargo metadata should succeed");
    assert!(output.status.success(), "cargo metadata failed");

    let meta: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON from cargo metadata");
    PathBuf::from(meta["workspace_root"].as_str().unwrap())
}

/// Parsed entry from `Cargo.lock`.
#[derive(Debug)]
struct LockEntry {
    name: String,
    version: String,
}

/// Parse all `[[package]]` entries from `Cargo.lock` (TOML v3/v4 format).
fn parse_cargo_lock(root: &Path) -> Vec<LockEntry> {
    let content =
        std::fs::read_to_string(root.join("Cargo.lock")).expect("Cargo.lock should exist");

    let mut entries = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in content.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            // Flush previous entry
            if let (Some(n), Some(v)) = (current_name.take(), current_version.take()) {
                entries.push(LockEntry {
                    name: n,
                    version: v,
                });
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("name = ") {
            current_name = Some(rest.trim_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("version = ") {
            // Skip the top-level `version = 4` (lockfile format version)
            let val = rest.trim_matches('"');
            if current_name.is_some() {
                current_version = Some(val.to_string());
            }
        }
    }
    // Flush last entry
    if let (Some(n), Some(v)) = (current_name, current_version) {
        entries.push(LockEntry {
            name: n,
            version: v,
        });
    }

    entries
}

/// Extract semver major version from a version string (e.g. "0.6.4" → 0).
fn semver_major(version: &str) -> u64 {
    version
        .split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Collect major versions per crate name from the lock entries.
fn major_versions_by_crate(entries: &[LockEntry]) -> HashMap<String, Vec<u64>> {
    let mut map: HashMap<String, Vec<u64>> = HashMap::new();
    for e in entries {
        let major = semver_major(&e.version);
        let majors = map.entry(e.name.clone()).or_default();
        if !majors.contains(&major) {
            majors.push(major);
        }
    }
    map
}

/// Assert that `crate_name` has at most one semver-major version resolved.
fn assert_single_major(majors: &HashMap<String, Vec<u64>>, crate_name: &str, category: &str) {
    if let Some(versions) = majors.get(crate_name) {
        assert!(
            versions.len() <= 1,
            "{category} dep `{crate_name}` has multiple semver-major versions: {versions:?}. \
             This can break deterministic derivation or cause subtle incompatibilities."
        );
    }
    // Absent from lock → not used → no conflict
}

/// Parse allowed licenses from `deny.toml`.
fn parse_deny_allowed_licenses(root: &Path) -> Vec<String> {
    let content = std::fs::read_to_string(root.join("deny.toml")).expect("deny.toml should exist");

    let mut in_allow = false;
    let mut licenses = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("allow") && trimmed.contains('[') {
            in_allow = true;
            // Handle inline items on the same line as `allow = [`
            if let Some(rest) = trimmed.split('[').nth(1) {
                for item in rest.split(',') {
                    let lic = item.trim().trim_matches(|c| c == '"' || c == ']');
                    if !lic.is_empty() {
                        licenses.push(lic.to_string());
                    }
                }
                if trimmed.contains(']') {
                    in_allow = false;
                }
            }
            continue;
        }

        if in_allow {
            if trimmed.contains(']') {
                // Last line of the array
                let before_bracket = trimmed.split(']').next().unwrap_or("");
                let lic = before_bracket.trim().trim_matches(|c| c == '"' || c == ',');
                if !lic.is_empty() {
                    licenses.push(lic.to_string());
                }
                in_allow = false;
            } else {
                let lic = trimmed.trim_matches(|c| c == '"' || c == ',');
                if !lic.is_empty() {
                    licenses.push(lic.to_string());
                }
            }
        }
    }

    licenses
}

/// Check if a license expression (e.g. "MIT OR Apache-2.0") is covered by
/// the allowed set from deny.toml.
///
/// Handles SPDX operators:
/// - `OR`  — disjunctive: at least one alternative must be allowed
/// - `AND` — conjunctive: every part must be allowed
/// - `WITH` — exception modifier: stripped, only the base license is checked
/// - Parentheses are stripped before evaluation.
fn license_expression_allowed(expr: &str, allowed: &[String]) -> bool {
    // Strip all parentheses for a simple flat evaluation.
    let flat = expr.replace('(', "").replace(')', "");

    // Split on " AND " first — every conjunct must be satisfied.
    flat.split(" AND ").all(|conjunct| {
        // Within each conjunct, " OR " means any alternative suffices.
        conjunct.split(" OR ").any(|alt| {
            // Strip " WITH <exception>" suffix (e.g. "Apache-2.0 WITH LLVM-exception").
            let base = alt.split(" WITH ").next().unwrap_or(alt).trim();
            allowed.iter().any(|a| a == base)
        })
    })
}

// ---------------------------------------------------------------------------
// Tests: RNG dependency guard
// ---------------------------------------------------------------------------

/// Critical RNG crates whose major versions must not diverge.
const RNG_DEPS: &[&str] = &["rand", "rand_core", "rand_chacha"];

#[test]
fn no_duplicate_major_versions_of_rng_deps() {
    let root = workspace_root();
    let entries = parse_cargo_lock(&root);
    let majors = major_versions_by_crate(&entries);

    for dep in RNG_DEPS {
        assert_single_major(&majors, dep, "RNG");
    }
}

// ---------------------------------------------------------------------------
// Tests: Crypto dependency guard
// ---------------------------------------------------------------------------

/// Critical crypto crates whose major versions must not diverge.
const CRYPTO_DEPS: &[&str] = &["blake3", "sha2", "hmac", "digest"];

#[test]
fn no_duplicate_major_versions_of_crypto_deps() {
    let root = workspace_root();
    let entries = parse_cargo_lock(&root);
    let majors = major_versions_by_crate(&entries);

    for dep in CRYPTO_DEPS {
        assert_single_major(&majors, dep, "crypto");
    }
}

// ---------------------------------------------------------------------------
// Tests: License policy
// ---------------------------------------------------------------------------

#[test]
fn deny_toml_license_allowlist_is_nonempty() {
    let root = workspace_root();
    let licenses = parse_deny_allowed_licenses(&root);
    assert!(
        !licenses.is_empty(),
        "deny.toml should have a non-empty [licenses].allow list"
    );
}

#[test]
fn deny_toml_includes_expected_core_licenses() {
    let root = workspace_root();
    let licenses = parse_deny_allowed_licenses(&root);

    let expected = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "CC0-1.0"];
    for lic in &expected {
        assert!(
            licenses.iter().any(|l| l == lic),
            "deny.toml should allow {lic}, but allowlist is: {licenses:?}"
        );
    }
}

#[test]
fn all_direct_deps_use_approved_licenses() {
    let root = workspace_root();
    let allowed = parse_deny_allowed_licenses(&root);

    // Use `cargo metadata` to inspect all workspace packages' direct deps
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .current_dir(&root)
        .output()
        .expect("cargo metadata should succeed");
    assert!(output.status.success(), "cargo metadata failed");

    let meta: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON from cargo metadata");

    let packages = meta["packages"].as_array().expect("packages array");

    // Collect workspace member package IDs
    let workspace_members: Vec<&str> = meta["workspace_members"]
        .as_array()
        .expect("workspace_members array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    // Build a lookup from package id → package object
    let pkg_by_id: HashMap<&str, &serde_json::Value> = packages
        .iter()
        .filter_map(|p| Some((p["id"].as_str()?, p)))
        .collect();

    // Collect all direct dependency names from workspace crates
    let mut direct_dep_names: Vec<String> = Vec::new();
    for member_id in &workspace_members {
        if let Some(pkg) = pkg_by_id.get(member_id) {
            if let Some(deps) = pkg["dependencies"].as_array() {
                for dep in deps {
                    if let Some(name) = dep["name"].as_str() {
                        if !direct_dep_names.contains(&name.to_string()) {
                            direct_dep_names.push(name.to_string());
                        }
                    }
                }
            }
        }
    }

    // Check license of each direct dependency
    let mut violations = Vec::new();
    for pkg in packages {
        let name = pkg["name"].as_str().unwrap_or("?");
        if !direct_dep_names.contains(&name.to_string()) {
            continue;
        }
        // Skip workspace-internal crates (they share the workspace license)
        if workspace_members
            .iter()
            .any(|m| pkg["id"].as_str() == Some(*m))
        {
            continue;
        }
        if let Some(license) = pkg["license"].as_str() {
            if !license_expression_allowed(license, &allowed) {
                violations.push(format!("{name}: {license}"));
            }
        }
        // Packages with `license = null` are typically path deps; skip them.
    }

    assert!(
        violations.is_empty(),
        "The following direct dependencies have licenses not in deny.toml allowlist:\n  {}",
        violations.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Tests: Cargo.lock parsing sanity
// ---------------------------------------------------------------------------

#[test]
fn cargo_lock_contains_uselesskey_core() {
    let root = workspace_root();
    let entries = parse_cargo_lock(&root);
    assert!(
        entries.iter().any(|e| e.name == "uselesskey-core"),
        "Cargo.lock should contain uselesskey-core"
    );
}

#[test]
fn cargo_lock_has_no_empty_names() {
    let root = workspace_root();
    let entries = parse_cargo_lock(&root);
    for e in &entries {
        assert!(!e.name.is_empty(), "Cargo.lock entry has empty name");
        assert!(!e.version.is_empty(), "Cargo.lock entry has empty version");
    }
}
