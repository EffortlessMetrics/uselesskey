use std::collections::{BTreeSet, HashSet};

#[derive(Debug, Clone)]
pub struct Plan {
    pub impacted_crates: BTreeSet<String>,
    pub directly_changed_crates: BTreeSet<String>,
    pub run_fmt: bool,
    pub run_clippy: bool,
    pub run_tests: bool,
    pub run_feature_matrix: bool,
    pub run_dep_guard: bool,
    pub run_bdd: bool,
    pub run_mutants: bool,
    pub run_fuzz: bool,
    pub run_no_blob: bool,
    pub run_coverage: bool,
    pub run_publish_preflight: bool,
    pub run_root_tests: bool,
    pub run_xtask_tests: bool,
    pub docs_only: bool,
}

pub fn build_plan(paths: &[String]) -> Plan {
    let mut crate_rust_changed = false;
    let mut xtask_changed = false;
    let mut xtask_cargo_changed = false;
    let mut fuzz_changed = false;
    let mut root_tests_changed = false;
    let mut examples_changed = false;
    let mut cargo_changed = false;
    let mut bdd_feature_changed = false;
    let mut no_blob_trigger = false;
    let mut tests_cargo_changed = false;
    let mut changed_crates: HashSet<String> = HashSet::new();
    let mut source_changed_crates: HashSet<String> = HashSet::new();

    for path in paths {
        let path = normalize_path(path);

        if is_crate_rust_change(&path) {
            crate_rust_changed = true;
            if let Some(crate_name) = crate_from_path(&path) {
                source_changed_crates.insert(crate_name);
            }
        }
        if is_xtask_change(&path) {
            xtask_changed = true;
        }
        if path == "xtask/Cargo.toml" {
            xtask_cargo_changed = true;
        }
        if is_fuzz_change(&path) {
            fuzz_changed = true;
        }
        if is_root_tests_change(&path) {
            root_tests_changed = true;
        }
        if is_examples_change(&path) {
            examples_changed = true;
        }

        if path.ends_with("Cargo.toml") || path.ends_with("Cargo.lock") {
            cargo_changed = true;
        }
        if path == "tests/Cargo.toml" {
            tests_cargo_changed = true;
        }

        if path.starts_with("crates/uselesskey-bdd/")
            || path.starts_with("features/")
            || path.ends_with(".feature") && path.contains("features/")
        {
            bdd_feature_changed = true;
        }

        if is_no_blob_trigger(&path) {
            no_blob_trigger = true;
        }

        if let Some(crate_name) = crate_from_path(&path) {
            changed_crates.insert(crate_name);
        }
    }

    let impacted_crates = expand_impacted_crates(&changed_crates);
    let directly_changed_crates = source_changed_crates.into_iter().collect::<BTreeSet<_>>();

    // any_rust_changed is the OR of all five classifiers (used for fmt/clippy)
    let any_rust_changed = crate_rust_changed
        || xtask_changed
        || fuzz_changed
        || root_tests_changed
        || examples_changed;

    let run_fmt = any_rust_changed || cargo_changed;
    let run_clippy = run_fmt;
    let run_tests = crate_rust_changed || root_tests_changed || !impacted_crates.is_empty();
    let run_feature_matrix = cargo_changed
        || paths.iter().any(|p| {
            let p = normalize_path(p);
            p.starts_with("crates/uselesskey/")
                || (p.starts_with("crates/uselesskey-bdd/") && p.ends_with(".feature"))
        });
    let run_dep_guard = cargo_changed;
    let run_bdd = crate_rust_changed || bdd_feature_changed;
    let run_mutants = crate_rust_changed;
    let run_fuzz = crate_rust_changed || fuzz_changed;
    let run_no_blob = no_blob_trigger;
    let run_coverage = crate_rust_changed;
    let run_publish_preflight = cargo_changed;
    let run_root_tests = root_tests_changed || tests_cargo_changed;
    let run_xtask_tests = xtask_changed || xtask_cargo_changed;

    let run_any = run_fmt
        || run_clippy
        || run_tests
        || run_feature_matrix
        || run_dep_guard
        || run_bdd
        || run_mutants
        || run_fuzz
        || run_no_blob
        || run_coverage
        || run_publish_preflight
        || run_root_tests
        || run_xtask_tests;

    Plan {
        impacted_crates,
        directly_changed_crates,
        run_fmt,
        run_clippy,
        run_tests,
        run_feature_matrix,
        run_dep_guard,
        run_bdd,
        run_mutants,
        run_fuzz,
        run_no_blob,
        run_coverage,
        run_publish_preflight,
        run_root_tests,
        run_xtask_tests,
        docs_only: !run_any,
    }
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn is_crate_rust_change(path: &str) -> bool {
    path.ends_with(".rs")
        && path.starts_with("crates/")
        && (path.contains("/src/") || path.contains("/tests/"))
}

fn is_xtask_change(path: &str) -> bool {
    path.ends_with(".rs") && path.starts_with("xtask/")
}

fn is_fuzz_change(path: &str) -> bool {
    path.ends_with(".rs") && path.starts_with("fuzz/")
}

fn is_root_tests_change(path: &str) -> bool {
    path.ends_with(".rs") && path.starts_with("tests/")
}

fn is_examples_change(path: &str) -> bool {
    path.ends_with(".rs") && path.starts_with("examples/")
}

fn is_no_blob_trigger(path: &str) -> bool {
    path.starts_with("tests/")
        || path.starts_with("fixtures/")
        || path.starts_with("testdata/")
        || (path.starts_with("crates/") && path.contains("/tests/"))
}

fn crate_from_path(path: &str) -> Option<String> {
    let mut parts = path.split('/');
    if parts.next()? != "crates" {
        return None;
    }
    parts.next().map(|s| s.to_string())
}

fn expand_impacted_crates(changed: &HashSet<String>) -> BTreeSet<String> {
    let mut impacted: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<String> = changed.iter().cloned().collect();

    while let Some(name) = queue.pop() {
        if impacted.insert(name.clone()) {
            for &dep in dependents(&name) {
                if !impacted.contains(dep) {
                    queue.push(dep.to_string());
                }
            }
        }
    }

    impacted
}

fn dependents(crate_name: &str) -> &'static [&'static str] {
    match crate_name {
        "uselesskey-core-seed" => &["uselesskey-core-id"],
        "uselesskey-core-id" => &["uselesskey-core-cache", "uselesskey-core"],
        "uselesskey-core-kid" => &["uselesskey-core-keypair-material", "uselesskey-hmac"],
        "uselesskey-core-keypair-material" => &[
            "uselesskey-core-keypair",
            "uselesskey-rsa",
            "uselesskey-ecdsa",
            "uselesskey-ed25519",
        ],
        "uselesskey-core-keypair" => &[],
        "uselesskey-core-base62" => &["uselesskey-core-token-shape"],
        "uselesskey-core-factory" => &["uselesskey-core"],
        "uselesskey-core-hmac-spec" => &["uselesskey-hmac"],
        "uselesskey-core-negative-der" => &["uselesskey-core-negative"],
        "uselesskey-core-negative-pem" => &["uselesskey-core-negative"],
        "uselesskey-core-rustls-pki" => &["uselesskey-rustls"],
        "uselesskey-core-x509-chain-negative" => &["uselesskey-core-x509-negative"],
        "uselesskey-core-x509-negative" => &["uselesskey-core-x509"],
        "uselesskey-core-hash" => &[
            "uselesskey-core-id",
            "uselesskey-core-negative",
            "uselesskey-core-negative-pem",
            "uselesskey-core-x509-derive",
        ],
        "uselesskey-core-jwks-order" => &["uselesskey-core-jwk-builder"],
        "uselesskey-core-jwk-builder" => &["uselesskey-core-jwk"],
        "uselesskey-core-cache" => &["uselesskey-core"],
        "uselesskey-core-negative" => &["uselesskey-core"],
        "uselesskey-core-sink" => &["uselesskey-core"],
        "uselesskey-core-token" => &["uselesskey-token"],
        "uselesskey-core-token-shape" => &["uselesskey-core-token"],
        "uselesskey-core-jwk-shape" => &["uselesskey-core-jwk", "uselesskey-core-jwk-builder"],
        "uselesskey-core-jwk" => &["uselesskey-jwk"],
        "uselesskey-core-x509-spec" => &["uselesskey-core-x509"],
        "uselesskey-core-x509-derive" => &["uselesskey-core-x509"],
        "uselesskey-core-x509" => &["uselesskey-x509"],
        "uselesskey-core" => &[
            "uselesskey-rsa",
            "uselesskey-ecdsa",
            "uselesskey-ed25519",
            "uselesskey-hmac",
            "uselesskey-token",
            "uselesskey-pgp",
            "uselesskey-x509",
            "uselesskey",
            "uselesskey-bdd",
        ],
        "uselesskey-rsa" => &[
            "uselesskey-x509",
            "uselesskey",
            "uselesskey-jsonwebtoken",
            "uselesskey-rustls",
            "uselesskey-ring",
            "uselesskey-rustcrypto",
            "uselesskey-aws-lc-rs",
        ],
        "uselesskey-ecdsa" => &[
            "uselesskey",
            "uselesskey-jsonwebtoken",
            "uselesskey-rustls",
            "uselesskey-ring",
            "uselesskey-rustcrypto",
            "uselesskey-aws-lc-rs",
        ],
        "uselesskey-ed25519" => &[
            "uselesskey",
            "uselesskey-jsonwebtoken",
            "uselesskey-rustls",
            "uselesskey-ring",
            "uselesskey-rustcrypto",
            "uselesskey-aws-lc-rs",
        ],
        "uselesskey-x509" => &["uselesskey", "uselesskey-rustls", "uselesskey-tonic"],
        "uselesskey-jwk" => &[
            "uselesskey-rsa",
            "uselesskey-ecdsa",
            "uselesskey-ed25519",
            "uselesskey-hmac",
            "uselesskey",
        ],
        "uselesskey-hmac" => &[
            "uselesskey",
            "uselesskey-jsonwebtoken",
            "uselesskey-rustcrypto",
        ],
        "uselesskey-token" => &["uselesskey"],
        "uselesskey-pgp" => &["uselesskey"],
        "uselesskey" => &[],
        "uselesskey-jsonwebtoken" => &[],
        "uselesskey-rustls" => &[],
        "uselesskey-tonic" => &[],
        "uselesskey-ring" => &[],
        "uselesskey-rustcrypto" => &[],
        "uselesskey-aws-lc-rs" => &[],
        "uselesskey-bdd-steps" => &["uselesskey-bdd"],
        "uselesskey-bdd" => &["uselesskey-bdd"],
        "uselesskey-feature-grid" => &["uselesskey-test-grid"],
        "uselesskey-interop-tests" => &[],
        "uselesskey-test-grid" => &["uselesskey-bdd"],
        "uselesskey-token-spec" => &["uselesskey-core-token-shape", "uselesskey-token"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docs_only_changes_skip_all() {
        let paths = vec!["README.md".to_string(), "docs/architecture.md".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.docs_only);
        assert!(!plan.run_fmt);
        assert!(!plan.run_clippy);
        assert!(!plan.run_tests);
        assert!(!plan.run_feature_matrix);
        assert!(!plan.run_bdd);
        assert!(!plan.run_mutants);
        assert!(!plan.run_fuzz);
        assert!(!plan.run_no_blob);
        assert!(!plan.run_coverage);
        assert!(!plan.run_publish_preflight);
        assert!(plan.impacted_crates.is_empty());
    }

    #[test]
    fn core_change_expands_dependents() {
        let paths = vec!["crates/uselesskey-core/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core"));
        assert!(impacted.contains("uselesskey-rsa"));
        assert!(impacted.contains("uselesskey-ecdsa"));
        assert!(impacted.contains("uselesskey-ed25519"));
        assert!(impacted.contains("uselesskey-hmac"));
        assert!(impacted.contains("uselesskey-token"));
        assert!(impacted.contains("uselesskey-pgp"));
        assert!(impacted.contains("uselesskey-x509"));
        assert!(impacted.contains("uselesskey"));
        assert!(impacted.contains("uselesskey-bdd"));
        assert!(plan.run_bdd);
        assert!(plan.run_mutants);
        assert!(plan.run_fuzz);
    }

    #[test]
    fn core_id_change_expands_to_core_and_facade() {
        let paths = vec!["crates/uselesskey-core-id/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-id"));
        assert!(impacted.contains("uselesskey-core-cache"));
        assert!(impacted.contains("uselesskey-core"));
        assert!(impacted.contains("uselesskey-rsa"));
        assert!(impacted.contains("uselesskey"));
        assert!(impacted.contains("uselesskey-bdd"));
    }

    #[test]
    fn core_seed_change_expands_to_core_id_stack() {
        let paths = vec!["crates/uselesskey-core-seed/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-seed"));
        assert!(impacted.contains("uselesskey-core-id"));
        assert!(impacted.contains("uselesskey-core-cache"));
        assert!(impacted.contains("uselesskey-core"));
        assert!(impacted.contains("uselesskey-rsa"));
        assert!(impacted.contains("uselesskey"));
        assert!(impacted.contains("uselesskey-bdd"));
    }

    #[test]
    fn core_cache_change_expands_to_core_and_facade() {
        let paths = vec!["crates/uselesskey-core-cache/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-cache"));
        assert!(impacted.contains("uselesskey-core"));
        assert!(impacted.contains("uselesskey-rsa"));
        assert!(impacted.contains("uselesskey"));
        assert!(impacted.contains("uselesskey-bdd"));
    }

    #[test]
    fn core_kid_change_expands_to_keypair_and_hmac_dependents() {
        let paths = vec!["crates/uselesskey-core-kid/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-kid"));
        assert!(impacted.contains("uselesskey-core-keypair-material"));
        assert!(impacted.contains("uselesskey-core-keypair"));
        assert!(impacted.contains("uselesskey-hmac"));
        assert!(impacted.contains("uselesskey-rsa"));
        assert!(impacted.contains("uselesskey-ecdsa"));
        assert!(impacted.contains("uselesskey-ed25519"));
        assert!(impacted.contains("uselesskey-jsonwebtoken"));
    }

    #[test]
    fn core_keypair_material_change_expands_to_key_fixture_crates() {
        let paths = vec!["crates/uselesskey-core-keypair-material/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-keypair-material"));
        assert!(impacted.contains("uselesskey-core-keypair"));
        assert!(impacted.contains("uselesskey-rsa"));
        assert!(impacted.contains("uselesskey-ecdsa"));
        assert!(impacted.contains("uselesskey-ed25519"));
    }

    #[test]
    fn core_keypair_change_is_self_only() {
        let paths = vec!["crates/uselesskey-core-keypair/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-keypair"));
        assert_eq!(impacted.len(), 1);
    }

    #[test]
    fn core_negative_change_expands_to_core_and_facade() {
        let paths = vec!["crates/uselesskey-core-negative/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-negative"));
        assert!(impacted.contains("uselesskey-core"));
        assert!(impacted.contains("uselesskey-rsa"));
        assert!(impacted.contains("uselesskey"));
        assert!(impacted.contains("uselesskey-bdd"));
    }

    #[test]
    fn core_sink_change_expands_to_core_and_dependents() {
        let paths = vec!["crates/uselesskey-core-sink/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-sink"));
        assert!(impacted.contains("uselesskey-core"));
        assert!(impacted.contains("uselesskey"));
        assert!(impacted.contains("uselesskey-rsa"));
        assert!(impacted.contains("uselesskey-bdd"));
    }

    #[test]
    fn core_token_change_expands_to_token_and_facade() {
        let paths = vec!["crates/uselesskey-core-token/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-token"));
        assert!(impacted.contains("uselesskey-token"));
        assert!(impacted.contains("uselesskey"));
    }

    #[test]
    fn core_token_shape_change_expands_to_token_and_token_facade() {
        let paths = vec!["crates/uselesskey-core-token-shape/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-token-shape"));
        assert!(impacted.contains("uselesskey-core-token"));
        assert!(impacted.contains("uselesskey-token"));
        assert!(impacted.contains("uselesskey"));
    }

    #[test]
    fn core_jwk_change_expands_to_jwk_and_key_crates() {
        let paths = vec!["crates/uselesskey-core-jwk/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-jwk"));
        assert!(impacted.contains("uselesskey-jwk"));
        assert!(impacted.contains("uselesskey-rsa"));
        assert!(impacted.contains("uselesskey-ecdsa"));
        assert!(impacted.contains("uselesskey-ed25519"));
        assert!(impacted.contains("uselesskey-hmac"));
        assert!(impacted.contains("uselesskey"));
    }

    #[test]
    fn core_jwk_shape_change_expands_to_jwk_and_builder() {
        let paths = vec!["crates/uselesskey-core-jwk-shape/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-jwk-shape"));
        assert!(impacted.contains("uselesskey-core-jwk"));
        assert!(impacted.contains("uselesskey-core-jwk-builder"));
        assert!(impacted.contains("uselesskey-jwk"));
        assert!(impacted.contains("uselesskey-rsa"));
        assert!(impacted.contains("uselesskey-ecdsa"));
        assert!(impacted.contains("uselesskey-ed25519"));
        assert!(impacted.contains("uselesskey-hmac"));
        assert!(impacted.contains("uselesskey"));
    }

    #[test]
    fn core_x509_spec_change_expands_to_x509_stack() {
        let paths = vec!["crates/uselesskey-core-x509-spec/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-x509-spec"));
        assert!(impacted.contains("uselesskey-core-x509"));
        assert!(impacted.contains("uselesskey-x509"));
        assert!(impacted.contains("uselesskey"));
        assert!(impacted.contains("uselesskey-rustls"));
        assert!(impacted.contains("uselesskey-tonic"));
    }

    #[test]
    fn core_x509_derive_change_expands_to_x509_stack() {
        let paths = vec!["crates/uselesskey-core-x509-derive/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-x509-derive"));
        assert!(impacted.contains("uselesskey-core-x509"));
        assert!(impacted.contains("uselesskey-x509"));
        assert!(impacted.contains("uselesskey"));
        assert!(impacted.contains("uselesskey-rustls"));
        assert!(impacted.contains("uselesskey-tonic"));
    }

    #[test]
    fn core_x509_change_expands_to_x509_stack() {
        let paths = vec!["crates/uselesskey-core-x509/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-x509"));
        assert!(impacted.contains("uselesskey-x509"));
        assert!(impacted.contains("uselesskey"));
        assert!(impacted.contains("uselesskey-rustls"));
        assert!(impacted.contains("uselesskey-tonic"));
    }

    #[test]
    fn examples_path_counts_as_rust_code_change() {
        let paths = vec!["examples/demo.rs".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_fmt);
        assert!(plan.run_clippy);
        // examples-only changes don't trigger tests (no crate source or root test changes)
        assert!(!plan.run_tests);
    }

    #[test]
    fn xtask_only_change_skips_expensive_steps() {
        let paths = vec!["xtask/src/main.rs".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_fmt);
        assert!(plan.run_clippy);
        assert!(!plan.run_tests);
        assert!(!plan.run_bdd);
        assert!(!plan.run_mutants);
        assert!(!plan.run_fuzz);
        assert!(!plan.run_coverage);
        assert!(!plan.run_root_tests);
        assert!(plan.run_xtask_tests);
        assert!(plan.directly_changed_crates.is_empty());
    }

    #[test]
    fn xtask_rs_change_triggers_xtask_tests() {
        let paths = vec!["xtask/src/main.rs".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_xtask_tests);
    }

    #[test]
    fn xtask_cargo_change_triggers_xtask_tests() {
        let paths = vec!["xtask/Cargo.toml".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_xtask_tests);
    }

    #[test]
    fn fuzz_only_change_runs_fuzz_but_not_mutants() {
        let paths = vec!["fuzz/fuzz_targets/pem_corrupt.rs".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_fmt);
        assert!(plan.run_clippy);
        assert!(plan.run_fuzz);
        assert!(!plan.run_mutants);
        assert!(!plan.run_bdd);
        assert!(!plan.run_coverage);
    }

    #[test]
    fn root_tests_change_triggers_root_tests() {
        let paths = vec!["tests/governance.rs".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_fmt);
        assert!(plan.run_clippy);
        assert!(plan.run_tests);
        assert!(plan.run_root_tests);
        assert!(!plan.run_bdd);
        assert!(!plan.run_mutants);
        assert!(!plan.run_fuzz);
        assert!(!plan.run_coverage);
    }

    #[test]
    fn tests_cargo_toml_triggers_root_tests() {
        let paths = vec!["tests/Cargo.toml".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_root_tests);
        assert!(!plan.run_bdd);
        assert!(!plan.run_mutants);
        assert!(!plan.run_fuzz);
        assert!(!plan.run_coverage);
    }

    #[test]
    fn release_prep_cargo_only_skips_expensive_steps() {
        let paths = vec![
            "Cargo.toml".to_string(),
            "crates/uselesskey-core/Cargo.toml".to_string(),
            "crates/uselesskey-rsa/Cargo.toml".to_string(),
        ];
        let plan = build_plan(&paths);
        assert!(plan.run_fmt);
        assert!(plan.run_clippy);
        assert!(plan.run_tests); // impacted_crates is non-empty
        assert!(plan.run_dep_guard);
        assert!(plan.run_publish_preflight);
        assert!(!plan.run_bdd);
        assert!(!plan.run_mutants);
        assert!(!plan.run_fuzz);
        assert!(!plan.run_coverage);
        assert!(!plan.run_root_tests);
        assert!(plan.directly_changed_crates.is_empty());
    }

    #[test]
    fn directly_changed_crates_tracks_source_changes() {
        let paths = vec![
            "crates/uselesskey-core/src/lib.rs".to_string(),
            "crates/uselesskey-rsa/Cargo.toml".to_string(),
        ];
        let plan = build_plan(&paths);
        // directly_changed_crates only includes crates with actual .rs changes (no expansion)
        assert!(plan.directly_changed_crates.contains("uselesskey-core"));
        assert!(!plan.directly_changed_crates.contains("uselesskey-rsa")); // NOT expanded
        // impacted_crates includes both source and Cargo.toml changes (with expansion)
        assert!(plan.impacted_crates.contains("uselesskey-rsa"));
        assert!(plan.impacted_crates.contains("uselesskey-core"));
    }

    #[test]
    fn no_blob_trigger_sets_flag() {
        let paths = vec!["tests/fixtures/secret.pem".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_no_blob);
    }

    #[test]
    fn dependents_unknown_is_empty() {
        assert!(dependents("unknown-crate").is_empty());
    }

    #[test]
    fn bdd_feature_change_runs_bdd() {
        let paths = vec!["crates/uselesskey-bdd/features/rsa.feature".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_bdd);
    }

    #[test]
    fn fuzz_target_change_runs_fuzz() {
        let paths = vec!["fuzz/fuzz_targets/pem_corrupt.rs".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_fuzz);
    }

    #[test]
    fn jwk_change_expands_to_key_crates() {
        let paths = vec!["crates/uselesskey-jwk/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-jwk"));
        assert!(impacted.contains("uselesskey-rsa"));
        assert!(impacted.contains("uselesskey-ecdsa"));
        assert!(impacted.contains("uselesskey-ed25519"));
        assert!(impacted.contains("uselesskey-hmac"));
        assert!(impacted.contains("uselesskey"));
    }

    #[test]
    fn hmac_change_expands_to_facade_and_jwt() {
        let paths = vec!["crates/uselesskey-hmac/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-hmac"));
        assert!(impacted.contains("uselesskey"));
        assert!(impacted.contains("uselesskey-jsonwebtoken"));
    }

    #[test]
    fn token_change_expands_to_facade() {
        let paths = vec!["crates/uselesskey-token/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-token"));
        assert!(impacted.contains("uselesskey"));
    }

    #[test]
    fn x509_change_expands_to_tonic_adapter() {
        let paths = vec!["crates/uselesskey-x509/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-x509"));
        assert!(impacted.contains("uselesskey-rustls"));
        assert!(impacted.contains("uselesskey-tonic"));
    }

    #[test]
    fn pgp_change_expands_to_facade() {
        let paths = vec!["crates/uselesskey-pgp/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-pgp"));
        assert!(impacted.contains("uselesskey"));
    }

    #[test]
    fn rust_change_enables_coverage() {
        let paths = vec!["crates/uselesskey-core/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_coverage);
    }

    #[test]
    fn cargo_change_enables_publish_preflight() {
        let paths = vec!["Cargo.toml".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_publish_preflight);
    }

    #[test]
    fn cargo_lock_triggers_feature_matrix() {
        let paths = vec!["Cargo.lock".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_feature_matrix);
        assert!(plan.run_fmt);
        assert!(plan.run_clippy);
    }

    #[test]
    fn facade_change_triggers_feature_matrix() {
        let paths = vec!["crates/uselesskey/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_feature_matrix);
    }

    #[test]
    fn bdd_feature_file_triggers_feature_matrix() {
        let paths = vec!["crates/uselesskey-bdd/features/rsa.feature".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_feature_matrix);
    }

    #[test]
    fn windows_paths_normalized_for_feature_matrix() {
        let paths = vec!["crates\\uselesskey\\src\\lib.rs".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_feature_matrix);
    }

    #[test]
    fn core_factory_change_expands_to_core_and_facade() {
        let paths = vec!["crates/uselesskey-core-factory/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-factory"));
        assert!(impacted.contains("uselesskey-core"));
        assert!(impacted.contains("uselesskey-rsa"));
        assert!(impacted.contains("uselesskey"));
        assert!(impacted.contains("uselesskey-bdd"));
    }

    #[test]
    fn core_negative_pem_change_expands_to_negative_and_core() {
        let paths = vec!["crates/uselesskey-core-negative-pem/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-negative-pem"));
        assert!(impacted.contains("uselesskey-core-negative"));
        assert!(impacted.contains("uselesskey-core"));
        assert!(impacted.contains("uselesskey"));
    }

    #[test]
    fn core_x509_negative_change_expands_to_x509_stack() {
        let paths = vec!["crates/uselesskey-core-x509-negative/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-x509-negative"));
        assert!(impacted.contains("uselesskey-core-x509"));
        assert!(impacted.contains("uselesskey-x509"));
        assert!(impacted.contains("uselesskey"));
    }

    #[test]
    fn core_hash_change_expands_to_id_and_negative() {
        let paths = vec!["crates/uselesskey-core-hash/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-hash"));
        assert!(impacted.contains("uselesskey-core-id"));
        assert!(impacted.contains("uselesskey-core-negative"));
        assert!(impacted.contains("uselesskey-core-negative-pem"));
        assert!(impacted.contains("uselesskey-core-x509-derive"));
        assert!(impacted.contains("uselesskey-core"));
    }

    #[test]
    fn core_jwk_builder_change_expands_to_jwk_facade() {
        let paths = vec!["crates/uselesskey-core-jwk-builder/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-jwk-builder"));
        assert!(impacted.contains("uselesskey-core-jwk"));
        assert!(impacted.contains("uselesskey-jwk"));
        assert!(impacted.contains("uselesskey-rsa"));
    }

    #[test]
    fn core_negative_der_change_expands_to_negative_and_core() {
        let paths = vec!["crates/uselesskey-core-negative-der/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-negative-der"));
        assert!(impacted.contains("uselesskey-core-negative"));
        assert!(impacted.contains("uselesskey-core"));
    }

    #[test]
    fn core_rustls_pki_change_expands_to_rustls() {
        let paths = vec!["crates/uselesskey-core-rustls-pki/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-rustls-pki"));
        assert!(impacted.contains("uselesskey-rustls"));
    }

    #[test]
    fn core_base62_change_expands_to_token_shape() {
        let paths = vec!["crates/uselesskey-core-base62/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-base62"));
        assert!(impacted.contains("uselesskey-core-token-shape"));
        assert!(impacted.contains("uselesskey-core-token"));
        assert!(impacted.contains("uselesskey-token"));
        assert!(impacted.contains("uselesskey"));
    }

    #[test]
    fn core_hmac_spec_change_expands_to_hmac() {
        let paths = vec!["crates/uselesskey-core-hmac-spec/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-hmac-spec"));
        assert!(impacted.contains("uselesskey-hmac"));
        assert!(impacted.contains("uselesskey"));
    }

    #[test]
    fn core_x509_chain_negative_change_expands_to_x509_stack() {
        let paths = vec!["crates/uselesskey-core-x509-chain-negative/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-core-x509-chain-negative"));
        assert!(impacted.contains("uselesskey-core-x509-negative"));
        assert!(impacted.contains("uselesskey-core-x509"));
        assert!(impacted.contains("uselesskey-x509"));
        assert!(impacted.contains("uselesskey"));
    }

    #[test]
    fn bdd_steps_change_expands_to_bdd() {
        let paths = vec!["crates/uselesskey-bdd-steps/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-bdd-steps"));
        assert!(impacted.contains("uselesskey-bdd"));
    }

    #[test]
    fn feature_grid_change_expands_to_test_grid_and_bdd() {
        let paths = vec!["crates/uselesskey-feature-grid/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-feature-grid"));
        assert!(impacted.contains("uselesskey-test-grid"));
        assert!(impacted.contains("uselesskey-bdd"));
    }

    #[test]
    fn interop_tests_change_is_self_only() {
        let paths = vec!["crates/uselesskey-interop-tests/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-interop-tests"));
        assert_eq!(impacted.len(), 1);
    }

    #[test]
    fn test_grid_change_expands_to_bdd() {
        let paths = vec!["crates/uselesskey-test-grid/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-test-grid"));
        assert!(impacted.contains("uselesskey-bdd"));
    }

    #[test]
    fn token_spec_change_expands_to_token_shape_and_token() {
        let paths = vec!["crates/uselesskey-token-spec/src/lib.rs".to_string()];
        let plan = build_plan(&paths);
        let impacted = &plan.impacted_crates;
        assert!(impacted.contains("uselesskey-token-spec"));
        assert!(impacted.contains("uselesskey-core-token-shape"));
        assert!(impacted.contains("uselesskey-core-token"));
        assert!(impacted.contains("uselesskey-token"));
        assert!(impacted.contains("uselesskey"));
    }
}
