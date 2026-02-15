use std::collections::{BTreeSet, HashSet};

#[derive(Debug, Clone)]
pub struct Plan {
    pub impacted_crates: BTreeSet<String>,
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
    pub docs_only: bool,
}

pub fn build_plan(paths: &[String]) -> Plan {
    let mut rust_code_changed = false;
    let mut cargo_changed = false;
    let mut bdd_feature_changed = false;
    let mut no_blob_trigger = false;
    let mut changed_crates: HashSet<String> = HashSet::new();

    for path in paths {
        let path = normalize_path(path);

        if is_rust_code_change(&path) {
            rust_code_changed = true;
        }

        if path.ends_with("Cargo.toml") || path.ends_with("Cargo.lock") {
            cargo_changed = true;
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

    let run_fmt = rust_code_changed || cargo_changed;
    let run_clippy = run_fmt;
    let run_tests = rust_code_changed || !impacted_crates.is_empty();
    let run_feature_matrix = cargo_changed
        || paths.iter().any(|p| {
            let p = normalize_path(p);
            p.starts_with("crates/uselesskey/")
                || (p.starts_with("crates/uselesskey-bdd/") && p.ends_with(".feature"))
        });
    let run_dep_guard = cargo_changed;
    let run_bdd = rust_code_changed || bdd_feature_changed;
    let run_mutants = rust_code_changed;
    let run_fuzz = rust_code_changed;
    let run_no_blob = no_blob_trigger;
    let run_coverage = rust_code_changed;
    let run_publish_preflight = cargo_changed;

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
        || run_publish_preflight;

    Plan {
        impacted_crates,
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
        docs_only: !run_any,
    }
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn is_rust_code_change(path: &str) -> bool {
    if !path.ends_with(".rs") {
        return false;
    }

    path.starts_with("crates/") && (path.contains("/src/") || path.contains("/tests/"))
        || path.starts_with("xtask/")
        || path.starts_with("fuzz/")
        || path.starts_with("examples/")
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
        "uselesskey-core" => &[
            "uselesskey-rsa",
            "uselesskey-ecdsa",
            "uselesskey-ed25519",
            "uselesskey-hmac",
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
        "uselesskey-x509" => &["uselesskey", "uselesskey-rustls"],
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
        "uselesskey" => &[],
        "uselesskey-jsonwebtoken" => &[],
        "uselesskey-rustls" => &[],
        "uselesskey-ring" => &[],
        "uselesskey-rustcrypto" => &[],
        "uselesskey-aws-lc-rs" => &[],
        "uselesskey-bdd" => &["uselesskey-bdd"],
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
        assert!(impacted.contains("uselesskey-x509"));
        assert!(impacted.contains("uselesskey"));
        assert!(impacted.contains("uselesskey-bdd"));
        assert!(plan.run_bdd);
        assert!(plan.run_mutants);
        assert!(plan.run_fuzz);
    }

    #[test]
    fn examples_path_counts_as_rust_code_change() {
        let paths = vec!["examples/demo.rs".to_string()];
        let plan = build_plan(&paths);
        assert!(plan.run_fmt);
        assert!(plan.run_clippy);
        assert!(plan.run_tests);
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
}
