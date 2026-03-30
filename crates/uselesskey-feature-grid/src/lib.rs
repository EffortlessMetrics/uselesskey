//! Canonical feature-matrix definitions for workspace CI and BDD automation.
//!
//! Exports [`FeatureSet`] entries and the [`CORE_FEATURE_MATRIX`] /
//! [`BDD_FEATURE_MATRIX`] slices consumed by `xtask` and CI receipts.
//! Each entry specifies a stable label and the corresponding Cargo CLI arguments.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Canonical matrix entry used by automation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeatureSet {
    /// Stable matrix label for receipts and logging.
    pub name: &'static str,
    /// Cargo CLI arguments to apply for this matrix row.
    pub cargo_args: &'static [&'static str],
}

impl FeatureSet {
    /// Construct a matrix entry in one location.
    pub const fn new(name: &'static str, cargo_args: &'static [&'static str]) -> Self {
        Self { name, cargo_args }
    }
}

/// BDD tag for the full feature set.
pub const UK_FEATURE_ALL: &str = "uk-all";
/// BDD tag for RSA fixtures.
pub const UK_FEATURE_RSA: &str = "uk-rsa";
/// BDD tag for ECDSA fixtures.
pub const UK_FEATURE_ECDSA: &str = "uk-ecdsa";
/// BDD tag for Ed25519 fixtures.
pub const UK_FEATURE_ED25519: &str = "uk-ed25519";
/// BDD tag for HMAC fixtures.
pub const UK_FEATURE_HMAC: &str = "uk-hmac";
/// BDD tag for PGP fixtures.
pub const UK_FEATURE_PGP: &str = "uk-pgp";
/// BDD tag for SSH fixtures.
pub const UK_FEATURE_SSH: &str = "uk-ssh";
/// BDD tag for X.509 fixtures.
pub const UK_FEATURE_X509: &str = "uk-x509";
/// BDD tag for JWK fixtures.
pub const UK_FEATURE_JWK: &str = "uk-jwk";
/// BDD tag for token fixtures.
pub const UK_FEATURE_TOKEN: &str = "uk-token";
/// BDD tag for JWT adapter fixtures.
pub const UK_FEATURE_JWT: &str = "uk-jwt";
/// BDD tag for core identity module.
pub const UK_FEATURE_CORE_ID: &str = "uk-core-id";
/// BDD tag for core seed module.
pub const UK_FEATURE_CORE_SEED: &str = "uk-core-seed";
/// BDD tag for core factory module.
pub const UK_FEATURE_CORE_FACTORY: &str = "uk-core-factory";
/// BDD tag for core key-ID module.
pub const UK_FEATURE_CORE_KID: &str = "uk-core-kid";
/// BDD tag for core keypair module.
pub const UK_FEATURE_CORE_KEYPAIR: &str = "uk-core-keypair";
/// BDD tag for core negative-fixture module.
pub const UK_FEATURE_CORE_NEGATIVE: &str = "uk-core-negative";
/// BDD tag for core token-shape module.
pub const UK_FEATURE_CORE_TOKEN_SHAPE: &str = "uk-core-token-shape";
/// BDD tag for core sink module.
pub const UK_FEATURE_CORE_SINK: &str = "uk-core-sink";
/// BDD tag for aws-lc-rs adapter.
pub const UK_FEATURE_AWS_LC_RS: &str = "uk-aws-lc-rs";
/// BDD tag for ring adapter.
pub const UK_FEATURE_RING: &str = "uk-ring";
/// BDD tag for RustCrypto adapter.
pub const UK_FEATURE_RUSTCRYPTO: &str = "uk-rustcrypto";
/// BDD tag for rustls adapter.
pub const UK_FEATURE_RUSTLS: &str = "uk-rustls";
/// BDD tag for tonic adapter.
pub const UK_FEATURE_TONIC: &str = "uk-tonic";

/// All BDD feature names in one canonical slice.
pub const UK_FEATURE_SETS: &[&str] = &[
    UK_FEATURE_ALL,
    UK_FEATURE_RSA,
    UK_FEATURE_ECDSA,
    UK_FEATURE_ED25519,
    UK_FEATURE_HMAC,
    UK_FEATURE_PGP,
    UK_FEATURE_SSH,
    UK_FEATURE_X509,
    UK_FEATURE_JWK,
    UK_FEATURE_TOKEN,
    UK_FEATURE_JWT,
    UK_FEATURE_CORE_ID,
    UK_FEATURE_CORE_SEED,
    UK_FEATURE_CORE_FACTORY,
    UK_FEATURE_CORE_KID,
    UK_FEATURE_CORE_KEYPAIR,
    UK_FEATURE_CORE_TOKEN_SHAPE,
    UK_FEATURE_CORE_NEGATIVE,
    UK_FEATURE_CORE_SINK,
    UK_FEATURE_AWS_LC_RS,
    UK_FEATURE_RING,
    UK_FEATURE_RUSTCRYPTO,
    UK_FEATURE_RUSTLS,
    UK_FEATURE_TONIC,
];

/// Core matrix for workspace feature validation.
pub const CORE_FEATURE_MATRIX: &[FeatureSet] = &[
    FeatureSet::new("default", &[]),
    FeatureSet::new("no-default", &["--no-default-features"]),
    FeatureSet::new("rsa", &["--no-default-features", "--features", "rsa"]),
    FeatureSet::new("ecdsa", &["--no-default-features", "--features", "ecdsa"]),
    FeatureSet::new(
        "ed25519",
        &["--no-default-features", "--features", "ed25519"],
    ),
    FeatureSet::new("hmac", &["--no-default-features", "--features", "hmac"]),
    FeatureSet::new("token", &["--no-default-features", "--features", "token"]),
    FeatureSet::new("pgp", &["--no-default-features", "--features", "pgp"]),
    FeatureSet::new("ssh", &["--no-default-features", "--features", "ssh"]),
    FeatureSet::new("x509", &["--no-default-features", "--features", "x509"]),
    FeatureSet::new("jwk", &["--no-default-features", "--features", "jwk"]),
    FeatureSet::new(
        "rsa+jwk",
        &["--no-default-features", "--features", "rsa,jwk"],
    ),
    FeatureSet::new(
        "ecdsa+jwk",
        &["--no-default-features", "--features", "ecdsa,jwk"],
    ),
    FeatureSet::new(
        "ed25519+jwk",
        &["--no-default-features", "--features", "ed25519,jwk"],
    ),
    FeatureSet::new(
        "rsa+x509",
        &["--no-default-features", "--features", "rsa,x509"],
    ),
    FeatureSet::new(
        "ecdsa+x509",
        &["--no-default-features", "--features", "ecdsa,x509"],
    ),
    FeatureSet::new(
        "ed25519+pgp",
        &["--no-default-features", "--features", "ed25519,pgp"],
    ),
    FeatureSet::new(
        "rsa+pgp",
        &["--no-default-features", "--features", "rsa,pgp"],
    ),
    FeatureSet::new("all-features", &["--all-features"]),
];

/// BDD matrix consumed by automation and CI receipt generation.
pub const BDD_FEATURE_MATRIX: &[FeatureSet] = &[
    FeatureSet::new("all-features", &["--features", UK_FEATURE_ALL]),
    FeatureSet::new("all-features+rustls", &["--features", "uk-all,uk-rustls"]),
    FeatureSet::new("all-features+tonic", &["--features", "uk-all,uk-tonic"]),
    FeatureSet::new("all-features+ring", &["--features", "uk-all,uk-ring"]),
    FeatureSet::new(
        "all-features+rustcrypto",
        &["--features", "uk-all,uk-rustcrypto"],
    ),
    FeatureSet::new(
        "all-features+aws-lc-rs",
        &["--features", "uk-all,uk-aws-lc-rs"],
    ),
];

/// All entries in `BDD_FEATURE_MATRIX`, for simple iteration in tooling.
pub const BDD_FEATURE_SETS: &[&str] = &[
    "all-features",
    "all-features+rustls",
    "all-features+tonic",
    "all-features+ring",
    "all-features+rustcrypto",
    "all-features+aws-lc-rs",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_matrix_has_unique_names() {
        for (i, item) in CORE_FEATURE_MATRIX.iter().enumerate() {
            for previous in CORE_FEATURE_MATRIX.iter().take(i) {
                assert_ne!(item.name, previous.name);
            }
        }
    }

    #[test]
    fn bdd_matrix_includes_all_features_flag() {
        assert!(
            BDD_FEATURE_MATRIX
                .iter()
                .any(|entry| entry.cargo_args.contains(&UK_FEATURE_ALL))
        );
    }

    #[test]
    fn bdd_matrix_is_not_empty() {
        assert!(!BDD_FEATURE_MATRIX.is_empty());
    }

    #[test]
    fn bdd_feature_set_is_explicit() {
        for feature in UK_FEATURE_SETS {
            assert!(
                feature.starts_with("uk-"),
                "feature name should use uk-*: {feature}"
            );
        }
    }

    #[test]
    fn bdd_matrix_has_unique_names() {
        for (i, item) in BDD_FEATURE_MATRIX.iter().enumerate() {
            for previous in BDD_FEATURE_MATRIX.iter().take(i) {
                assert_ne!(item.name, previous.name, "duplicate BDD matrix name");
            }
        }
    }

    #[test]
    fn core_matrix_names_are_non_empty() {
        for entry in CORE_FEATURE_MATRIX {
            assert!(
                !entry.name.is_empty(),
                "matrix entry name must not be empty"
            );
        }
    }

    #[test]
    fn bdd_matrix_names_are_non_empty() {
        for entry in BDD_FEATURE_MATRIX {
            assert!(
                !entry.name.is_empty(),
                "BDD matrix entry name must not be empty"
            );
        }
    }

    #[test]
    fn core_matrix_includes_default_and_all_features() {
        let names: Vec<&str> = CORE_FEATURE_MATRIX.iter().map(|e| e.name).collect();
        assert!(names.contains(&"default"), "matrix must include 'default'");
        assert!(
            names.contains(&"all-features"),
            "matrix must include 'all-features'"
        );
    }

    #[test]
    fn core_matrix_no_default_has_flag() {
        let no_default = CORE_FEATURE_MATRIX
            .iter()
            .find(|e| e.name == "no-default")
            .expect("matrix must include 'no-default'");
        assert!(
            no_default.cargo_args.contains(&"--no-default-features"),
            "no-default entry must pass --no-default-features"
        );
    }

    #[test]
    fn core_matrix_default_has_no_args() {
        let default = CORE_FEATURE_MATRIX
            .iter()
            .find(|e| e.name == "default")
            .expect("matrix must include 'default'");
        assert!(
            default.cargo_args.is_empty(),
            "default entry must have no extra cargo args"
        );
    }

    #[test]
    fn bdd_feature_sets_match_bdd_matrix_names() {
        let matrix_names: Vec<&str> = BDD_FEATURE_MATRIX.iter().map(|e| e.name).collect();
        for name in BDD_FEATURE_SETS {
            assert!(
                matrix_names.contains(name),
                "BDD_FEATURE_SETS entry '{name}' missing from BDD_FEATURE_MATRIX"
            );
        }
        assert_eq!(BDD_FEATURE_SETS.len(), BDD_FEATURE_MATRIX.len());
    }

    #[test]
    fn uk_feature_sets_contains_all() {
        assert!(
            UK_FEATURE_SETS.contains(&UK_FEATURE_ALL),
            "UK_FEATURE_SETS must include the 'all' feature"
        );
    }

    #[test]
    fn uk_feature_sets_has_no_duplicates() {
        for (i, feature) in UK_FEATURE_SETS.iter().enumerate() {
            for prev in UK_FEATURE_SETS.iter().take(i) {
                assert_ne!(feature, prev, "duplicate in UK_FEATURE_SETS");
            }
        }
    }

    #[test]
    fn feature_set_new_constructs_correctly() {
        let fs = FeatureSet::new("test-entry", &["--all-features"]);
        assert_eq!(fs.name, "test-entry");
        assert_eq!(fs.cargo_args, &["--all-features"]);
    }

    #[test]
    fn feature_set_equality() {
        let a = FeatureSet::new("a", &["--all-features"]);
        let b = FeatureSet::new("a", &["--all-features"]);
        let c = FeatureSet::new("c", &[]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn feature_set_debug_includes_name() {
        let fs = FeatureSet::new("dbg-test", &[]);
        let dbg = format!("{fs:?}");
        assert!(dbg.contains("dbg-test"));
    }

    #[test]
    fn feature_set_clone() {
        let original = FeatureSet::new("clone-test", &["--features", "rsa"]);
        let cloned = original;
        assert_eq!(original, cloned);
    }

    // --- Wave 81: additional coverage ---

    #[test]
    fn core_matrix_all_features_has_flag() {
        let all = CORE_FEATURE_MATRIX
            .iter()
            .find(|e| e.name == "all-features")
            .expect("matrix must include 'all-features'");
        assert!(
            all.cargo_args.contains(&"--all-features"),
            "all-features entry must pass --all-features"
        );
    }

    #[test]
    fn core_matrix_feature_entries_use_no_default_features() {
        for entry in CORE_FEATURE_MATRIX {
            if entry.name != "default" && entry.name != "all-features" {
                assert!(
                    entry.cargo_args.contains(&"--no-default-features"),
                    "non-default entry '{}' should use --no-default-features",
                    entry.name
                );
            }
        }
    }

    #[test]
    fn core_matrix_names_are_ascii_lowercase_or_punctuation() {
        for entry in CORE_FEATURE_MATRIX {
            assert!(
                entry
                    .name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '+'),
                "matrix name '{}' should be lowercase ascii/digits with dashes/plus",
                entry.name
            );
        }
    }

    #[test]
    fn bdd_matrix_names_are_ascii_lowercase_or_punctuation() {
        for entry in BDD_FEATURE_MATRIX {
            assert!(
                entry
                    .name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '+'),
                "BDD matrix name '{}' should be lowercase ascii/digits with dashes/plus",
                entry.name
            );
        }
    }

    #[test]
    fn bdd_matrix_all_entries_have_features_arg() {
        for entry in BDD_FEATURE_MATRIX {
            assert!(
                entry.cargo_args.contains(&"--features"),
                "BDD entry '{}' should pass --features",
                entry.name
            );
        }
    }

    #[test]
    fn uk_feature_constants_match_uk_feature_sets_entries() {
        let constants = [
            UK_FEATURE_ALL,
            UK_FEATURE_RSA,
            UK_FEATURE_ECDSA,
            UK_FEATURE_ED25519,
            UK_FEATURE_HMAC,
            UK_FEATURE_PGP,
            UK_FEATURE_SSH,
            UK_FEATURE_X509,
            UK_FEATURE_JWK,
            UK_FEATURE_TOKEN,
            UK_FEATURE_JWT,
            UK_FEATURE_CORE_ID,
            UK_FEATURE_CORE_SEED,
            UK_FEATURE_CORE_FACTORY,
            UK_FEATURE_CORE_KID,
            UK_FEATURE_CORE_KEYPAIR,
            UK_FEATURE_CORE_TOKEN_SHAPE,
            UK_FEATURE_CORE_NEGATIVE,
            UK_FEATURE_CORE_SINK,
            UK_FEATURE_AWS_LC_RS,
            UK_FEATURE_RING,
            UK_FEATURE_RUSTCRYPTO,
            UK_FEATURE_RUSTLS,
            UK_FEATURE_TONIC,
        ];
        assert_eq!(
            constants.len(),
            UK_FEATURE_SETS.len(),
            "constants count must match UK_FEATURE_SETS length"
        );
        for c in constants {
            assert!(
                UK_FEATURE_SETS.contains(&c),
                "constant '{c}' missing from UK_FEATURE_SETS"
            );
        }
    }

    #[test]
    fn feature_set_inequality_different_args() {
        let a = FeatureSet::new("same", &["--all-features"]);
        let b = FeatureSet::new("same", &["--no-default-features"]);
        assert_ne!(a, b);
    }

    #[test]
    fn feature_set_empty_args() {
        let fs = FeatureSet::new("empty", &[]);
        assert!(fs.cargo_args.is_empty());
    }

    #[test]
    fn bdd_feature_sets_len_matches_matrix() {
        assert_eq!(
            BDD_FEATURE_SETS.len(),
            BDD_FEATURE_MATRIX.len(),
            "BDD_FEATURE_SETS and BDD_FEATURE_MATRIX must have same length"
        );
    }

    #[test]
    fn core_matrix_no_duplicate_cargo_args() {
        for (i, entry) in CORE_FEATURE_MATRIX.iter().enumerate() {
            for prev in CORE_FEATURE_MATRIX.iter().take(i) {
                if entry.cargo_args == prev.cargo_args {
                    panic!(
                        "duplicate cargo_args between '{}' and '{}'",
                        entry.name, prev.name
                    );
                }
            }
        }
    }

    #[test]
    fn bdd_feature_sets_are_non_empty_strings() {
        for name in BDD_FEATURE_SETS {
            assert!(!name.is_empty(), "BDD_FEATURE_SETS entry must not be empty");
        }
    }

    // --- Wave 153: additional coverage ---

    #[test]
    fn core_matrix_cargo_args_strings_are_non_empty() {
        for entry in CORE_FEATURE_MATRIX {
            for arg in entry.cargo_args {
                assert!(
                    !arg.is_empty(),
                    "cargo_args in '{}' must not contain empty strings",
                    entry.name
                );
            }
        }
    }

    #[test]
    fn bdd_matrix_cargo_args_strings_are_non_empty() {
        for entry in BDD_FEATURE_MATRIX {
            for arg in entry.cargo_args {
                assert!(
                    !arg.is_empty(),
                    "cargo_args in BDD entry '{}' must not contain empty strings",
                    entry.name
                );
            }
        }
    }

    #[test]
    fn bdd_matrix_feature_values_are_valid_uk_tags() {
        for entry in BDD_FEATURE_MATRIX {
            // Find the value after "--features"
            let feature_idx = entry
                .cargo_args
                .iter()
                .position(|a| *a == "--features")
                .expect("BDD entry must have --features");
            let features_csv = entry.cargo_args[feature_idx + 1];
            for tag in features_csv.split(',') {
                assert!(
                    UK_FEATURE_SETS.contains(&tag),
                    "BDD entry '{}' references unknown tag '{tag}'",
                    entry.name
                );
            }
        }
    }

    #[test]
    fn core_matrix_covers_all_individual_facade_features() {
        let expected_singles = [
            "rsa", "ecdsa", "ed25519", "hmac", "token", "pgp", "ssh", "x509", "jwk",
        ];
        let names: Vec<&str> = CORE_FEATURE_MATRIX.iter().map(|e| e.name).collect();
        for feature in expected_singles {
            assert!(
                names.contains(&feature),
                "CORE_FEATURE_MATRIX must include single-feature entry '{feature}'"
            );
        }
    }

    #[test]
    fn core_matrix_single_feature_entries_pass_correct_feature() {
        let singles = [
            "rsa", "ecdsa", "ed25519", "hmac", "token", "pgp", "ssh", "x509", "jwk",
        ];
        for name in singles {
            let entry = CORE_FEATURE_MATRIX
                .iter()
                .find(|e| e.name == name)
                .unwrap_or_else(|| panic!("missing entry '{name}'"));
            let feat_idx = entry
                .cargo_args
                .iter()
                .position(|a| *a == "--features")
                .unwrap_or_else(|| panic!("'{name}' should have --features"));
            let value = entry.cargo_args[feat_idx + 1];
            assert!(
                value.contains(name),
                "single-feature entry '{name}' should pass feature '{name}', got '{value}'"
            );
        }
    }

    #[test]
    fn bdd_matrix_no_duplicate_cargo_args() {
        for (i, entry) in BDD_FEATURE_MATRIX.iter().enumerate() {
            for prev in BDD_FEATURE_MATRIX.iter().take(i) {
                if entry.cargo_args == prev.cargo_args {
                    panic!(
                        "duplicate cargo_args between BDD entries '{}' and '{}'",
                        entry.name, prev.name
                    );
                }
            }
        }
    }

    #[test]
    fn bdd_feature_sets_has_no_duplicates() {
        for (i, name) in BDD_FEATURE_SETS.iter().enumerate() {
            for prev in BDD_FEATURE_SETS.iter().take(i) {
                assert_ne!(name, prev, "duplicate in BDD_FEATURE_SETS");
            }
        }
    }

    #[test]
    fn core_matrix_has_minimum_expected_size() {
        // default + no-default + 8 singles + combos + all-features
        assert!(
            CORE_FEATURE_MATRIX.len() >= 11,
            "CORE_FEATURE_MATRIX should have at least 11 entries, got {}",
            CORE_FEATURE_MATRIX.len()
        );
    }

    #[test]
    fn bdd_matrix_every_entry_references_uk_all() {
        for entry in BDD_FEATURE_MATRIX {
            let feat_idx = entry
                .cargo_args
                .iter()
                .position(|a| *a == "--features")
                .expect("BDD entry must have --features");
            let features_csv = entry.cargo_args[feat_idx + 1];
            let tags: Vec<&str> = features_csv.split(',').collect();
            assert!(
                tags.contains(&UK_FEATURE_ALL),
                "BDD entry '{}' should include '{UK_FEATURE_ALL}' tag",
                entry.name
            );
        }
    }

    #[test]
    fn uk_feature_sets_are_non_empty() {
        for feature in UK_FEATURE_SETS {
            assert!(
                !feature.is_empty(),
                "UK_FEATURE_SETS must not have empty entries"
            );
        }
    }

    #[test]
    fn core_matrix_combo_entries_reference_valid_features() {
        let known_features = [
            "rsa", "ecdsa", "ed25519", "hmac", "token", "pgp", "ssh", "x509", "jwk",
        ];
        for entry in CORE_FEATURE_MATRIX {
            if let Some(feat_idx) = entry.cargo_args.iter().position(|a| *a == "--features") {
                let value = entry.cargo_args[feat_idx + 1];
                for feat in value.split(',') {
                    assert!(
                        known_features.contains(&feat),
                        "core entry '{}' references unknown feature '{feat}'",
                        entry.name
                    );
                }
            }
        }
    }
}
