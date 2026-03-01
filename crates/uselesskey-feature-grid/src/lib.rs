#![forbid(unsafe_code)]
//! Canonical feature and matrix definitions for uselesskey automation.
//!
//! Defines `FeatureSet` entries consumed by `cargo xtask feature-matrix` to
//! drive the CI feature-combination matrix. Each entry specifies a stable
//! label and the corresponding Cargo CLI arguments.

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

/// Canonical BDD feature names.
pub const UK_FEATURE_ALL: &str = "uk-all";
pub const UK_FEATURE_RSA: &str = "uk-rsa";
pub const UK_FEATURE_ECDSA: &str = "uk-ecdsa";
pub const UK_FEATURE_ED25519: &str = "uk-ed25519";
pub const UK_FEATURE_HMAC: &str = "uk-hmac";
pub const UK_FEATURE_PGP: &str = "uk-pgp";
pub const UK_FEATURE_X509: &str = "uk-x509";
pub const UK_FEATURE_JWK: &str = "uk-jwk";
pub const UK_FEATURE_TOKEN: &str = "uk-token";
pub const UK_FEATURE_JWT: &str = "uk-jwt";
pub const UK_FEATURE_CORE_ID: &str = "uk-core-id";
pub const UK_FEATURE_CORE_SEED: &str = "uk-core-seed";
pub const UK_FEATURE_CORE_FACTORY: &str = "uk-core-factory";
pub const UK_FEATURE_CORE_KID: &str = "uk-core-kid";
pub const UK_FEATURE_CORE_KEYPAIR: &str = "uk-core-keypair";
pub const UK_FEATURE_CORE_NEGATIVE: &str = "uk-core-negative";
pub const UK_FEATURE_CORE_TOKEN_SHAPE: &str = "uk-core-token-shape";
pub const UK_FEATURE_CORE_SINK: &str = "uk-core-sink";
pub const UK_FEATURE_AWS_LC_RS: &str = "uk-aws-lc-rs";
pub const UK_FEATURE_RING: &str = "uk-ring";
pub const UK_FEATURE_RUSTCRYPTO: &str = "uk-rustcrypto";
pub const UK_FEATURE_RUSTLS: &str = "uk-rustls";
pub const UK_FEATURE_TONIC: &str = "uk-tonic";

/// All BDD feature names in one canonical slice.
pub const UK_FEATURE_SETS: &[&str] = &[
    UK_FEATURE_ALL,
    UK_FEATURE_RSA,
    UK_FEATURE_ECDSA,
    UK_FEATURE_ED25519,
    UK_FEATURE_HMAC,
    UK_FEATURE_PGP,
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
}
