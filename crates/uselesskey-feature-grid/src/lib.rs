#![forbid(unsafe_code)]

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
pub const UK_FEATURE_CORE_KID: &str = "uk-core-kid";
pub const UK_FEATURE_CORE_KEYPAIR: &str = "uk-core-keypair";
pub const UK_FEATURE_CORE_NEGATIVE: &str = "uk-core-negative";
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
    UK_FEATURE_CORE_KID,
    UK_FEATURE_CORE_KEYPAIR,
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
    use super::{BDD_FEATURE_MATRIX, CORE_FEATURE_MATRIX, UK_FEATURE_ALL, UK_FEATURE_SETS};

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
}
