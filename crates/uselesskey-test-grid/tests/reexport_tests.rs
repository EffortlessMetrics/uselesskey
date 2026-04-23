//! Tests verifying that the `uselesskey-test-grid` façade correctly
//! re-exports everything from `uselesskey-feature-grid`.

#![forbid(unsafe_code)]

use uselesskey_test_grid::{
    BDD_FEATURE_MATRIX, BDD_FEATURE_SETS, CORE_FEATURE_MATRIX, FeatureSet, UK_FEATURE_ALL,
    UK_FEATURE_AWS_LC_RS, UK_FEATURE_CORE_FACTORY, UK_FEATURE_CORE_ID, UK_FEATURE_CORE_KEYPAIR,
    UK_FEATURE_CORE_KID, UK_FEATURE_CORE_NEGATIVE, UK_FEATURE_CORE_SEED, UK_FEATURE_CORE_SINK,
    UK_FEATURE_CORE_TOKEN_SHAPE, UK_FEATURE_ECDSA, UK_FEATURE_ED25519, UK_FEATURE_HMAC,
    UK_FEATURE_JWK, UK_FEATURE_JWT, UK_FEATURE_PGP, UK_FEATURE_RING, UK_FEATURE_RSA,
    UK_FEATURE_SSH,
    UK_FEATURE_RUSTCRYPTO, UK_FEATURE_RUSTLS, UK_FEATURE_SETS, UK_FEATURE_TOKEN, UK_FEATURE_TONIC,
    UK_FEATURE_X509,
};

// ---------------------------------------------------------------------------
// Re-export identity: values match the canonical crate
// ---------------------------------------------------------------------------

#[test]
fn core_feature_matrix_matches_canonical() {
    assert_eq!(
        CORE_FEATURE_MATRIX.len(),
        uselesskey_feature_grid::CORE_FEATURE_MATRIX.len()
    );
    for (a, b) in CORE_FEATURE_MATRIX
        .iter()
        .zip(uselesskey_feature_grid::CORE_FEATURE_MATRIX.iter())
    {
        assert_eq!(a, b);
    }
}

#[test]
fn bdd_feature_matrix_matches_canonical() {
    assert_eq!(
        BDD_FEATURE_MATRIX.len(),
        uselesskey_feature_grid::BDD_FEATURE_MATRIX.len()
    );
    for (a, b) in BDD_FEATURE_MATRIX
        .iter()
        .zip(uselesskey_feature_grid::BDD_FEATURE_MATRIX.iter())
    {
        assert_eq!(a, b);
    }
}

#[test]
fn bdd_feature_sets_matches_canonical() {
    assert_eq!(BDD_FEATURE_SETS, uselesskey_feature_grid::BDD_FEATURE_SETS);
}

#[test]
fn uk_feature_sets_matches_canonical() {
    assert_eq!(UK_FEATURE_SETS, uselesskey_feature_grid::UK_FEATURE_SETS);
}

// ---------------------------------------------------------------------------
// Feature constants are accessible and non-empty
// ---------------------------------------------------------------------------

#[test]
fn all_feature_constants_are_non_empty() {
    let constants = [
        UK_FEATURE_ALL,
        UK_FEATURE_RSA,
        UK_FEATURE_ECDSA,
        UK_FEATURE_ED25519,
        UK_FEATURE_HMAC,
        UK_FEATURE_SSH,
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
        UK_FEATURE_CORE_NEGATIVE,
        UK_FEATURE_CORE_TOKEN_SHAPE,
        UK_FEATURE_CORE_SINK,
        UK_FEATURE_AWS_LC_RS,
        UK_FEATURE_RING,
        UK_FEATURE_RUSTCRYPTO,
        UK_FEATURE_RUSTLS,
        UK_FEATURE_TONIC,
    ];
    for c in constants {
        assert!(!c.is_empty(), "feature constant must not be empty");
    }
}

#[test]
fn all_feature_constants_start_with_uk_prefix() {
    let constants = [
        UK_FEATURE_ALL,
        UK_FEATURE_RSA,
        UK_FEATURE_ECDSA,
        UK_FEATURE_ED25519,
        UK_FEATURE_HMAC,
        UK_FEATURE_SSH,
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
        UK_FEATURE_CORE_NEGATIVE,
        UK_FEATURE_CORE_TOKEN_SHAPE,
        UK_FEATURE_CORE_SINK,
        UK_FEATURE_AWS_LC_RS,
        UK_FEATURE_RING,
        UK_FEATURE_RUSTCRYPTO,
        UK_FEATURE_RUSTLS,
        UK_FEATURE_TONIC,
    ];
    for c in constants {
        assert!(c.starts_with("uk-"), "expected uk- prefix: {c}");
    }
}

// ---------------------------------------------------------------------------
// FeatureSet type is usable through the façade
// ---------------------------------------------------------------------------

#[test]
fn feature_set_constructible_via_facade() {
    let fs = FeatureSet::new("facade-test", &["--all-features"]);
    assert_eq!(fs.name, "facade-test");
    assert_eq!(fs.cargo_args, &["--all-features"]);
}

#[test]
fn feature_set_equality_via_facade() {
    let a = FeatureSet::new("eq-test", &["--features", "rsa"]);
    let b = FeatureSet::new("eq-test", &["--features", "rsa"]);
    assert_eq!(a, b);
}

#[test]
fn feature_set_inequality_different_name() {
    let a = FeatureSet::new("name-a", &[]);
    let b = FeatureSet::new("name-b", &[]);
    assert_ne!(a, b);
}

#[test]
fn feature_set_inequality_different_args() {
    let a = FeatureSet::new("same", &["--all-features"]);
    let b = FeatureSet::new("same", &["--no-default-features"]);
    assert_ne!(a, b);
}

#[test]
fn feature_set_debug_via_facade() {
    let fs = FeatureSet::new("debug-test", &[]);
    let dbg = format!("{fs:?}");
    assert!(dbg.contains("debug-test"));
}

#[test]
fn feature_set_clone_via_facade() {
    let original = FeatureSet::new("clone-test", &["--features", "ecdsa"]);
    let cloned = original;
    assert_eq!(original, cloned);
}

// ---------------------------------------------------------------------------
// Matrix content sanity via façade
// ---------------------------------------------------------------------------

#[test]
fn core_matrix_is_non_empty_via_facade() {
    assert!(!CORE_FEATURE_MATRIX.is_empty());
}

#[test]
fn bdd_matrix_is_non_empty_via_facade() {
    assert!(!BDD_FEATURE_MATRIX.is_empty());
}

#[test]
fn uk_feature_sets_is_non_empty_via_facade() {
    assert!(!UK_FEATURE_SETS.is_empty());
}
