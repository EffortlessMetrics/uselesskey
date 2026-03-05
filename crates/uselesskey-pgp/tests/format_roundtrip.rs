//! Format roundtrip integration tests for PGP.

mod testutil;

use testutil::fx;
use uselesskey_pgp::{PgpFactoryExt, PgpSpec};

// ---------------------------------------------------------------------------
// Armored (PEM-like) format
// ---------------------------------------------------------------------------

#[test]
fn private_armored_has_pgp_headers() {
    let kp = fx().pgp("arm-priv", PgpSpec::ed25519());
    let armored = kp.private_key_armored();
    assert!(
        armored.contains("BEGIN PGP PRIVATE KEY BLOCK"),
        "private armored must contain PGP private header"
    );
    assert!(
        armored.contains("END PGP PRIVATE KEY BLOCK"),
        "private armored must contain PGP private footer"
    );
}

#[test]
fn public_armored_has_pgp_headers() {
    let kp = fx().pgp("arm-pub", PgpSpec::ed25519());
    let armored = kp.public_key_armored();
    assert!(
        armored.contains("BEGIN PGP PUBLIC KEY BLOCK"),
        "public armored must contain PGP public header"
    );
    assert!(
        armored.contains("END PGP PUBLIC KEY BLOCK"),
        "public armored must contain PGP public footer"
    );
}

// ---------------------------------------------------------------------------
// Binary format
// ---------------------------------------------------------------------------

#[test]
fn private_binary_is_non_empty() {
    let kp = fx().pgp("bin-priv", PgpSpec::ed25519());
    assert!(!kp.private_key_binary().is_empty());
}

#[test]
fn public_binary_is_non_empty() {
    let kp = fx().pgp("bin-pub", PgpSpec::ed25519());
    assert!(!kp.public_key_binary().is_empty());
}

#[test]
fn rsa_keys_are_larger_than_ed25519() {
    let fx = fx();
    let ed = fx.pgp("size-ed", PgpSpec::ed25519());
    let rsa = fx.pgp("size-rsa", PgpSpec::rsa_2048());
    assert!(
        rsa.private_key_binary().len() > ed.private_key_binary().len(),
        "RSA PGP key should be larger than Ed25519 PGP key"
    );
}

// ---------------------------------------------------------------------------
// Negative fixtures
// ---------------------------------------------------------------------------

#[test]
fn mismatch_public_key_differs_from_original() {
    let kp = fx().pgp("mismatch-pgp", PgpSpec::ed25519());
    let original = kp.public_key_binary();
    let mismatched = kp.mismatched_public_key_binary();
    assert_ne!(
        original,
        &mismatched[..],
        "mismatched public key must differ from original"
    );
}

#[test]
fn corrupt_armored_alters_header() {
    let kp = fx().pgp("corrupt-pgp", PgpSpec::ed25519());
    let corrupt = kp.private_key_armored_corrupt(uselesskey_core::negative::CorruptPem::BadHeader);
    assert!(
        !corrupt.contains("BEGIN PGP PRIVATE KEY BLOCK"),
        "corrupt BadHeader must not have original PGP header"
    );
}

#[test]
fn truncated_binary_has_exact_length() {
    let kp = fx().pgp("trunc-pgp", PgpSpec::ed25519());
    let truncated = kp.private_key_binary_truncated(12);
    assert_eq!(truncated.len(), 12);
}

#[test]
fn mismatch_armored_is_valid_pgp_format() {
    let kp = fx().pgp("mismatch-arm", PgpSpec::ed25519());
    let mismatched = kp.mismatched_public_key_armored();
    assert!(
        mismatched.contains("BEGIN PGP PUBLIC KEY BLOCK"),
        "mismatched armored key must be valid PGP format"
    );
}
