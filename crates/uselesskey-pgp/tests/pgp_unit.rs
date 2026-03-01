//! External unit tests for uselesskey-pgp.
//!
//! Gaps covered beyond the proptest file and inline tests:
//! - All three PgpSpec variants produce valid armored output with markers
//! - Public key armor/binary output (proptest only tested private key)
//! - Spec isolation: different specs → different fingerprints
//! - Determinism across separate Factory instances
//! - Determinism survives cache clear
//! - User ID contains label
//! - Debug does NOT leak key material
//! - Mismatched public keys through public API
//! - Binary outputs are non-empty for all specs

mod testutil;

use testutil::fx;
use uselesskey_pgp::{PgpFactoryExt, PgpSpec};

// =========================================================================
// All specs produce valid armored output with markers
// =========================================================================

#[test]
fn ed25519_armored_output_has_expected_markers() {
    let fx = fx();
    let key = fx.pgp("ed25519-markers", PgpSpec::ed25519());

    assert!(
        key.private_key_armored()
            .contains("BEGIN PGP PRIVATE KEY BLOCK")
    );
    assert!(
        key.private_key_armored()
            .contains("END PGP PRIVATE KEY BLOCK")
    );
    assert!(
        key.public_key_armored()
            .contains("BEGIN PGP PUBLIC KEY BLOCK")
    );
    assert!(
        key.public_key_armored()
            .contains("END PGP PUBLIC KEY BLOCK")
    );
}

#[test]
fn rsa2048_armored_output_has_expected_markers() {
    let fx = fx();
    let key = fx.pgp("rsa2048-markers", PgpSpec::rsa_2048());

    assert!(
        key.private_key_armored()
            .contains("BEGIN PGP PRIVATE KEY BLOCK")
    );
    assert!(
        key.public_key_armored()
            .contains("BEGIN PGP PUBLIC KEY BLOCK")
    );
}

#[test]
fn rsa3072_armored_output_has_expected_markers() {
    let fx = fx();
    let key = fx.pgp("rsa3072-markers", PgpSpec::rsa_3072());

    assert!(
        key.private_key_armored()
            .contains("BEGIN PGP PRIVATE KEY BLOCK")
    );
    assert!(
        key.public_key_armored()
            .contains("BEGIN PGP PUBLIC KEY BLOCK")
    );
}

// =========================================================================
// Spec isolation
// =========================================================================

#[test]
fn different_specs_produce_different_fingerprints() {
    let fx = fx();
    let ed = fx.pgp("spec-iso", PgpSpec::ed25519());
    let rsa2 = fx.pgp("spec-iso", PgpSpec::rsa_2048());
    let rsa3 = fx.pgp("spec-iso", PgpSpec::rsa_3072());

    assert_ne!(ed.fingerprint(), rsa2.fingerprint());
    assert_ne!(ed.fingerprint(), rsa3.fingerprint());
    assert_ne!(rsa2.fingerprint(), rsa3.fingerprint());
}

// =========================================================================
// Determinism across separate factories
// =========================================================================

#[test]
fn determinism_across_factories() {
    use uselesskey_core::{Factory, Seed};

    let seed1 = Seed::from_env_value("pgp-cross-factory").unwrap();
    let seed2 = Seed::from_env_value("pgp-cross-factory").unwrap();
    let fx1 = Factory::deterministic(seed1);
    let fx2 = Factory::deterministic(seed2);

    let k1 = fx1.pgp("cross-factory", PgpSpec::ed25519());
    let k2 = fx2.pgp("cross-factory", PgpSpec::ed25519());

    assert_eq!(k1.fingerprint(), k2.fingerprint());
    assert_eq!(k1.private_key_armored(), k2.private_key_armored());
    assert_eq!(k1.public_key_armored(), k2.public_key_armored());
}

// =========================================================================
// Determinism survives cache clear
// =========================================================================

#[test]
fn determinism_survives_cache_clear() {
    use uselesskey_core::{Factory, Seed};

    let seed = Seed::from_env_value("pgp-cache-clear").unwrap();
    let fx = Factory::deterministic(seed);

    let k1 = fx.pgp("cache-test", PgpSpec::ed25519());
    let fp1 = k1.fingerprint().to_string();
    let armor1 = k1.private_key_armored().to_string();

    fx.clear_cache();

    let k2 = fx.pgp("cache-test", PgpSpec::ed25519());
    assert_eq!(fp1, k2.fingerprint());
    assert_eq!(armor1, k2.private_key_armored());
}

// =========================================================================
// User ID
// =========================================================================

#[test]
fn user_id_contains_label_and_domain() {
    let fx = fx();
    let key = fx.pgp("my-service", PgpSpec::ed25519());

    assert!(
        key.user_id().contains("my-service"),
        "user_id should contain the label"
    );
    assert!(
        key.user_id().contains("@uselesskey.test"),
        "user_id should contain the test domain"
    );
}

// =========================================================================
// Debug safety
// =========================================================================

#[test]
fn debug_does_not_leak_key_material() {
    let fx = fx();
    let key = fx.pgp("debug-test", PgpSpec::ed25519());
    let dbg = format!("{key:?}");

    assert!(dbg.contains("PgpKeyPair"));
    assert!(dbg.contains("debug-test"));
    assert!(
        !dbg.contains("BEGIN PGP PRIVATE KEY BLOCK"),
        "Debug must not contain private key armor"
    );
    assert!(
        !dbg.contains("BEGIN PGP PUBLIC KEY BLOCK"),
        "Debug must not contain public key armor"
    );
    assert!(
        dbg.contains(".."),
        "Debug should use finish_non_exhaustive()"
    );
}

// =========================================================================
// Mismatched keys
// =========================================================================

#[test]
fn mismatched_public_key_differs_from_original() {
    let fx = fx();
    let key = fx.pgp("mismatch-ext", PgpSpec::ed25519());

    assert_ne!(key.mismatched_public_key_binary(), key.public_key_binary());
    assert_ne!(
        key.mismatched_public_key_armored(),
        key.public_key_armored()
    );
}

// =========================================================================
// Binary outputs non-empty for all specs
// =========================================================================

#[test]
fn binary_outputs_are_non_empty_for_all_specs() {
    let fx = fx();

    for spec in [PgpSpec::ed25519(), PgpSpec::rsa_2048(), PgpSpec::rsa_3072()] {
        let key = fx.pgp("binary-check", spec);
        assert!(
            !key.private_key_binary().is_empty(),
            "private binary should not be empty for {:?}",
            spec
        );
        assert!(
            !key.public_key_binary().is_empty(),
            "public binary should not be empty for {:?}",
            spec
        );
    }
}

// =========================================================================
// Public key armor is parseable (proptest only tested private key)
// =========================================================================

#[test]
fn public_key_armor_is_parseable() {
    use pgp::composed::{Deserializable, SignedPublicKey};
    use std::io::Cursor;

    let fx = fx();
    let key = fx.pgp("pub-parse", PgpSpec::ed25519());

    let result = SignedPublicKey::from_armor_single(Cursor::new(key.public_key_armored()));
    assert!(
        result.is_ok(),
        "Armored public key should be parseable, error: {:?}",
        result.err()
    );
}

#[test]
fn public_key_binary_is_parseable() {
    use pgp::composed::{Deserializable, SignedPublicKey};
    use std::io::Cursor;

    let fx = fx();
    let key = fx.pgp("pub-bin-parse", PgpSpec::ed25519());

    let result = SignedPublicKey::from_bytes(Cursor::new(key.public_key_binary()));
    assert!(
        result.is_ok(),
        "Binary public key should be parseable, error: {:?}",
        result.err()
    );
}
