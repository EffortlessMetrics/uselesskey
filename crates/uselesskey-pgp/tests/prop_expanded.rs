//! Expanded property tests for PGP key generation.

#[allow(dead_code)]
mod testutil;

use proptest::prelude::*;

use uselesskey_core::{Factory, Seed};
use uselesskey_pgp::{PgpFactoryExt, PgpSpec};

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

    /// Debug output never leaks private key material.
    #[test]
    fn debug_does_not_leak_key_material(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let key = fx.pgp("prop-debug", PgpSpec::ed25519());
        let dbg = format!("{key:?}");

        prop_assert!(dbg.contains("PgpKeyPair"));
        prop_assert!(!dbg.contains("BEGIN PGP PRIVATE KEY BLOCK"));
        prop_assert!(!dbg.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    }

    /// Different labels produce different fingerprints.
    #[test]
    fn label_independence(
        seed in any::<[u8; 32]>(),
        label_a in "[a-zA-Z][a-zA-Z0-9]{1,10}",
        label_b in "[a-zA-Z][a-zA-Z0-9]{1,10}",
    ) {
        prop_assume!(label_a != label_b);
        let fx = Factory::deterministic(Seed::new(seed));
        let ka = fx.pgp(&label_a, PgpSpec::ed25519());
        let kb = fx.pgp(&label_b, PgpSpec::ed25519());

        prop_assert_ne!(
            ka.fingerprint(),
            kb.fingerprint(),
            "Different labels should produce different fingerprints"
        );
    }

    /// Determinism holds across cache clears.
    #[test]
    fn determinism_across_cache_clear(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let k1 = fx.pgp("prop-det-clear", PgpSpec::ed25519());
        let fp1 = k1.fingerprint().to_string();
        let armor1 = k1.private_key_armored().to_string();

        fx.clear_cache();

        let k2 = fx.pgp("prop-det-clear", PgpSpec::ed25519());
        prop_assert_eq!(fp1, k2.fingerprint());
        prop_assert_eq!(armor1, k2.private_key_armored());
    }

    /// Public key armored output has correct PGP header.
    #[test]
    fn public_key_has_correct_header(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let key = fx.pgp("prop-pub-hdr", PgpSpec::ed25519());

        prop_assert!(
            key.public_key_armored().contains("BEGIN PGP PUBLIC KEY BLOCK"),
            "Public key should have correct PGP header"
        );
        prop_assert!(!key.public_key_binary().is_empty());
    }

    /// User ID contains the label.
    #[test]
    fn user_id_contains_label(
        seed in any::<[u8; 32]>(),
        label in "[a-zA-Z][a-zA-Z0-9]{1,12}",
    ) {
        let fx = Factory::deterministic(Seed::new(seed));
        let key = fx.pgp(&label, PgpSpec::ed25519());

        prop_assert!(
            key.user_id().contains(&label),
            "user_id '{}' should contain label '{}'",
            key.user_id(),
            label
        );
    }

    /// Mismatched public key is always different from the real public key.
    #[test]
    fn mismatched_key_always_differs(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let key = fx.pgp("prop-mismatch", PgpSpec::ed25519());

        let mismatch = key.mismatched_public_key_armored();
        prop_assert_ne!(
            mismatch.as_str(),
            key.public_key_armored(),
            "Mismatched key should differ from the real key"
        );
    }
}
