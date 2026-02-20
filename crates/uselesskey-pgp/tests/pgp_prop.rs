#[allow(dead_code)]
mod testutil;

use std::io::Cursor;

use pgp::composed::{Deserializable, SignedSecretKey};
use proptest::prelude::*;

use uselesskey_core::{Factory, Seed};
use uselesskey_pgp::{PgpFactoryExt, PgpSpec};

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

    // =========================================================================
    // Armor parseable
    // =========================================================================

    /// Ed25519 armored private key output is parseable by the pgp crate.
    #[test]
    fn armor_parseable(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let key = fx.pgp("prop-armor", PgpSpec::ed25519());

        let armor = key.private_key_armored();
        let result = SignedSecretKey::from_armor_single(Cursor::new(armor));
        prop_assert!(
            result.is_ok(),
            "Armored private key should be parseable, error: {:?}",
            result.err()
        );
    }

    // =========================================================================
    // Binary parseable
    // =========================================================================

    /// Ed25519 binary private key output is parseable by the pgp crate.
    #[test]
    fn binary_parseable(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let key = fx.pgp("prop-binary", PgpSpec::ed25519());

        let binary = key.private_key_binary();
        let result = SignedSecretKey::from_bytes(Cursor::new(binary));
        prop_assert!(
            result.is_ok(),
            "Binary private key should be parseable, error: {:?}",
            result.err()
        );
    }

    // =========================================================================
    // Fingerprint stability
    // =========================================================================

    /// Same seed + label produces the same fingerprint (within same process, using cache).
    #[test]
    fn fingerprint_stability(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let key1 = fx.pgp("prop-fp", PgpSpec::ed25519());
        let key2 = fx.pgp("prop-fp", PgpSpec::ed25519());

        prop_assert_eq!(
            key1.fingerprint(),
            key2.fingerprint(),
            "Same seed+label should produce same fingerprint"
        );
    }

    // =========================================================================
    // Fingerprint non-empty
    // =========================================================================

    /// Fingerprint is never an empty string.
    #[test]
    fn fingerprint_non_empty(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let key = fx.pgp("prop-fp-ne", PgpSpec::ed25519());

        prop_assert!(
            !key.fingerprint().is_empty(),
            "Fingerprint should not be empty"
        );
    }
}
