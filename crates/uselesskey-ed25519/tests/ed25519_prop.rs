#[allow(dead_code)]
mod testutil;

use proptest::prelude::*;

use uselesskey_core::{Factory, Seed};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    // =========================================================================
    // Deterministic stability
    // =========================================================================

    /// Same seed + label produces identical DER output.
    #[test]
    fn deterministic_ed25519_key_is_stable(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let k1 = fx.ed25519("prop-key", Ed25519Spec::new());
        let k2 = fx.ed25519("prop-key", Ed25519Spec::new());

        prop_assert_eq!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
        prop_assert_eq!(k1.public_key_spki_der(), k2.public_key_spki_der());
    }

    // =========================================================================
    // Parseability
    // =========================================================================

    /// Ed25519 keys produce parseable PKCS#8 DER/PEM and SPKI DER/PEM.
    #[test]
    fn ed25519_keys_are_parseable(seed in any::<[u8; 32]>()) {
        use ed25519_dalek::pkcs8::DecodePrivateKey as _;
        use ed25519_dalek::pkcs8::DecodePublicKey as _;
        use ed25519_dalek::{SigningKey, VerifyingKey};

        let fx = Factory::deterministic(Seed::new(seed));
        let key = fx.ed25519("prop-parse", Ed25519Spec::new());

        let priv_der = SigningKey::from_pkcs8_der(key.private_key_pkcs8_der());
        prop_assert!(priv_der.is_ok(), "Ed25519 private key DER should be parseable");

        let priv_pem = SigningKey::from_pkcs8_pem(key.private_key_pkcs8_pem());
        prop_assert!(priv_pem.is_ok(), "Ed25519 private key PEM should be parseable");

        let pub_der = VerifyingKey::from_public_key_der(key.public_key_spki_der());
        prop_assert!(pub_der.is_ok(), "Ed25519 public key DER should be parseable");

        let pub_pem = VerifyingKey::from_public_key_pem(key.public_key_spki_pem());
        prop_assert!(pub_pem.is_ok(), "Ed25519 public key PEM should be parseable");
    }

    // =========================================================================
    // kid determinism (feature-gated)
    // =========================================================================

    /// kid is deterministic: same key produces same kid.
    #[test]
    #[cfg(feature = "jwk")]
    fn kid_is_deterministic(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let k1 = fx.ed25519("prop-kid", Ed25519Spec::new());
        let k2 = fx.ed25519("prop-kid", Ed25519Spec::new());

        prop_assert_eq!(k1.kid(), k2.kid(), "Same key should produce same kid");
    }

    /// Different labels produce different kids.
    #[test]
    #[cfg(feature = "jwk")]
    fn different_labels_produce_different_kids(
        seed in any::<[u8; 32]>(),
        label1 in "[a-zA-Z0-9]{1,16}",
        label2 in "[a-zA-Z0-9]{1,16}",
    ) {
        prop_assume!(label1 != label2);

        let fx = Factory::deterministic(Seed::new(seed));
        let k1 = fx.ed25519(&label1, Ed25519Spec::new());
        let k2 = fx.ed25519(&label2, Ed25519Spec::new());

        prop_assert_ne!(
            k1.kid(), k2.kid(),
            "Different labels should produce different kids"
        );
    }
}
