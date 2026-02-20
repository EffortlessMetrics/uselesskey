#[allow(dead_code)]
mod testutil;

use proptest::prelude::*;

use uselesskey_core::{Factory, Seed};
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

    // =========================================================================
    // Deterministic stability
    // =========================================================================

    /// Same seed + label + ES256 spec produces identical DER output.
    #[test]
    fn deterministic_es256_key_is_stable(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let k1 = fx.ecdsa("prop-key", EcdsaSpec::es256());
        let k2 = fx.ecdsa("prop-key", EcdsaSpec::es256());

        prop_assert_eq!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
        prop_assert_eq!(k1.public_key_spki_der(), k2.public_key_spki_der());
    }

    /// Same seed + label + ES384 spec produces identical DER output.
    #[test]
    fn deterministic_es384_key_is_stable(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let k1 = fx.ecdsa("prop-key", EcdsaSpec::es384());
        let k2 = fx.ecdsa("prop-key", EcdsaSpec::es384());

        prop_assert_eq!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
        prop_assert_eq!(k1.public_key_spki_der(), k2.public_key_spki_der());
    }

    // =========================================================================
    // Parseability — ES256
    // =========================================================================

    /// ES256 keys produce parseable PKCS#8 DER/PEM and SPKI DER/PEM.
    #[test]
    fn es256_keys_are_parseable(seed in any::<[u8; 32]>()) {
        use p256::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};

        let fx = Factory::deterministic(Seed::new(seed));
        let key = fx.ecdsa("prop-parse", EcdsaSpec::es256());

        let priv_der = p256::SecretKey::from_pkcs8_der(key.private_key_pkcs8_der());
        prop_assert!(priv_der.is_ok(), "ES256 private key DER should be parseable");

        let priv_pem = p256::SecretKey::from_pkcs8_pem(key.private_key_pkcs8_pem());
        prop_assert!(priv_pem.is_ok(), "ES256 private key PEM should be parseable");

        let pub_der = p256::PublicKey::from_public_key_der(key.public_key_spki_der());
        prop_assert!(pub_der.is_ok(), "ES256 public key DER should be parseable");

        let pub_pem = p256::PublicKey::from_public_key_pem(key.public_key_spki_pem());
        prop_assert!(pub_pem.is_ok(), "ES256 public key PEM should be parseable");
    }

    // =========================================================================
    // Parseability — ES384
    // =========================================================================

    /// ES384 keys produce parseable PKCS#8 DER/PEM and SPKI DER/PEM.
    #[test]
    fn es384_keys_are_parseable(seed in any::<[u8; 32]>()) {
        use p384::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};

        let fx = Factory::deterministic(Seed::new(seed));
        let key = fx.ecdsa("prop-parse", EcdsaSpec::es384());

        let priv_der = p384::SecretKey::from_pkcs8_der(key.private_key_pkcs8_der());
        prop_assert!(priv_der.is_ok(), "ES384 private key DER should be parseable");

        let priv_pem = p384::SecretKey::from_pkcs8_pem(key.private_key_pkcs8_pem());
        prop_assert!(priv_pem.is_ok(), "ES384 private key PEM should be parseable");

        let pub_der = p384::PublicKey::from_public_key_der(key.public_key_spki_der());
        prop_assert!(pub_der.is_ok(), "ES384 public key DER should be parseable");

        let pub_pem = p384::PublicKey::from_public_key_pem(key.public_key_spki_pem());
        prop_assert!(pub_pem.is_ok(), "ES384 public key PEM should be parseable");
    }

    // =========================================================================
    // kid determinism (feature-gated)
    // =========================================================================

    /// kid is deterministic: same key produces same kid.
    #[test]
    #[cfg(feature = "jwk")]
    fn kid_is_deterministic(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let k1 = fx.ecdsa("prop-kid", EcdsaSpec::es256());
        let k2 = fx.ecdsa("prop-kid", EcdsaSpec::es256());

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
        let k1 = fx.ecdsa(&label1, EcdsaSpec::es256());
        let k2 = fx.ecdsa(&label2, EcdsaSpec::es256());

        prop_assert_ne!(
            k1.kid(), k2.kid(),
            "Different labels should produce different kids"
        );
    }
}
