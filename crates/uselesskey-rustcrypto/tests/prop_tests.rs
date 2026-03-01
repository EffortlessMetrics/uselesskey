mod testutil;

use proptest::prelude::*;
use uselesskey_core::{Factory, Seed};

// RSA property tests require expensive keygen — limit cases.
#[cfg(feature = "rsa")]
mod rsa_prop {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

        /// Deterministic factories with the same seed produce identical RustCrypto RSA keys.
        #[test]
        fn deterministic_rsa_is_consistent(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp1 = fx.rsa("prop-rsa", RsaSpec::rs256());
            let kp2 = fx.rsa("prop-rsa", RsaSpec::rs256());

            prop_assert_eq!(
                kp1.private_key_pkcs8_der(),
                kp2.private_key_pkcs8_der(),
                "Same seed should produce identical RSA keys"
            );

            // Verify the adapter conversion does not panic.
            use uselesskey_rustcrypto::RustCryptoRsaExt;
            let _ = kp1.rsa_private_key();
            let _ = kp2.rsa_public_key();
        }

        /// Different seeds produce different RSA keys.
        #[test]
        fn different_seeds_different_rsa(
            seed_a in any::<[u8; 32]>(),
            seed_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed_a != seed_b);

            let fx_a = Factory::deterministic(Seed::new(seed_a));
            let fx_b = Factory::deterministic(Seed::new(seed_b));

            let kp_a = fx_a.rsa("prop-rsa", RsaSpec::rs256());
            let kp_b = fx_b.rsa("prop-rsa", RsaSpec::rs256());

            prop_assert_ne!(
                kp_a.private_key_pkcs8_der(),
                kp_b.private_key_pkcs8_der(),
                "Different seeds should produce different RSA keys"
            );
        }

        /// RSA PEM starts with expected header, DER is non-empty.
        #[test]
        fn rsa_output_format_invariants(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.rsa("prop-fmt", RsaSpec::rs256());

            prop_assert!(
                kp.private_key_pkcs8_pem().starts_with("-----BEGIN PRIVATE KEY-----"),
                "Private PEM should start with BEGIN PRIVATE KEY"
            );
            prop_assert!(
                kp.public_key_spki_pem().starts_with("-----BEGIN PUBLIC KEY-----"),
                "Public PEM should start with BEGIN PUBLIC KEY"
            );
            prop_assert!(
                !kp.private_key_pkcs8_der().is_empty(),
                "Private DER should be non-empty"
            );
            prop_assert!(
                !kp.public_key_spki_der().is_empty(),
                "Public DER should be non-empty"
            );
        }
    }
}

#[cfg(feature = "ecdsa")]
mod ecdsa_prop {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Deterministic P-256 keys are consistent across calls with the same seed.
        #[test]
        fn deterministic_p256_is_consistent(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp1 = fx.ecdsa("prop-p256", EcdsaSpec::es256());
            let kp2 = fx.ecdsa("prop-p256", EcdsaSpec::es256());

            prop_assert_eq!(
                kp1.private_key_pkcs8_der(),
                kp2.private_key_pkcs8_der(),
                "Same seed should produce identical P-256 keys"
            );

            // Verify the adapter conversion does not panic.
            use uselesskey_rustcrypto::RustCryptoEcdsaExt;
            let _ = kp1.p256_signing_key();
            let _ = kp2.p256_verifying_key();
        }

        /// Deterministic P-384 keys are consistent across calls with the same seed.
        #[test]
        fn deterministic_p384_is_consistent(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp1 = fx.ecdsa("prop-p384", EcdsaSpec::es384());
            let kp2 = fx.ecdsa("prop-p384", EcdsaSpec::es384());

            prop_assert_eq!(
                kp1.private_key_pkcs8_der(),
                kp2.private_key_pkcs8_der(),
                "Same seed should produce identical P-384 keys"
            );

            // Verify the adapter conversion does not panic.
            use uselesskey_rustcrypto::RustCryptoEcdsaExt;
            let _ = kp1.p384_signing_key();
            let _ = kp2.p384_verifying_key();
        }

        /// Different seeds produce different ECDSA keys.
        #[test]
        fn different_seeds_different_ecdsa(
            seed_a in any::<[u8; 32]>(),
            seed_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed_a != seed_b);

            let fx_a = Factory::deterministic(Seed::new(seed_a));
            let fx_b = Factory::deterministic(Seed::new(seed_b));

            let kp_a = fx_a.ecdsa("prop-ec", EcdsaSpec::es256());
            let kp_b = fx_b.ecdsa("prop-ec", EcdsaSpec::es256());

            prop_assert_ne!(
                kp_a.private_key_pkcs8_der(),
                kp_b.private_key_pkcs8_der(),
                "Different seeds should produce different ECDSA keys"
            );
        }

        /// ECDSA PEM starts with expected header, DER is non-empty.
        #[test]
        fn ecdsa_output_format_invariants(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ecdsa("prop-fmt", EcdsaSpec::es256());

            prop_assert!(
                kp.private_key_pkcs8_pem().starts_with("-----BEGIN PRIVATE KEY-----"),
                "Private PEM should start with BEGIN PRIVATE KEY"
            );
            prop_assert!(
                !kp.private_key_pkcs8_der().is_empty(),
                "Private DER should be non-empty"
            );
        }
    }
}

#[cfg(feature = "ed25519")]
mod ed25519_prop {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Deterministic Ed25519 keys are consistent across calls.
        #[test]
        fn deterministic_ed25519_is_consistent(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp1 = fx.ed25519("prop-ed", Ed25519Spec::new());
            let kp2 = fx.ed25519("prop-ed", Ed25519Spec::new());

            prop_assert_eq!(
                kp1.private_key_pkcs8_der(),
                kp2.private_key_pkcs8_der(),
                "Same seed should produce identical Ed25519 keys"
            );

            // Verify the adapter conversion does not panic.
            use uselesskey_rustcrypto::RustCryptoEd25519Ext;
            let _ = kp1.ed25519_signing_key();
            let _ = kp2.ed25519_verifying_key();
        }

        /// Different seeds produce different Ed25519 keys.
        #[test]
        fn different_seeds_different_ed25519(
            seed_a in any::<[u8; 32]>(),
            seed_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed_a != seed_b);

            let fx_a = Factory::deterministic(Seed::new(seed_a));
            let fx_b = Factory::deterministic(Seed::new(seed_b));

            let kp_a = fx_a.ed25519("prop-ed", Ed25519Spec::new());
            let kp_b = fx_b.ed25519("prop-ed", Ed25519Spec::new());

            prop_assert_ne!(
                kp_a.private_key_pkcs8_der(),
                kp_b.private_key_pkcs8_der(),
                "Different seeds should produce different Ed25519 keys"
            );
        }

        /// Ed25519 PEM starts with expected header, DER is non-empty.
        #[test]
        fn ed25519_output_format_invariants(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ed25519("prop-fmt", Ed25519Spec::new());

            prop_assert!(
                kp.private_key_pkcs8_pem().starts_with("-----BEGIN PRIVATE KEY-----"),
                "Private PEM should start with BEGIN PRIVATE KEY"
            );
            prop_assert!(
                !kp.private_key_pkcs8_der().is_empty(),
                "Private DER should be non-empty"
            );
        }
    }
}

#[cfg(feature = "hmac")]
mod hmac_prop {
    use super::*;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Deterministic HMAC secrets are consistent across calls.
        #[test]
        fn deterministic_hmac_is_consistent(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let s1 = fx.hmac("prop-hmac", HmacSpec::hs256());
            let s2 = fx.hmac("prop-hmac", HmacSpec::hs256());

            prop_assert_eq!(
                s1.secret_bytes(),
                s2.secret_bytes(),
                "Same seed should produce identical HMAC secrets"
            );

            // Verify the adapter conversion does not panic.
            use uselesskey_rustcrypto::RustCryptoHmacExt;
            let _ = s1.hmac_sha256();
            let _ = s2.hmac_sha384();
        }

        /// Different seeds produce different HMAC secrets.
        #[test]
        fn different_seeds_different_hmac(
            seed_a in any::<[u8; 32]>(),
            seed_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed_a != seed_b);

            let fx_a = Factory::deterministic(Seed::new(seed_a));
            let fx_b = Factory::deterministic(Seed::new(seed_b));

            let s_a = fx_a.hmac("prop-hmac", HmacSpec::hs256());
            let s_b = fx_b.hmac("prop-hmac", HmacSpec::hs256());

            prop_assert_ne!(
                s_a.secret_bytes(),
                s_b.secret_bytes(),
                "Different seeds should produce different HMAC secrets"
            );
        }

        /// HMAC secret bytes are non-empty.
        #[test]
        fn hmac_output_format_invariants(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));

            for spec in [HmacSpec::hs256(), HmacSpec::hs384(), HmacSpec::hs512()] {
                let secret = fx.hmac("prop-fmt", spec);
                prop_assert!(
                    !secret.secret_bytes().is_empty(),
                    "HMAC secret bytes should be non-empty"
                );
            }
        }
    }
}
