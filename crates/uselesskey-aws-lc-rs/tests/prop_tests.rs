//! Property-based tests for uselesskey-aws-lc-rs adapter.
//!
//! Covers:
//! - Roundtrip: generate key → convert to aws-lc-rs type → sign → verify
//! - Determinism: same seed produces same adapter keys
//! - Distinctness: different seeds produce different keys
//! - All algorithm specs produce valid keys

use proptest::prelude::*;
use uselesskey_core::{Factory, Seed};

// =========================================================================
// RSA property-based tests
// =========================================================================

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "rsa"))]
mod rsa_props {
    use super::*;
    use aws_lc_rs::signature::{self, KeyPair};
    use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    proptest! {
        // RSA keygen is very expensive; keep case count minimal.
        #![proptest_config(ProptestConfig { cases: 5, ..ProptestConfig::default() })]

        /// Arbitrary labels never panic during key generation + aws-lc-rs conversion.
        #[test]
        fn random_label_does_not_panic(label in "[a-z][a-z0-9-]{0,30}") {
            let fx = Factory::random();
            let kp = fx.rsa(&label, RsaSpec::rs256());
            let _aws_kp = kp.rsa_key_pair_aws_lc_rs();
        }

        /// Deterministic factories with the same seed produce identical aws-lc-rs keys.
        #[test]
        fn deterministic_rsa_from_seed(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.rsa("prop-det-rsa", RsaSpec::rs256());
            let kp2 = fx2.rsa("prop-det-rsa", RsaSpec::rs256());

            prop_assert_eq!(
                kp1.private_key_pkcs8_der(),
                kp2.private_key_pkcs8_der(),
                "Deterministic RSA keys should be identical"
            );

            let aws1 = kp1.rsa_key_pair_aws_lc_rs();
            let aws2 = kp2.rsa_key_pair_aws_lc_rs();
            prop_assert_eq!(
                aws1.public_key().as_ref(),
                aws2.public_key().as_ref(),
                "aws-lc-rs RSA public keys should match"
            );
        }

        /// Signing with a random message always produces a verifiable signature.
        #[test]
        fn signing_produces_valid_signature(msg in prop::collection::vec(any::<u8>(), 0..1024)) {
            let fx = Factory::random();
            let kp = fx.rsa("prop-rsa-sign", RsaSpec::rs256());
            let aws_kp = kp.rsa_key_pair_aws_lc_rs();

            let rng = aws_lc_rs::rand::SystemRandom::new();
            let mut sig = vec![0u8; aws_kp.public_modulus_len()];
            aws_kp
                .sign(&signature::RSA_PKCS1_SHA256, &rng, &msg, &mut sig)
                .expect("sign should succeed");

            let pk = signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                aws_kp.public_key().as_ref(),
            );
            prop_assert!(
                pk.verify(&msg, &sig).is_ok(),
                "Signature should verify for the same message"
            );
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
    }
}

// =========================================================================
// ECDSA property-based tests
// =========================================================================

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ecdsa"))]
mod ecdsa_props {
    use super::*;
    use aws_lc_rs::signature::{self, KeyPair};
    use uselesskey_aws_lc_rs::AwsLcRsEcdsaKeyPairExt;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

        /// Arbitrary labels never panic during ECDSA key generation + aws-lc-rs conversion.
        #[test]
        fn random_label_does_not_panic(label in "[a-z][a-z0-9-]{0,30}") {
            let fx = Factory::random();
            let kp = fx.ecdsa(&label, EcdsaSpec::es256());
            let _aws_kp = kp.ecdsa_key_pair_aws_lc_rs();
        }

        /// Deterministic factories produce identical ECDSA aws-lc-rs keys.
        #[test]
        fn deterministic_ecdsa_from_seed(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.ecdsa("prop-det-ec", EcdsaSpec::es256());
            let kp2 = fx2.ecdsa("prop-det-ec", EcdsaSpec::es256());

            prop_assert_eq!(
                kp1.private_key_pkcs8_der(),
                kp2.private_key_pkcs8_der(),
                "Deterministic ECDSA keys should be identical"
            );

            let aws1 = kp1.ecdsa_key_pair_aws_lc_rs();
            let aws2 = kp2.ecdsa_key_pair_aws_lc_rs();
            prop_assert_eq!(
                aws1.public_key().as_ref(),
                aws2.public_key().as_ref(),
                "aws-lc-rs ECDSA public keys should match"
            );
        }

        /// ECDSA P-256 signing always produces a verifiable signature.
        #[test]
        fn p256_signing_produces_valid_signature(msg in prop::collection::vec(any::<u8>(), 0..1024)) {
            let fx = Factory::random();
            let kp = fx.ecdsa("prop-ec-sign", EcdsaSpec::es256());
            let aws_kp = kp.ecdsa_key_pair_aws_lc_rs();

            let rng = aws_lc_rs::rand::SystemRandom::new();
            let sig = aws_kp.sign(&rng, &msg).expect("sign should succeed");

            let pk = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P256_SHA256_ASN1,
                aws_kp.public_key().as_ref(),
            );
            prop_assert!(
                pk.verify(&msg, sig.as_ref()).is_ok(),
                "ECDSA P-256 signature should verify"
            );
        }

        /// ECDSA P-384 signing always produces a verifiable signature.
        #[test]
        fn p384_signing_produces_valid_signature(msg in prop::collection::vec(any::<u8>(), 0..512)) {
            let fx = Factory::random();
            let kp = fx.ecdsa("prop-ec384-sign", EcdsaSpec::es384());
            let aws_kp = kp.ecdsa_key_pair_aws_lc_rs();

            let rng = aws_lc_rs::rand::SystemRandom::new();
            let sig = aws_kp.sign(&rng, &msg).expect("sign should succeed");

            let pk = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P384_SHA384_ASN1,
                aws_kp.public_key().as_ref(),
            );
            prop_assert!(
                pk.verify(&msg, sig.as_ref()).is_ok(),
                "ECDSA P-384 signature should verify"
            );
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
    }
}

// =========================================================================
// Ed25519 property-based tests
// =========================================================================

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ed25519"))]
mod ed25519_props {
    use super::*;
    use aws_lc_rs::signature::{self, KeyPair};
    use uselesskey_aws_lc_rs::AwsLcRsEd25519KeyPairExt;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Arbitrary labels never panic during Ed25519 key generation + aws-lc-rs conversion.
        #[test]
        fn random_label_does_not_panic(label in "[a-z][a-z0-9-]{0,30}") {
            let fx = Factory::random();
            let kp = fx.ed25519(&label, Ed25519Spec::new());
            let _aws_kp = kp.ed25519_key_pair_aws_lc_rs();
        }

        /// Deterministic factories produce identical Ed25519 aws-lc-rs keys.
        #[test]
        fn deterministic_ed25519_from_seed(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.ed25519("prop-det-ed", Ed25519Spec::new());
            let kp2 = fx2.ed25519("prop-det-ed", Ed25519Spec::new());

            prop_assert_eq!(
                kp1.private_key_pkcs8_der(),
                kp2.private_key_pkcs8_der(),
                "Deterministic Ed25519 keys should be identical"
            );

            let aws1 = kp1.ed25519_key_pair_aws_lc_rs();
            let aws2 = kp2.ed25519_key_pair_aws_lc_rs();
            prop_assert_eq!(
                aws1.public_key().as_ref(),
                aws2.public_key().as_ref(),
                "aws-lc-rs Ed25519 public keys should match"
            );
        }

        /// Ed25519 signing always produces a verifiable signature.
        #[test]
        fn signing_produces_valid_signature(msg in prop::collection::vec(any::<u8>(), 0..2048)) {
            let fx = Factory::random();
            let kp = fx.ed25519("prop-ed-sign", Ed25519Spec::new());
            let aws_kp = kp.ed25519_key_pair_aws_lc_rs();

            let sig = aws_kp.sign(&msg);

            let pk = signature::UnparsedPublicKey::new(
                &signature::ED25519,
                aws_kp.public_key().as_ref(),
            );
            prop_assert!(
                pk.verify(&msg, sig.as_ref()).is_ok(),
                "Ed25519 signature should verify"
            );
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
    }
}
