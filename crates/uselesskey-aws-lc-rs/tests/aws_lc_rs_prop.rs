#[allow(dead_code)]
mod testutil;

use proptest::prelude::*;

use uselesskey_core::{Factory, Seed};

// =========================================================================
// ECDSA
// =========================================================================

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ecdsa"))]
mod ecdsa_prop {
    use super::*;
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{self, KeyPair, UnparsedPublicKey},
    };
    use uselesskey_aws_lc_rs::AwsLcRsEcdsaKeyPairExt;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Sign/verify roundtrip for P-256 via aws-lc-rs.
        #[test]
        fn p256_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ecdsa("prop-aws", EcdsaSpec::es256());
            let aws_kp = kp.ecdsa_key_pair_aws_lc_rs();

            let msg = b"proptest roundtrip message";
            let rng = SystemRandom::new();
            let sig = aws_kp.sign(&rng, msg).expect("sign should succeed");

            let pub_key = UnparsedPublicKey::new(
                &signature::ECDSA_P256_SHA256_ASN1,
                aws_kp.public_key().as_ref(),
            );
            prop_assert!(pub_key.verify(msg, sig.as_ref()).is_ok(), "verify should succeed");
        }

        /// Sign/verify roundtrip for P-384 via aws-lc-rs.
        #[test]
        fn p384_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ecdsa("prop-aws", EcdsaSpec::es384());
            let aws_kp = kp.ecdsa_key_pair_aws_lc_rs();

            let msg = b"proptest roundtrip message";
            let rng = SystemRandom::new();
            let sig = aws_kp.sign(&rng, msg).expect("sign should succeed");

            let pub_key = UnparsedPublicKey::new(
                &signature::ECDSA_P384_SHA384_ASN1,
                aws_kp.public_key().as_ref(),
            );
            prop_assert!(pub_key.verify(msg, sig.as_ref()).is_ok(), "verify should succeed");
        }

        /// Different seeds produce different ECDSA keys.
        #[test]
        fn different_seeds_produce_different_ecdsa_keys(
            seed1 in any::<[u8; 32]>(),
            seed2 in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed1 != seed2);

            let fx1 = Factory::deterministic(Seed::new(seed1));
            let fx2 = Factory::deterministic(Seed::new(seed2));
            let k1 = fx1.ecdsa("prop-aws", EcdsaSpec::es256());
            let k2 = fx2.ecdsa("prop-aws", EcdsaSpec::es256());

            prop_assert_ne!(
                k1.private_key_pkcs8_der(),
                k2.private_key_pkcs8_der(),
                "different seeds should produce different keys"
            );
        }
    }
}

// =========================================================================
// Ed25519
// =========================================================================

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ed25519"))]
mod ed25519_prop {
    use super::*;
    use aws_lc_rs::signature::{self, KeyPair, UnparsedPublicKey};
    use uselesskey_aws_lc_rs::AwsLcRsEd25519KeyPairExt;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

        /// Sign/verify roundtrip for Ed25519 via aws-lc-rs.
        #[test]
        fn ed25519_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ed25519("prop-aws", Ed25519Spec::new());
            let aws_kp = kp.ed25519_key_pair_aws_lc_rs();

            let msg = b"proptest ed25519 message";
            let sig = aws_kp.sign(msg);

            let pub_key = UnparsedPublicKey::new(
                &signature::ED25519,
                aws_kp.public_key().as_ref(),
            );
            prop_assert!(pub_key.verify(msg, sig.as_ref()).is_ok(), "verify should succeed");
        }

        /// Different seeds produce different Ed25519 keys.
        #[test]
        fn different_seeds_produce_different_ed25519_keys(
            seed1 in any::<[u8; 32]>(),
            seed2 in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed1 != seed2);

            let fx1 = Factory::deterministic(Seed::new(seed1));
            let fx2 = Factory::deterministic(Seed::new(seed2));
            let k1 = fx1.ed25519("prop-aws", Ed25519Spec::new());
            let k2 = fx2.ed25519("prop-aws", Ed25519Spec::new());

            prop_assert_ne!(
                k1.private_key_pkcs8_der(),
                k2.private_key_pkcs8_der(),
                "different seeds should produce different keys"
            );
        }
    }
}

// =========================================================================
// RSA (slow — keep case count low)
// =========================================================================

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "rsa"))]
mod rsa_prop {
    use super::*;
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{self, KeyPair, UnparsedPublicKey},
    };
    use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 4, ..ProptestConfig::default() })]

        /// Sign/verify roundtrip for RSA 2048-bit via aws-lc-rs.
        #[test]
        fn rsa_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.rsa("prop-aws", RsaSpec::rs256());
            let aws_kp = kp.rsa_key_pair_aws_lc_rs();

            let msg = b"proptest rsa message";
            let rng = SystemRandom::new();
            let mut sig = vec![0u8; aws_kp.public_modulus_len()];
            aws_kp
                .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
                .expect("sign should succeed");

            let pub_key = aws_kp.public_key();
            let pub_key = UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                pub_key.as_ref(),
            );
            prop_assert!(pub_key.verify(msg, &sig).is_ok(), "verify should succeed");
        }

        /// Different seeds produce different RSA keys.
        #[test]
        fn different_seeds_produce_different_rsa_keys(
            seed1 in any::<[u8; 32]>(),
            seed2 in any::<[u8; 32]>(),
        ) {
            prop_assume!(seed1 != seed2);

            let fx1 = Factory::deterministic(Seed::new(seed1));
            let fx2 = Factory::deterministic(Seed::new(seed2));
            let k1 = fx1.rsa("prop-aws", RsaSpec::rs256());
            let k2 = fx2.rsa("prop-aws", RsaSpec::rs256());

            prop_assert_ne!(
                k1.private_key_pkcs8_der(),
                k2.private_key_pkcs8_der(),
                "different seeds should produce different keys"
            );
        }
    }
}
