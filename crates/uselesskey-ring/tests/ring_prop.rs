#[allow(dead_code)]
mod testutil;

use proptest::prelude::*;

use uselesskey_core::{Factory, Seed};

// =========================================================================
// ECDSA
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_prop {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{self, KeyPair, UnparsedPublicKey},
    };
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ring::RingEcdsaKeyPairExt;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Sign/verify roundtrip for P-256 via ring.
        #[test]
        fn p256_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ecdsa("prop-ring", EcdsaSpec::es256());
            let ring_kp = kp.ecdsa_key_pair_ring();

            let msg = b"proptest roundtrip message";
            let rng = SystemRandom::new();
            let sig = ring_kp.sign(&rng, msg).expect("sign should succeed");

            let pub_key = UnparsedPublicKey::new(
                &signature::ECDSA_P256_SHA256_ASN1,
                ring_kp.public_key().as_ref(),
            );
            prop_assert!(pub_key.verify(msg, sig.as_ref()).is_ok(), "verify should succeed");
        }

        /// Sign/verify roundtrip for P-384 via ring.
        #[test]
        fn p384_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ecdsa("prop-ring", EcdsaSpec::es384());
            let ring_kp = kp.ecdsa_key_pair_ring();

            let msg = b"proptest roundtrip message";
            let rng = SystemRandom::new();
            let sig = ring_kp.sign(&rng, msg).expect("sign should succeed");

            let pub_key = UnparsedPublicKey::new(
                &signature::ECDSA_P384_SHA384_ASN1,
                ring_kp.public_key().as_ref(),
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
            let k1 = fx1.ecdsa("prop-ring", EcdsaSpec::es256());
            let k2 = fx2.ecdsa("prop-ring", EcdsaSpec::es256());

            prop_assert_ne!(
                k1.private_key_pkcs8_der(),
                k2.private_key_pkcs8_der(),
                "different seeds should produce different keys"
            );
        }

        /// Cross-key verification fails.
        #[test]
        fn cross_key_verification_fails(
            seed in any::<[u8; 32]>(),
            label1 in "[a-zA-Z0-9]{1,16}",
            label2 in "[a-zA-Z0-9]{1,16}",
        ) {
            prop_assume!(label1 != label2);

            let fx = Factory::deterministic(Seed::new(seed));
            let key_a = fx.ecdsa(&label1, EcdsaSpec::es256());
            let key_b = fx.ecdsa(&label2, EcdsaSpec::es256());

            let ring_a = key_a.ecdsa_key_pair_ring();
            let ring_b = key_b.ecdsa_key_pair_ring();

            let msg = b"cross-key test";
            let rng = SystemRandom::new();
            let sig = ring_a.sign(&rng, msg).unwrap();

            let pub_key_b = UnparsedPublicKey::new(
                &signature::ECDSA_P256_SHA256_ASN1,
                ring_b.public_key().as_ref(),
            );
            prop_assert!(
                pub_key_b.verify(msg, sig.as_ref()).is_err(),
                "verification with wrong key should fail"
            );
        }
    }
}

// =========================================================================
// Ed25519
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_prop {
    use super::*;
    use ring::signature::{self, KeyPair, UnparsedPublicKey};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_ring::RingEd25519KeyPairExt;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

        /// Sign/verify roundtrip for Ed25519 via ring.
        #[test]
        fn ed25519_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ed25519("prop-ring", Ed25519Spec::new());
            let ring_kp = kp.ed25519_key_pair_ring();

            let msg = b"proptest ed25519 message";
            let sig = ring_kp.sign(msg);

            let pub_key = UnparsedPublicKey::new(
                &signature::ED25519,
                ring_kp.public_key().as_ref(),
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
            let k1 = fx1.ed25519("prop-ring", Ed25519Spec::new());
            let k2 = fx2.ed25519("prop-ring", Ed25519Spec::new());

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

#[cfg(feature = "rsa")]
mod rsa_prop {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{self, UnparsedPublicKey},
    };
    use uselesskey_ring::RingRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 4, ..ProptestConfig::default() })]

        /// Sign/verify roundtrip for RSA 2048-bit via ring.
        #[test]
        fn rsa_sign_verify_roundtrip(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.rsa("prop-ring", RsaSpec::rs256());
            let ring_kp = kp.rsa_key_pair_ring();

            let msg = b"proptest rsa message";
            let rng = SystemRandom::new();
            let mut sig = vec![0u8; ring_kp.public().modulus_len()];
            ring_kp
                .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
                .expect("sign should succeed");

            let pub_key = UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                ring_kp.public().as_ref(),
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
            let k1 = fx1.rsa("prop-ring", RsaSpec::rs256());
            let k2 = fx2.rsa("prop-ring", RsaSpec::rs256());

            prop_assert_ne!(
                k1.private_key_pkcs8_der(),
                k2.private_key_pkcs8_der(),
                "different seeds should produce different keys"
            );
        }
    }
}
