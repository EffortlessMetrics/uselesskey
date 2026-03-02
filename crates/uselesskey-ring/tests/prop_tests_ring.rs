//! Property-based tests for uselesskey-ring adapter.
//!
//! Covers:
//! - Random label generation doesn't panic
//! - Key generation is deterministic from seed
//! - Signing produces valid signatures

use proptest::prelude::*;
use uselesskey_core::{Factory, Seed};

// =========================================================================
// RSA property-based tests
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_props {
    use super::*;
    use ring::{rand::SystemRandom, signature};
    use uselesskey_ring::RingRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    proptest! {
        // RSA keygen is very expensive; keep case count minimal.
        #![proptest_config(ProptestConfig { cases: 5, ..ProptestConfig::default() })]

        /// Arbitrary labels never panic during key generation + ring conversion.
        #[test]
        fn random_label_does_not_panic(label in "[a-z][a-z0-9-]{0,30}") {
            let fx = Factory::random();
            let kp = fx.rsa(&label, RsaSpec::rs256());
            let _ring_kp = kp.rsa_key_pair_ring();
        }

        /// Deterministic factories with the same seed produce identical ring keys.
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

            let ring1 = kp1.rsa_key_pair_ring();
            let ring2 = kp2.rsa_key_pair_ring();
            prop_assert_eq!(
                ring1.public().as_ref(),
                ring2.public().as_ref(),
                "Ring public keys should match"
            );
        }

        /// Signing with a random message always produces a verifiable signature.
        #[test]
        fn signing_produces_valid_signature(msg in prop::collection::vec(any::<u8>(), 0..1024)) {
            let fx = Factory::random();
            let kp = fx.rsa("prop-rsa-sign", RsaSpec::rs256());
            let ring_kp = kp.rsa_key_pair_ring();

            let rng = SystemRandom::new();
            let mut sig = vec![0u8; ring_kp.public().modulus_len()];
            ring_kp
                .sign(&signature::RSA_PKCS1_SHA256, &rng, &msg, &mut sig)
                .expect("sign should succeed");

            let pk = signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                ring_kp.public().as_ref(),
            );
            prop_assert!(
                pk.verify(&msg, &sig).is_ok(),
                "Signature should verify for the same message"
            );
        }
    }
}

// =========================================================================
// ECDSA property-based tests
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_props {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{self, KeyPair},
    };
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ring::RingEcdsaKeyPairExt;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

        /// Arbitrary labels never panic during ECDSA key generation + ring conversion.
        #[test]
        fn random_label_does_not_panic(label in "[a-z][a-z0-9-]{0,30}") {
            let fx = Factory::random();
            let kp = fx.ecdsa(&label, EcdsaSpec::es256());
            let _ring_kp = kp.ecdsa_key_pair_ring();
        }

        /// Deterministic factories produce identical ECDSA ring keys.
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

            let ring1 = kp1.ecdsa_key_pair_ring();
            let ring2 = kp2.ecdsa_key_pair_ring();
            prop_assert_eq!(
                ring1.public_key().as_ref(),
                ring2.public_key().as_ref(),
                "Ring ECDSA public keys should match"
            );
        }

        /// ECDSA P-256 signing always produces a verifiable signature.
        #[test]
        fn p256_signing_produces_valid_signature(msg in prop::collection::vec(any::<u8>(), 0..1024)) {
            let fx = Factory::random();
            let kp = fx.ecdsa("prop-ec-sign", EcdsaSpec::es256());
            let ring_kp = kp.ecdsa_key_pair_ring();

            let rng = SystemRandom::new();
            let sig = ring_kp.sign(&rng, &msg).expect("sign should succeed");

            let pk = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P256_SHA256_ASN1,
                ring_kp.public_key().as_ref(),
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
            let ring_kp = kp.ecdsa_key_pair_ring();

            let rng = SystemRandom::new();
            let sig = ring_kp.sign(&rng, &msg).expect("sign should succeed");

            let pk = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P384_SHA384_ASN1,
                ring_kp.public_key().as_ref(),
            );
            prop_assert!(
                pk.verify(&msg, sig.as_ref()).is_ok(),
                "ECDSA P-384 signature should verify"
            );
        }
    }
}

// =========================================================================
// Ed25519 property-based tests
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_props {
    use super::*;
    use ring::signature::{self, KeyPair};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_ring::RingEd25519KeyPairExt;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Arbitrary labels never panic during Ed25519 key generation + ring conversion.
        #[test]
        fn random_label_does_not_panic(label in "[a-z][a-z0-9-]{0,30}") {
            let fx = Factory::random();
            let kp = fx.ed25519(&label, Ed25519Spec::new());
            let _ring_kp = kp.ed25519_key_pair_ring();
        }

        /// Deterministic factories produce identical Ed25519 ring keys.
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

            let ring1 = kp1.ed25519_key_pair_ring();
            let ring2 = kp2.ed25519_key_pair_ring();
            prop_assert_eq!(
                ring1.public_key().as_ref(),
                ring2.public_key().as_ref(),
                "Ring Ed25519 public keys should match"
            );
        }

        /// Ed25519 signing always produces a verifiable signature.
        #[test]
        fn signing_produces_valid_signature(msg in prop::collection::vec(any::<u8>(), 0..2048)) {
            let fx = Factory::random();
            let kp = fx.ed25519("prop-ed-sign", Ed25519Spec::new());
            let ring_kp = kp.ed25519_key_pair_ring();

            let sig = ring_kp.sign(&msg);

            let pk = signature::UnparsedPublicKey::new(
                &signature::ED25519,
                ring_kp.public_key().as_ref(),
            );
            prop_assert!(
                pk.verify(&msg, sig.as_ref()).is_ok(),
                "Ed25519 signature should verify"
            );
        }

        /// Ed25519 signatures are deterministic for the same key and message.
        #[test]
        fn ed25519_signatures_are_deterministic(
            seed in any::<[u8; 32]>(),
            msg in prop::collection::vec(any::<u8>(), 0..512),
        ) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ed25519("prop-ed-det-sig", Ed25519Spec::new());
            let ring_kp = kp.ed25519_key_pair_ring();

            let sig1 = ring_kp.sign(&msg);
            let sig2 = ring_kp.sign(&msg);

            prop_assert_eq!(
                sig1.as_ref(),
                sig2.as_ref(),
                "Ed25519 signatures should be deterministic"
            );
        }
    }
}
