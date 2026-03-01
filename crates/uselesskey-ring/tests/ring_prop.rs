//! Property tests for the uselesskey-ring adapter.
//!
//! Covers:
//! - Determinism across independent factory instantiations
//! - Debug safety (no key material leakage)
//! - Label divergence (different labels → different ring keys)
//! - Algorithm coverage (RSA, ECDSA P-256/P-384, Ed25519)

mod testutil;

use proptest::prelude::*;
use uselesskey_core::{Factory, Seed};

// =========================================================================
// RSA
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_prop {
    use super::*;
    use uselesskey_ring::RingRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    proptest! {
        // RSA keygen is expensive — limit cases.
        #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

        /// Deterministic factories with the same seed produce identical ring RSA key pairs.
        #[test]
        fn deterministic_rsa_ring_is_consistent(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.rsa("prop-rsa", RsaSpec::rs256());
            let kp2 = fx2.rsa("prop-rsa", RsaSpec::rs256());

            prop_assert_eq!(
                kp1.private_key_pkcs8_der(),
                kp2.private_key_pkcs8_der(),
                "Same seed should produce identical RSA keys"
            );

            // Adapter conversion should not panic.
            let ring1 = kp1.rsa_key_pair_ring();
            let ring2 = kp2.rsa_key_pair_ring();

            prop_assert_eq!(
                ring1.public().modulus_len(),
                ring2.public().modulus_len(),
                "Modulus length should be identical"
            );
        }

        /// Different labels produce different RSA keys through ring.
        #[test]
        fn label_divergence_rsa_ring(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));

            let kp_a = fx.rsa("label-a", RsaSpec::rs256());
            let kp_b = fx.rsa("label-b", RsaSpec::rs256());

            prop_assert_ne!(
                kp_a.private_key_pkcs8_der(),
                kp_b.private_key_pkcs8_der(),
                "Different labels should produce different RSA keys"
            );

            let ring_a = kp_a.rsa_key_pair_ring();
            let ring_b = kp_b.rsa_key_pair_ring();

            prop_assert_ne!(
                ring_a.public().as_ref(),
                ring_b.public().as_ref(),
                "Different labels should yield different ring public keys"
            );
        }

        /// Debug output of uselesskey RSA key pair does not leak key material.
        #[test]
        fn debug_safety_rsa(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.rsa("prop-debug", RsaSpec::rs256());

            let dbg = format!("{:?}", kp);

            prop_assert!(!dbg.contains("BEGIN PRIVATE KEY"), "Debug must not contain PEM header");
            prop_assert!(!dbg.contains("BEGIN RSA PRIVATE"), "Debug must not contain RSA PEM header");
        }
    }
}

// =========================================================================
// ECDSA
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_prop {
    use super::*;
    use ring::signature::KeyPair;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ring::RingEcdsaKeyPairExt;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Deterministic P-256 keys yield identical ring key pairs.
        #[test]
        fn deterministic_p256_ring_is_consistent(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.ecdsa("prop-p256", EcdsaSpec::es256());
            let kp2 = fx2.ecdsa("prop-p256", EcdsaSpec::es256());

            prop_assert_eq!(
                kp1.private_key_pkcs8_der(),
                kp2.private_key_pkcs8_der(),
                "Same seed should produce identical P-256 keys"
            );

            let ring1 = kp1.ecdsa_key_pair_ring();
            let ring2 = kp2.ecdsa_key_pair_ring();

            prop_assert_eq!(
                ring1.public_key().as_ref(),
                ring2.public_key().as_ref(),
                "Ring public keys should be identical"
            );
        }

        /// Deterministic P-384 keys yield identical ring key pairs.
        #[test]
        fn deterministic_p384_ring_is_consistent(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.ecdsa("prop-p384", EcdsaSpec::es384());
            let kp2 = fx2.ecdsa("prop-p384", EcdsaSpec::es384());

            prop_assert_eq!(
                kp1.private_key_pkcs8_der(),
                kp2.private_key_pkcs8_der(),
                "Same seed should produce identical P-384 keys"
            );

            let ring1 = kp1.ecdsa_key_pair_ring();
            let ring2 = kp2.ecdsa_key_pair_ring();

            prop_assert_eq!(
                ring1.public_key().as_ref(),
                ring2.public_key().as_ref(),
                "Ring public keys should be identical"
            );
        }

        /// Different labels produce different ECDSA ring keys.
        #[test]
        fn label_divergence_ecdsa_ring(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));

            let kp_a = fx.ecdsa("label-a", EcdsaSpec::es256());
            let kp_b = fx.ecdsa("label-b", EcdsaSpec::es256());

            let ring_a = kp_a.ecdsa_key_pair_ring();
            let ring_b = kp_b.ecdsa_key_pair_ring();

            prop_assert_ne!(
                ring_a.public_key().as_ref(),
                ring_b.public_key().as_ref(),
                "Different labels should yield different ring public keys"
            );
        }

        /// Debug output of uselesskey ECDSA key pair does not leak key material.
        #[test]
        fn debug_safety_ecdsa(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ecdsa("prop-debug", EcdsaSpec::es256());

            let dbg = format!("{:?}", kp);

            prop_assert!(!dbg.contains("BEGIN PRIVATE KEY"), "Debug must not contain PEM header");
            prop_assert!(!dbg.contains("BEGIN EC PRIVATE"), "Debug must not contain EC PEM header");
        }
    }
}

// =========================================================================
// Ed25519
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_prop {
    use super::*;
    use ring::signature::KeyPair;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_ring::RingEd25519KeyPairExt;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        /// Deterministic Ed25519 keys yield identical ring key pairs.
        #[test]
        fn deterministic_ed25519_ring_is_consistent(seed in any::<[u8; 32]>()) {
            let fx1 = Factory::deterministic(Seed::new(seed));
            let fx2 = Factory::deterministic(Seed::new(seed));

            let kp1 = fx1.ed25519("prop-ed", Ed25519Spec::new());
            let kp2 = fx2.ed25519("prop-ed", Ed25519Spec::new());

            prop_assert_eq!(
                kp1.private_key_pkcs8_der(),
                kp2.private_key_pkcs8_der(),
                "Same seed should produce identical Ed25519 keys"
            );

            let ring1 = kp1.ed25519_key_pair_ring();
            let ring2 = kp2.ed25519_key_pair_ring();

            prop_assert_eq!(
                ring1.public_key().as_ref(),
                ring2.public_key().as_ref(),
                "Ring public keys should be identical"
            );
        }

        /// Different labels produce different Ed25519 ring keys.
        #[test]
        fn label_divergence_ed25519_ring(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));

            let kp_a = fx.ed25519("label-a", Ed25519Spec::new());
            let kp_b = fx.ed25519("label-b", Ed25519Spec::new());

            let ring_a = kp_a.ed25519_key_pair_ring();
            let ring_b = kp_b.ed25519_key_pair_ring();

            prop_assert_ne!(
                ring_a.public_key().as_ref(),
                ring_b.public_key().as_ref(),
                "Different labels should yield different ring public keys"
            );
        }

        /// Debug output of uselesskey Ed25519 key pair does not leak key material.
        #[test]
        fn debug_safety_ed25519(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ed25519("prop-debug", Ed25519Spec::new());

            let dbg = format!("{:?}", kp);

            prop_assert!(!dbg.contains("BEGIN PRIVATE KEY"), "Debug must not contain PEM header");
        }
    }
}
