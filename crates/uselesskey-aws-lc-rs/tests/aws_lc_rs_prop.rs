//! Property-based tests for uselesskey-aws-lc-rs adapter.
//!
//! Covers:
//! - Determinism: same seed → same aws-lc-rs key for all algorithms
//! - Debug safety: Debug output never contains key material
//! - Label divergence: different labels produce different keys

mod testutil;

use proptest::prelude::*;
use uselesskey_core::{Factory, Seed};

// RSA property tests — expensive keygen, limit cases.
#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "rsa"))]
mod rsa_prop {
    use super::*;
    use aws_lc_rs::signature::KeyPair;
    use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 5, ..ProptestConfig::default() })]

        #[test]
        fn deterministic_rsa_same_seed(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp1 = fx.rsa("prop-rsa", RsaSpec::rs256());
            let kp2 = fx.rsa("prop-rsa", RsaSpec::rs256());

            let aws1 = kp1.rsa_key_pair_aws_lc_rs();
            let aws2 = kp2.rsa_key_pair_aws_lc_rs();

            prop_assert_eq!(
                aws1.public_key().as_ref(),
                aws2.public_key().as_ref(),
                "Same seed must produce identical RSA public keys"
            );
        }

        #[test]
        fn rsa_debug_does_not_leak(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.rsa("prop-dbg", RsaSpec::rs256());
            let dbg = format!("{kp:?}");

            prop_assert!(!dbg.contains("BEGIN PRIVATE KEY"), "debug leaked private PEM header");
            prop_assert!(!dbg.contains("BEGIN PUBLIC KEY"), "debug leaked public PEM header");
            // Base64-encoded PKCS#8 RSA keys start with "MII"
            prop_assert!(!dbg.contains("MIIEv"), "debug leaked base64 private key body");
        }

        #[test]
        fn rsa_different_labels_diverge(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp_a = fx.rsa("prop-label-a", RsaSpec::rs256());
            let kp_b = fx.rsa("prop-label-b", RsaSpec::rs256());

            let aws_a = kp_a.rsa_key_pair_aws_lc_rs();
            let aws_b = kp_b.rsa_key_pair_aws_lc_rs();

            prop_assert_ne!(
                aws_a.public_key().as_ref(),
                aws_b.public_key().as_ref(),
                "Different labels must produce different RSA keys"
            );
        }
    }
}

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ecdsa"))]
mod ecdsa_prop {
    use super::*;
    use aws_lc_rs::signature::KeyPair;
    use uselesskey_aws_lc_rs::AwsLcRsEcdsaKeyPairExt;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        #[test]
        fn deterministic_p256_same_seed(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp1 = fx.ecdsa("prop-p256", EcdsaSpec::es256());
            let kp2 = fx.ecdsa("prop-p256", EcdsaSpec::es256());

            let aws1 = kp1.ecdsa_key_pair_aws_lc_rs();
            let aws2 = kp2.ecdsa_key_pair_aws_lc_rs();

            prop_assert_eq!(
                aws1.public_key().as_ref(),
                aws2.public_key().as_ref(),
                "Same seed must produce identical P-256 public keys"
            );
        }

        #[test]
        fn deterministic_p384_same_seed(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp1 = fx.ecdsa("prop-p384", EcdsaSpec::es384());
            let kp2 = fx.ecdsa("prop-p384", EcdsaSpec::es384());

            let aws1 = kp1.ecdsa_key_pair_aws_lc_rs();
            let aws2 = kp2.ecdsa_key_pair_aws_lc_rs();

            prop_assert_eq!(
                aws1.public_key().as_ref(),
                aws2.public_key().as_ref(),
                "Same seed must produce identical P-384 public keys"
            );
        }

        #[test]
        fn ecdsa_debug_does_not_leak(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
                let kp = fx.ecdsa("prop-dbg", spec);
                let dbg = format!("{kp:?}");

                prop_assert!(!dbg.contains("BEGIN PRIVATE KEY"), "debug leaked private PEM header");
                prop_assert!(!dbg.contains("BEGIN PUBLIC KEY"), "debug leaked public PEM header");
            }
        }

        #[test]
        fn ecdsa_different_labels_diverge(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp_a = fx.ecdsa("prop-label-a", EcdsaSpec::es256());
            let kp_b = fx.ecdsa("prop-label-b", EcdsaSpec::es256());

            let aws_a = kp_a.ecdsa_key_pair_aws_lc_rs();
            let aws_b = kp_b.ecdsa_key_pair_aws_lc_rs();

            prop_assert_ne!(
                aws_a.public_key().as_ref(),
                aws_b.public_key().as_ref(),
                "Different labels must produce different ECDSA keys"
            );
        }
    }
}

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ed25519"))]
mod ed25519_prop {
    use super::*;
    use aws_lc_rs::signature::KeyPair;
    use uselesskey_aws_lc_rs::AwsLcRsEd25519KeyPairExt;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

        #[test]
        fn deterministic_ed25519_same_seed(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp1 = fx.ed25519("prop-ed", Ed25519Spec::new());
            let kp2 = fx.ed25519("prop-ed", Ed25519Spec::new());

            let aws1 = kp1.ed25519_key_pair_aws_lc_rs();
            let aws2 = kp2.ed25519_key_pair_aws_lc_rs();

            prop_assert_eq!(
                aws1.public_key().as_ref(),
                aws2.public_key().as_ref(),
                "Same seed must produce identical Ed25519 public keys"
            );
        }

        #[test]
        fn ed25519_debug_does_not_leak(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp = fx.ed25519("prop-dbg", Ed25519Spec::new());
            let dbg = format!("{kp:?}");

            prop_assert!(!dbg.contains("BEGIN PRIVATE KEY"), "debug leaked private PEM header");
            prop_assert!(!dbg.contains("BEGIN PUBLIC KEY"), "debug leaked public PEM header");
        }

        #[test]
        fn ed25519_different_labels_diverge(seed in any::<[u8; 32]>()) {
            let fx = Factory::deterministic(Seed::new(seed));
            let kp_a = fx.ed25519("prop-label-a", Ed25519Spec::new());
            let kp_b = fx.ed25519("prop-label-b", Ed25519Spec::new());

            let aws_a = kp_a.ed25519_key_pair_aws_lc_rs();
            let aws_b = kp_b.ed25519_key_pair_aws_lc_rs();

            prop_assert_ne!(
                aws_a.public_key().as_ref(),
                aws_b.public_key().as_ref(),
                "Different labels must produce different Ed25519 keys"
            );
        }
    }
}
