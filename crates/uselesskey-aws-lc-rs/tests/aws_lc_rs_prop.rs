use proptest::prelude::*;
use uselesskey_core::{Factory, Seed};

proptest! {
    #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

    /// Deterministic factory produces the same aws-lc-rs RSA public key for the same seed.
    #[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "rsa"))]
    #[test]
    fn rsa_aws_lc_rs_deterministic(seed in any::<[u8; 32]>()) {
        use aws_lc_rs::signature::KeyPair;
        use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;
        use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

        let fx = Factory::deterministic(Seed::new(seed));
        let kp1 = fx.rsa("prop-test", RsaSpec::rs256()).rsa_key_pair_aws_lc_rs();
        let kp2 = fx.rsa("prop-test", RsaSpec::rs256()).rsa_key_pair_aws_lc_rs();

        prop_assert_eq!(kp1.public_key().as_ref(), kp2.public_key().as_ref());
        prop_assert!(kp1.public_modulus_len() > 0);
    }

    /// Deterministic factory produces the same aws-lc-rs ECDSA public key for the same seed.
    #[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ecdsa"))]
    #[test]
    fn ecdsa_aws_lc_rs_deterministic(seed in any::<[u8; 32]>()) {
        use aws_lc_rs::signature::KeyPair;
        use uselesskey_aws_lc_rs::AwsLcRsEcdsaKeyPairExt;
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

        let fx = Factory::deterministic(Seed::new(seed));
        let kp1 = fx.ecdsa("prop-test", EcdsaSpec::es256()).ecdsa_key_pair_aws_lc_rs();
        let kp2 = fx.ecdsa("prop-test", EcdsaSpec::es256()).ecdsa_key_pair_aws_lc_rs();

        prop_assert_eq!(kp1.public_key().as_ref(), kp2.public_key().as_ref());
    }

    /// Deterministic factory produces the same aws-lc-rs Ed25519 public key for the same seed.
    #[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ed25519"))]
    #[test]
    fn ed25519_aws_lc_rs_deterministic(seed in any::<[u8; 32]>()) {
        use aws_lc_rs::signature::KeyPair;
        use uselesskey_aws_lc_rs::AwsLcRsEd25519KeyPairExt;
        use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

        let fx = Factory::deterministic(Seed::new(seed));
        let kp1 = fx.ed25519("prop-test", Ed25519Spec::new()).ed25519_key_pair_aws_lc_rs();
        let kp2 = fx.ed25519("prop-test", Ed25519Spec::new()).ed25519_key_pair_aws_lc_rs();

        prop_assert_eq!(kp1.public_key().as_ref(), kp2.public_key().as_ref());
    }
}
