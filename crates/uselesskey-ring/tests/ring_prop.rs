use proptest::prelude::*;
use uselesskey_core::{Factory, Seed};

proptest! {
    #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

    /// Deterministic factory produces the same ring RSA KeyPair modulus for the same seed.
    #[cfg(feature = "rsa")]
    #[test]
    fn rsa_ring_deterministic(seed in any::<[u8; 32]>()) {
        use uselesskey_ring::RingRsaKeyPairExt;
        use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

        let fx = Factory::deterministic(Seed::new(seed));
        let kp1 = fx.rsa("prop-test", RsaSpec::rs256()).rsa_key_pair_ring();
        let kp2 = fx.rsa("prop-test", RsaSpec::rs256()).rsa_key_pair_ring();

        prop_assert_eq!(kp1.public().as_ref(), kp2.public().as_ref());
        prop_assert!(kp1.public().modulus_len() > 0);
    }

    /// Deterministic factory produces the same ring ECDSA public key for the same seed.
    #[cfg(feature = "ecdsa")]
    #[test]
    fn ecdsa_ring_deterministic(seed in any::<[u8; 32]>()) {
        use ring::signature::KeyPair;
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
        use uselesskey_ring::RingEcdsaKeyPairExt;

        let fx = Factory::deterministic(Seed::new(seed));
        let kp1 = fx.ecdsa("prop-test", EcdsaSpec::es256()).ecdsa_key_pair_ring();
        let kp2 = fx.ecdsa("prop-test", EcdsaSpec::es256()).ecdsa_key_pair_ring();

        prop_assert_eq!(kp1.public_key().as_ref(), kp2.public_key().as_ref());
    }

    /// Deterministic factory produces the same ring Ed25519 public key for the same seed.
    #[cfg(feature = "ed25519")]
    #[test]
    fn ed25519_ring_deterministic(seed in any::<[u8; 32]>()) {
        use ring::signature::KeyPair;
        use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
        use uselesskey_ring::RingEd25519KeyPairExt;

        let fx = Factory::deterministic(Seed::new(seed));
        let kp1 = fx.ed25519("prop-test", Ed25519Spec::new()).ed25519_key_pair_ring();
        let kp2 = fx.ed25519("prop-test", Ed25519Spec::new()).ed25519_key_pair_ring();

        prop_assert_eq!(kp1.public_key().as_ref(), kp2.public_key().as_ref());
    }
}
