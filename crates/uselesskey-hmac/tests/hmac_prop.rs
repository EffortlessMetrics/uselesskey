#[allow(dead_code)]
mod testutil;

use proptest::prelude::*;

use uselesskey_core::{Factory, Seed};
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    // =========================================================================
    // Deterministic stability
    // =========================================================================

    /// Same seed + label + spec produces identical secret bytes.
    #[test]
    fn deterministic_hmac_secret_is_stable(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let s1 = fx.hmac("prop-key", HmacSpec::hs256());
        let s2 = fx.hmac("prop-key", HmacSpec::hs256());

        prop_assert_eq!(s1.secret_bytes(), s2.secret_bytes());
    }

    // =========================================================================
    // Secret length matches spec
    // =========================================================================

    /// HS256 secrets are 32 bytes.
    #[test]
    fn hs256_secret_length_is_32(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let secret = fx.hmac("prop-len", HmacSpec::hs256());
        prop_assert_eq!(secret.secret_bytes().len(), 32, "HS256 secret should be 32 bytes");
    }

    /// HS384 secrets are 48 bytes.
    #[test]
    fn hs384_secret_length_is_48(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let secret = fx.hmac("prop-len", HmacSpec::hs384());
        prop_assert_eq!(secret.secret_bytes().len(), 48, "HS384 secret should be 48 bytes");
    }

    /// HS512 secrets are 64 bytes.
    #[test]
    fn hs512_secret_length_is_64(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let secret = fx.hmac("prop-len", HmacSpec::hs512());
        prop_assert_eq!(secret.secret_bytes().len(), 64, "HS512 secret should be 64 bytes");
    }

    // =========================================================================
    // Label isolation
    // =========================================================================

    /// Different labels produce different secret bytes.
    #[test]
    fn different_labels_produce_different_secrets(
        seed in any::<[u8; 32]>(),
        label1 in "[a-zA-Z0-9]{1,16}",
        label2 in "[a-zA-Z0-9]{1,16}",
    ) {
        prop_assume!(label1 != label2);

        let fx = Factory::deterministic(Seed::new(seed));
        let s1 = fx.hmac(&label1, HmacSpec::hs256());
        let s2 = fx.hmac(&label2, HmacSpec::hs256());

        prop_assert_ne!(
            s1.secret_bytes(), s2.secret_bytes(),
            "Different labels should produce different secrets"
        );
    }
}
