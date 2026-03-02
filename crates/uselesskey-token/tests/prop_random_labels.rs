//! Property tests: random labels produce valid output for all token specs.

#[allow(dead_code)]
mod testutil;

use proptest::prelude::*;

use uselesskey_core::{Factory, Seed};
use uselesskey_token::{TokenFactoryExt, TokenSpec};

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Random labels always produce a valid API key with correct prefix and length.
    #[test]
    fn random_label_api_key(
        seed in any::<[u8; 32]>(),
        label in "[a-zA-Z][a-zA-Z0-9_]{0,30}",
    ) {
        let fx = Factory::deterministic(Seed::new(seed));
        let tok = fx.token(&label, TokenSpec::api_key());
        prop_assert!(tok.value().starts_with("uk_test_"));
        prop_assert_eq!(tok.value().len(), 40);
    }

    /// Random labels always produce a valid bearer token (43-char base64url).
    #[test]
    fn random_label_bearer(
        seed in any::<[u8; 32]>(),
        label in "[a-zA-Z][a-zA-Z0-9_]{0,30}",
    ) {
        let fx = Factory::deterministic(Seed::new(seed));
        let tok = fx.token(&label, TokenSpec::bearer());
        prop_assert_eq!(tok.value().len(), 43);
        prop_assert!(!tok.value().contains('+'));
        prop_assert!(!tok.value().contains('/'));
    }

    /// Random labels always produce a valid OAuth token with 3 dot-separated segments.
    #[test]
    fn random_label_oauth(
        seed in any::<[u8; 32]>(),
        label in "[a-zA-Z][a-zA-Z0-9_]{0,30}",
    ) {
        let fx = Factory::deterministic(Seed::new(seed));
        let tok = fx.token(&label, TokenSpec::oauth_access_token());
        let parts: Vec<&str> = tok.value().split('.').collect();
        prop_assert_eq!(parts.len(), 3);
    }

    /// Different random labels with the same seed produce different tokens.
    #[test]
    fn label_independence(
        seed in any::<[u8; 32]>(),
        label_a in "[a-zA-Z][a-zA-Z0-9_]{1,15}",
        label_b in "[a-zA-Z][a-zA-Z0-9_]{1,15}",
    ) {
        prop_assume!(label_a != label_b);
        let fx = Factory::deterministic(Seed::new(seed));
        let ta = fx.token(&label_a, TokenSpec::api_key());
        let tb = fx.token(&label_b, TokenSpec::api_key());
        prop_assert_ne!(ta.value(), tb.value());
    }

    /// Non-emptiness holds for all spec variants with random labels.
    #[test]
    fn all_specs_non_empty(
        seed in any::<[u8; 32]>(),
        label in "[a-zA-Z][a-zA-Z0-9_]{0,15}",
        kind_idx in 0u8..3,
    ) {
        let spec = match kind_idx {
            0 => TokenSpec::api_key(),
            1 => TokenSpec::bearer(),
            _ => TokenSpec::oauth_access_token(),
        };
        let fx = Factory::deterministic(Seed::new(seed));
        let tok = fx.token(&label, spec);
        prop_assert!(!tok.value().is_empty());
    }
}
