//! Property tests for `TokenSpec` enum invariants.

use proptest::prelude::*;
use uselesskey_token_spec::TokenSpec;

fn arb_token_spec() -> impl Strategy<Value = TokenSpec> {
    prop_oneof![
        Just(TokenSpec::ApiKey),
        Just(TokenSpec::Bearer),
        Just(TokenSpec::OAuthAccessToken),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Every spec variant has a non-empty kind_name.
    #[test]
    fn kind_name_is_non_empty(spec in arb_token_spec()) {
        prop_assert!(!spec.kind_name().is_empty());
    }

    /// Every spec variant has a non-zero stable_bytes encoding.
    #[test]
    fn stable_bytes_is_non_zero(spec in arb_token_spec()) {
        prop_assert_ne!(spec.stable_bytes(), [0, 0, 0, 0]);
    }

    /// kind_name is always pure ASCII snake_case.
    #[test]
    fn kind_name_is_ascii_snake_case(spec in arb_token_spec()) {
        let name = spec.kind_name();
        prop_assert!(
            name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "kind_name '{}' is not snake_case",
            name
        );
    }

    /// Two arbitrary specs either are equal or have different stable_bytes.
    #[test]
    fn equal_or_distinct_stable_bytes(
        a in arb_token_spec(),
        b in arb_token_spec(),
    ) {
        if a == b {
            prop_assert_eq!(a.stable_bytes(), b.stable_bytes());
        } else {
            prop_assert_ne!(a.stable_bytes(), b.stable_bytes());
        }
    }

    /// Clone preserves equality.
    #[test]
    fn clone_preserves_equality(spec in arb_token_spec()) {
        #[allow(clippy::clone_on_copy)]
        let cloned = spec.clone();
        prop_assert_eq!(spec, cloned);
        prop_assert_eq!(spec.stable_bytes(), cloned.stable_bytes());
        prop_assert_eq!(spec.kind_name(), cloned.kind_name());
    }

    /// Debug output contains the variant name.
    #[test]
    fn debug_contains_variant(spec in arb_token_spec()) {
        let dbg = format!("{spec:?}");
        let expected = match spec {
            TokenSpec::ApiKey => "ApiKey",
            TokenSpec::Bearer => "Bearer",
            TokenSpec::OAuthAccessToken => "OAuthAccessToken",
        };
        prop_assert!(dbg.contains(expected));
    }
}
