#[allow(dead_code)]
mod testutil;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;

use uselesskey_core::{Factory, Seed};
use uselesskey_token::{TokenFactoryExt, TokenSpec};

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    // =========================================================================
    // API key prefix and length
    // =========================================================================

    /// API key tokens start with "uk_test_" and have total length 40.
    #[test]
    fn api_key_prefix_and_length(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let token = fx.token("prop-api", TokenSpec::api_key());
        let value = token.value();

        prop_assert!(
            value.starts_with("uk_test_"),
            "API key should start with 'uk_test_', got: {value}"
        );
        prop_assert_eq!(
            value.len(),
            40,
            "API key should be 40 chars (8 prefix + 32 base62), got: {}",
            value.len()
        );

        // Verify the suffix is all base62 (alphanumeric).
        let suffix = &value["uk_test_".len()..];
        prop_assert!(
            suffix.chars().all(|c| c.is_ascii_alphanumeric()),
            "API key suffix should be base62, got: {suffix}"
        );
    }

    // =========================================================================
    // Bearer is valid base64url
    // =========================================================================

    /// Bearer tokens are valid base64url-encoded strings of 43 characters.
    #[test]
    fn bearer_is_valid_base64url(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let token = fx.token("prop-bearer", TokenSpec::bearer());
        let value = token.value();

        prop_assert_eq!(
            value.len(),
            43,
            "Bearer token should be 43 chars (base64url of 32 bytes), got: {}",
            value.len()
        );

        let decoded = URL_SAFE_NO_PAD.decode(value);
        prop_assert!(
            decoded.is_ok(),
            "Bearer token should be valid base64url, decode error: {:?}",
            decoded.err()
        );
        prop_assert_eq!(
            decoded.unwrap().len(),
            32,
            "Bearer token should decode to 32 bytes"
        );
    }

    // =========================================================================
    // OAuth has 3 dot-separated segments
    // =========================================================================

    /// OAuth access tokens have exactly 3 dot-separated segments (JWT shape).
    #[test]
    fn oauth_has_three_dot_separated_segments(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let token = fx.token("prop-oauth", TokenSpec::oauth_access_token());
        let value = token.value();

        let parts: Vec<&str> = value.split('.').collect();
        prop_assert_eq!(
            parts.len(),
            3,
            "OAuth token should have 3 dot-separated segments, got: {}",
            parts.len()
        );
    }

    // =========================================================================
    // Spec isolation
    // =========================================================================

    /// Different specs for the same label produce different values.
    #[test]
    fn spec_isolation(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));

        let api_key = fx.token("same-label", TokenSpec::api_key());
        let bearer = fx.token("same-label", TokenSpec::bearer());
        let oauth = fx.token("same-label", TokenSpec::oauth_access_token());

        prop_assert_ne!(
            api_key.value(),
            bearer.value(),
            "ApiKey and Bearer should differ for same label"
        );
        prop_assert_ne!(
            api_key.value(),
            oauth.value(),
            "ApiKey and OAuth should differ for same label"
        );
        prop_assert_ne!(
            bearer.value(),
            oauth.value(),
            "Bearer and OAuth should differ for same label"
        );
    }

    // =========================================================================
    // Deterministic stability
    // =========================================================================

    /// Same seed + label + spec produces the same value.
    #[test]
    fn deterministic_stability(seed in any::<[u8; 32]>()) {
        let fx1 = Factory::deterministic(Seed::new(seed));
        let fx2 = Factory::deterministic(Seed::new(seed));

        let t1 = fx1.token("prop-stable", TokenSpec::api_key());
        let t2 = fx2.token("prop-stable", TokenSpec::api_key());
        prop_assert_eq!(t1.value(), t2.value(), "ApiKey should be deterministic");

        let t1 = fx1.token("prop-stable", TokenSpec::bearer());
        let t2 = fx2.token("prop-stable", TokenSpec::bearer());
        prop_assert_eq!(t1.value(), t2.value(), "Bearer should be deterministic");

        let t1 = fx1.token("prop-stable", TokenSpec::oauth_access_token());
        let t2 = fx2.token("prop-stable", TokenSpec::oauth_access_token());
        prop_assert_eq!(t1.value(), t2.value(), "OAuth should be deterministic");
    }
}
