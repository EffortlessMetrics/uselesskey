//! Additional property-based tests for token fixtures — Wave 91.
//!
//! Covers format invariants, character set compliance, authorization headers,
//! and variant isolation across all token specs with random seeds.

#[allow(dead_code)]
mod testutil;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;

use uselesskey_core::{Factory, Seed};
use uselesskey_token::{TokenFactoryExt, TokenSpec};

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    // =====================================================================
    // Character set invariants
    // =====================================================================

    #[test]
    fn prop_api_key_suffix_only_alphanumeric(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let tok = fx.token("prop-cs-api", TokenSpec::api_key());
        let suffix = tok.value().strip_prefix("uk_test_").unwrap();
        prop_assert!(
            suffix.chars().all(|c| c.is_ascii_alphanumeric()),
            "API key suffix must be base62"
        );
    }

    #[test]
    fn prop_bearer_no_standard_base64_chars(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let tok = fx.token("prop-cs-bearer", TokenSpec::bearer());
        let val = tok.value();
        prop_assert!(!val.contains('+'), "must not contain +");
        prop_assert!(!val.contains('/'), "must not contain /");
        prop_assert!(!val.contains('='), "must not contain padding");
    }

    #[test]
    fn prop_oauth_all_segments_valid_base64url(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let tok = fx.token("prop-cs-oauth", TokenSpec::oauth_access_token());
        for segment in tok.value().split('.') {
            prop_assert!(
                URL_SAFE_NO_PAD.decode(segment).is_ok(),
                "all OAuth segments must be valid base64url"
            );
        }
    }

    // =====================================================================
    // Authorization header invariants
    // =====================================================================

    #[test]
    fn prop_api_key_auth_header_starts_with_apikey(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let tok = fx.token("prop-auth-api", TokenSpec::api_key());
        let header = tok.authorization_header();
        prop_assert!(header.starts_with("ApiKey "));
        prop_assert!(header.ends_with(tok.value()));
    }

    #[test]
    fn prop_bearer_auth_header_starts_with_bearer(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let tok = fx.token("prop-auth-bearer", TokenSpec::bearer());
        let header = tok.authorization_header();
        prop_assert!(header.starts_with("Bearer "));
        prop_assert!(header.ends_with(tok.value()));
    }

    #[test]
    fn prop_oauth_auth_header_starts_with_bearer(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let tok = fx.token("prop-auth-oauth", TokenSpec::oauth_access_token());
        let header = tok.authorization_header();
        prop_assert!(header.starts_with("Bearer "));
        prop_assert!(header.ends_with(tok.value()));
    }

    // =====================================================================
    // Variant isolation
    // =====================================================================

    #[test]
    fn prop_variant_differs_from_default_all_specs(seed in any::<[u8; 32]>(), kind_idx in 0u8..3) {
        let spec = match kind_idx {
            0 => TokenSpec::api_key(),
            1 => TokenSpec::bearer(),
            _ => TokenSpec::oauth_access_token(),
        };
        let fx = Factory::deterministic(Seed::new(seed));
        let good = fx.token("prop-var", spec);
        let alt = fx.token_with_variant("prop-var", spec, "alt");
        prop_assert_ne!(good.value(), alt.value(), "variant should differ from default");
    }

    // =====================================================================
    // OAuth JWT payload sub matches label
    // =====================================================================

    #[test]
    fn prop_oauth_sub_matches_label(seed in any::<[u8; 32]>(), label in "[a-z][a-z0-9_-]{0,15}") {
        let fx = Factory::deterministic(Seed::new(seed));
        let tok = fx.token(&label, TokenSpec::oauth_access_token());
        let parts: Vec<&str> = tok.value().split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        prop_assert_eq!(claims["sub"].as_str().unwrap(), label.as_str());
    }

    // =====================================================================
    // Debug safety across all specs
    // =====================================================================

    #[test]
    fn prop_debug_does_not_leak_value(seed in any::<[u8; 32]>(), kind_idx in 0u8..3) {
        let spec = match kind_idx {
            0 => TokenSpec::api_key(),
            1 => TokenSpec::bearer(),
            _ => TokenSpec::oauth_access_token(),
        };
        let fx = Factory::deterministic(Seed::new(seed));
        let tok = fx.token("prop-debug", spec);
        let dbg = format!("{tok:?}");
        prop_assert!(!dbg.contains(tok.value()), "Debug must not leak token value");
    }

    // =====================================================================
    // Variant-based tokens still have correct format
    // =====================================================================

    #[test]
    fn prop_variant_api_key_still_valid_format(seed in any::<[u8; 32]>(), variant in "[a-z]{1,8}") {
        let fx = Factory::deterministic(Seed::new(seed));
        let tok = fx.token_with_variant("prop-fmt-var", TokenSpec::api_key(), &variant);
        prop_assert!(tok.value().starts_with("uk_test_"));
        prop_assert_eq!(tok.value().len(), 40);
    }

    #[test]
    fn prop_variant_bearer_still_valid_format(seed in any::<[u8; 32]>(), variant in "[a-z]{1,8}") {
        let fx = Factory::deterministic(Seed::new(seed));
        let tok = fx.token_with_variant("prop-fmt-var", TokenSpec::bearer(), &variant);
        prop_assert_eq!(tok.value().len(), 43);
        prop_assert!(URL_SAFE_NO_PAD.decode(tok.value()).is_ok());
    }

    #[test]
    fn prop_variant_oauth_still_valid_format(seed in any::<[u8; 32]>(), variant in "[a-z]{1,8}") {
        let fx = Factory::deterministic(Seed::new(seed));
        let tok = fx.token_with_variant("prop-fmt-var", TokenSpec::oauth_access_token(), &variant);
        let parts: Vec<&str> = tok.value().split('.').collect();
        prop_assert_eq!(parts.len(), 3);
    }
}
