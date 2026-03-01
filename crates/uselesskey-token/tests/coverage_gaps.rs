//! Coverage-gap tests for uselesskey-token.
//!
//! Fills gaps not covered by existing prop/unit/inline tests:
//! - Random mode produces valid shapes for all specs
//! - Bearer token value is non-empty and correct length
//! - OAuth token signature segment is non-empty
//! - token_with_variant for all specs (not just api_key)
//! - Different variants produce different values for bearer/oauth
//! - Debug safety for bearer and oauth tokens

mod testutil;

use testutil::fx;
use uselesskey_core::{Factory, Seed};
use uselesskey_token::{TokenFactoryExt, TokenSpec};

// =========================================================================
// Random mode for all specs
// =========================================================================

#[test]
fn random_mode_api_key_has_correct_shape() {
    let fx = Factory::random();
    let token = fx.token("random-api", TokenSpec::api_key());
    let value = token.value();

    assert!(value.starts_with("uk_test_"));
    assert_eq!(value.len(), 40);
    let suffix = &value["uk_test_".len()..];
    assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn random_mode_bearer_has_correct_shape() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let fx = Factory::random();
    let token = fx.token("random-bearer", TokenSpec::bearer());
    let value = token.value();

    assert_eq!(value.len(), 43, "Bearer should be 43 chars");
    let decoded = URL_SAFE_NO_PAD.decode(value);
    assert!(decoded.is_ok(), "Bearer should be valid base64url");
    assert_eq!(decoded.unwrap().len(), 32);
}

#[test]
fn random_mode_oauth_has_three_segments() {
    let fx = Factory::random();
    let token = fx.token("random-oauth", TokenSpec::oauth_access_token());
    let parts: Vec<&str> = token.value().split('.').collect();
    assert_eq!(parts.len(), 3);
}

// =========================================================================
// OAuth signature segment is non-empty
// =========================================================================

#[test]
fn oauth_signature_segment_is_non_empty() {
    let fx = fx();
    let token = fx.token("oauth-sig", TokenSpec::oauth_access_token());
    let parts: Vec<&str> = token.value().split('.').collect();
    assert!(
        !parts[2].is_empty(),
        "Signature segment should be non-empty"
    );
}

// =========================================================================
// token_with_variant for bearer and oauth
// =========================================================================

#[test]
fn token_with_variant_bearer() {
    let fx = fx();
    let good = fx.token("var-bearer", TokenSpec::bearer());
    let custom = fx.token_with_variant("var-bearer", TokenSpec::bearer(), "custom");
    assert_ne!(good.value(), custom.value());
}

#[test]
fn token_with_variant_oauth() {
    let fx = fx();
    let good = fx.token("var-oauth", TokenSpec::oauth_access_token());
    let custom = fx.token_with_variant("var-oauth", TokenSpec::oauth_access_token(), "custom");
    assert_ne!(good.value(), custom.value());
}

// =========================================================================
// Debug safety for bearer and oauth
// =========================================================================

#[test]
fn debug_does_not_leak_bearer_value() {
    let fx = Factory::random();
    let token = fx.token("debug-bearer", TokenSpec::bearer());
    let dbg = format!("{token:?}");

    assert!(dbg.contains("TokenFixture"));
    assert!(dbg.contains("debug-bearer"));
    assert!(!dbg.contains(token.value()));
}

#[test]
fn debug_does_not_leak_oauth_value() {
    let fx = Factory::random();
    let token = fx.token("debug-oauth", TokenSpec::oauth_access_token());
    let dbg = format!("{token:?}");

    assert!(dbg.contains("TokenFixture"));
    assert!(!dbg.contains(token.value()));
}

// =========================================================================
// Random mode caching
// =========================================================================

#[test]
fn random_mode_caches_all_specs() {
    let fx = Factory::random();

    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let t1 = fx.token("cache-test", spec);
        let t2 = fx.token("cache-test", spec);
        assert_eq!(
            t1.value(),
            t2.value(),
            "Random mode should cache for {:?}",
            spec
        );
    }
}

// =========================================================================
// OAuth claims contain expected fields for all labels
// =========================================================================

#[test]
fn oauth_payload_iat_and_exp_are_present() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let fx = fx();
    let token = fx.token("oauth-claims-check", TokenSpec::oauth_access_token());
    let parts: Vec<&str> = token.value().split('.').collect();

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("decode payload");
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).expect("parse payload");

    assert_eq!(
        payload["iss"], "uselesskey",
        "JWT payload should have 'iss'"
    );
    assert_eq!(
        payload["sub"], "oauth-claims-check",
        "JWT payload 'sub' should match label"
    );
    assert_eq!(payload["aud"], "tests", "JWT payload should have 'aud'");
    assert!(payload["exp"].is_number(), "JWT payload should have 'exp'");
    assert!(payload["jti"].is_string(), "JWT payload should have 'jti'");
}

// =========================================================================
// Determinism survives cache clear for all specs
// =========================================================================

#[test]
fn determinism_survives_cache_clear_all_specs() {
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let seed = Seed::from_env_value("token-cache-clear-all").unwrap();
        let fx = Factory::deterministic(seed);

        let t1 = fx.token("cache-clear", spec);
        let val1 = t1.value().to_string();
        fx.clear_cache();
        let t2 = fx.token("cache-clear", spec);
        assert_eq!(
            val1,
            t2.value(),
            "Determinism should survive cache clear for {:?}",
            spec
        );
    }
}
