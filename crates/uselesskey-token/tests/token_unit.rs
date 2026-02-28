//! External unit tests for uselesskey-token.
//!
//! Gaps covered beyond the proptest file and inline tests:
//! - authorization_header for all token types (inline only tested bearer)
//! - token_with_variant via public API
//! - Determinism across separate factories
//! - Determinism survives cache clear
//! - Debug does not leak token value
//! - OAuth JWT header/payload structure validation

mod testutil;

use testutil::fx;
use uselesskey_token::{TokenFactoryExt, TokenSpec};

// =========================================================================
// Authorization header for all token types
// =========================================================================

#[test]
fn api_key_authorization_header_uses_apikey_scheme() {
    let fx = fx();
    let token = fx.token("auth-api", TokenSpec::api_key());
    let header = token.authorization_header();

    assert!(
        header.starts_with("ApiKey "),
        "API key auth header should start with 'ApiKey ', got: {header}"
    );
    assert!(header.ends_with(token.value()));
}

#[test]
fn bearer_authorization_header_uses_bearer_scheme() {
    let fx = fx();
    let token = fx.token("auth-bearer", TokenSpec::bearer());
    let header = token.authorization_header();

    assert!(
        header.starts_with("Bearer "),
        "Bearer auth header should start with 'Bearer ', got: {header}"
    );
    assert!(header.ends_with(token.value()));
}

#[test]
fn oauth_authorization_header_uses_bearer_scheme() {
    let fx = fx();
    let token = fx.token("auth-oauth", TokenSpec::oauth_access_token());
    let header = token.authorization_header();

    assert!(
        header.starts_with("Bearer "),
        "OAuth auth header should start with 'Bearer ', got: {header}"
    );
    assert!(header.ends_with(token.value()));
}

// =========================================================================
// token_with_variant
// =========================================================================

#[test]
fn token_with_variant_produces_different_value() {
    let fx = fx();
    let good = fx.token("variant-test", TokenSpec::api_key());
    let custom = fx.token_with_variant("variant-test", TokenSpec::api_key(), "custom");

    assert_ne!(
        good.value(),
        custom.value(),
        "Default and custom variant should differ"
    );
}

#[test]
fn token_with_variant_is_deterministic() {
    use uselesskey_core::{Factory, Seed};

    let seed1 = Seed::from_env_value("token-variant-det").unwrap();
    let seed2 = Seed::from_env_value("token-variant-det").unwrap();
    let fx1 = Factory::deterministic(seed1);
    let fx2 = Factory::deterministic(seed2);

    let t1 = fx1.token_with_variant("svc", TokenSpec::bearer(), "custom");
    let t2 = fx2.token_with_variant("svc", TokenSpec::bearer(), "custom");

    assert_eq!(t1.value(), t2.value());
}

// =========================================================================
// Determinism across separate factories
// =========================================================================

#[test]
fn determinism_across_factories() {
    use uselesskey_core::{Factory, Seed};

    let seed1 = Seed::from_env_value("token-cross-factory").unwrap();
    let seed2 = Seed::from_env_value("token-cross-factory").unwrap();
    let fx1 = Factory::deterministic(seed1);
    let fx2 = Factory::deterministic(seed2);

    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let t1 = fx1.token("cross-fac", spec);
        let t2 = fx2.token("cross-fac", spec);
        assert_eq!(
            t1.value(),
            t2.value(),
            "Same seed should produce same token for {:?}",
            spec
        );
    }
}

// =========================================================================
// Cache-clear determinism
// =========================================================================

#[test]
fn determinism_survives_cache_clear() {
    use uselesskey_core::{Factory, Seed};

    let seed = Seed::from_env_value("token-cache-clear").unwrap();
    let fx = Factory::deterministic(seed);

    let t1 = fx.token("cache-test", TokenSpec::bearer());
    let val1 = t1.value().to_string();

    fx.clear_cache();

    let t2 = fx.token("cache-test", TokenSpec::bearer());
    assert_eq!(val1, t2.value());
}

// =========================================================================
// Debug safety
// =========================================================================

#[test]
fn debug_does_not_leak_token_value() {
    let fx = fx();
    let token = fx.token("debug-safety", TokenSpec::api_key());
    let dbg = format!("{token:?}");

    assert!(dbg.contains("TokenFixture"));
    assert!(dbg.contains("debug-safety"));
    assert!(
        !dbg.contains(token.value()),
        "Debug output must NOT contain token value"
    );
    assert!(
        dbg.contains(".."),
        "Debug should use finish_non_exhaustive()"
    );
}

// =========================================================================
// OAuth JWT structure
// =========================================================================

#[test]
fn oauth_jwt_header_has_alg_and_typ() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let fx = fx();
    let token = fx.token("oauth-jwt", TokenSpec::oauth_access_token());
    let parts: Vec<&str> = token.value().split('.').collect();
    assert_eq!(parts.len(), 3);

    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).expect("decode header");
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("parse header");

    assert!(header["alg"].is_string(), "JWT header should have 'alg'");
    assert!(header["typ"].is_string(), "JWT header should have 'typ'");
}

#[test]
fn oauth_jwt_payload_has_sub_matching_label() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let fx = fx();
    let token = fx.token("oauth-claims", TokenSpec::oauth_access_token());
    let parts: Vec<&str> = token.value().split('.').collect();

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("decode payload");
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).expect("parse payload");

    assert_eq!(
        payload["sub"], "oauth-claims",
        "JWT sub should match the label"
    );
    assert_eq!(payload["iss"], "uselesskey", "JWT iss should be uselesskey");
}
