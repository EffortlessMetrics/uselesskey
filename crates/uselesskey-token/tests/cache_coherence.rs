//! Cache coherence integration tests for Token.

mod testutil;

use testutil::fx;
use uselesskey_token::{TokenFactoryExt, TokenSpec};

#[test]
fn same_label_same_spec_returns_identical_token() {
    let fx = fx();
    let t1 = fx.token("cache-eq", TokenSpec::api_key());
    let t2 = fx.token("cache-eq", TokenSpec::api_key());
    assert_eq!(
        t1.value(),
        t2.value(),
        "same label+spec must return identical token value"
    );
}

#[test]
fn different_labels_produce_different_tokens() {
    let fx = fx();
    let t_a = fx.token("tok-a", TokenSpec::api_key());
    let t_b = fx.token("tok-b", TokenSpec::api_key());
    assert_ne!(
        t_a.value(),
        t_b.value(),
        "different labels must produce different tokens"
    );
}

#[test]
fn different_specs_produce_different_tokens() {
    let fx = fx();
    let t_api = fx.token("spec-diff", TokenSpec::api_key());
    let t_bearer = fx.token("spec-diff", TokenSpec::bearer());
    assert_ne!(
        t_api.value(),
        t_bearer.value(),
        "different specs must produce different tokens"
    );
}

#[test]
fn cache_survives_factory_clone() {
    let fx = fx();
    let _warm = fx.token("tok-clone", TokenSpec::bearer());
    let fx2 = fx.clone();
    let from_clone = fx2.token("tok-clone", TokenSpec::bearer());
    assert_eq!(
        _warm.value(),
        from_clone.value(),
        "cloned factory must share the cache"
    );
}

#[test]
fn api_key_has_expected_prefix() {
    let fx = fx();
    let t = fx.token("prefix-test", TokenSpec::api_key());
    assert!(
        t.value().starts_with("uk_test_"),
        "api key must start with 'uk_test_' prefix, got: {}",
        t.value()
    );
}

#[test]
fn bearer_token_is_non_empty() {
    let fx = fx();
    let t = fx.token("bearer-ne", TokenSpec::bearer());
    assert!(!t.value().is_empty(), "bearer token must not be empty");
}

#[test]
fn authorization_header_contains_token() {
    let fx = fx();
    let t = fx.token("auth-hdr", TokenSpec::bearer());
    let hdr = t.authorization_header();
    assert!(
        hdr.contains(t.value()),
        "authorization header must contain the token value"
    );
}
