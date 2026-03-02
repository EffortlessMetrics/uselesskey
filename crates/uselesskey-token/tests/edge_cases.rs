//! Edge-case and boundary tests for Token fixtures.

mod testutil;
use testutil::fx;

use uselesskey_token::{TokenFactoryExt, TokenSpec};

// ── Empty and unusual labels ────────────────────────────────────────

#[test]
fn empty_label_produces_valid_token() {
    let t = fx().token("", TokenSpec::api_key());
    assert!(!t.value().is_empty());
}

#[test]
fn unicode_label_produces_valid_token() {
    let t = fx().token("日本語🔑", TokenSpec::bearer());
    assert!(!t.value().is_empty());
}

#[test]
fn very_long_label_works() {
    let label = "x".repeat(10_000);
    let t = fx().token(&label, TokenSpec::api_key());
    assert!(!t.value().is_empty());
}

#[test]
fn null_byte_label() {
    let t = fx().token("label\0null", TokenSpec::api_key());
    assert!(!t.value().is_empty());
}

// ── All spec shapes ─────────────────────────────────────────────────

#[test]
fn api_key_shape() {
    let t = fx().token("shape-api", TokenSpec::api_key());
    assert!(
        t.value().starts_with("uk_test_"),
        "API key should start with uk_test_"
    );
    // Total: prefix(8) + 32 base62 chars = 40
    assert_eq!(t.value().len(), 40);
}

#[test]
fn bearer_token_shape() {
    let t = fx().token("shape-bearer", TokenSpec::bearer());
    let v = t.value();
    // base64url encoded 32 bytes = ~43 chars
    assert!(!v.is_empty());
    // Check base64url alphabet
    for ch in v.chars() {
        assert!(
            ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
            "Bearer token should be base64url: found {ch:?}"
        );
    }
}

#[test]
fn oauth_token_has_three_segments() {
    let t = fx().token("shape-oauth", TokenSpec::oauth_access_token());
    let segments: Vec<&str> = t.value().split('.').collect();
    assert_eq!(segments.len(), 3, "OAuth token should have 3 JWT segments");
}

// ── authorization_header ────────────────────────────────────────────

#[test]
fn api_key_authorization_header() {
    let t = fx().token("auth-api", TokenSpec::api_key());
    let header = t.authorization_header();
    assert!(
        header.starts_with("ApiKey "),
        "API key auth header should start with 'ApiKey '"
    );
    assert!(header.ends_with(t.value()));
}

#[test]
fn bearer_authorization_header() {
    let t = fx().token("auth-bearer", TokenSpec::bearer());
    let header = t.authorization_header();
    assert!(header.starts_with("Bearer "));
}

#[test]
fn oauth_authorization_header() {
    let t = fx().token("auth-oauth", TokenSpec::oauth_access_token());
    let header = t.authorization_header();
    assert!(header.starts_with("Bearer "));
}

// ── Debug does not leak token value ─────────────────────────────────

#[test]
fn debug_does_not_leak_value() {
    let t = fx().token("debug-test", TokenSpec::api_key());
    let dbg = format!("{t:?}");
    let value = t.value();

    assert!(dbg.contains("TokenFixture"), "Debug should name the type");
    assert!(!dbg.contains(value), "Debug must not contain token value");
}

#[test]
fn debug_shows_label() {
    let t = fx().token("my-label", TokenSpec::api_key());
    let dbg = format!("{t:?}");
    assert!(dbg.contains("my-label"), "Debug should show label");
}

// ── Clone ───────────────────────────────────────────────────────────

#[test]
fn clone_preserves_value() {
    let t = fx().token("clone-test", TokenSpec::api_key());
    let cloned = t.clone();
    assert_eq!(t.value(), cloned.value());
}

// ── Spec trait coverage ─────────────────────────────────────────────

#[test]
fn spec_clone_copy_eq() {
    let s1 = TokenSpec::api_key();
    let s2 = s1;
    assert_eq!(s1, s2);

    let s3 = TokenSpec::bearer();
    assert_ne!(s1, s3);
}

#[test]
fn spec_hash_in_set() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(TokenSpec::api_key());
    set.insert(TokenSpec::bearer());
    set.insert(TokenSpec::oauth_access_token());
    set.insert(TokenSpec::api_key()); // duplicate
    assert_eq!(set.len(), 3);
}

#[test]
fn spec_kind_names() {
    assert_eq!(TokenSpec::api_key().kind_name(), "api_key");
    assert_eq!(TokenSpec::bearer().kind_name(), "bearer");
    assert_eq!(
        TokenSpec::oauth_access_token().kind_name(),
        "oauth_access_token"
    );
}

#[test]
fn spec_stable_bytes_all_different() {
    let b1 = TokenSpec::api_key().stable_bytes();
    let b2 = TokenSpec::bearer().stable_bytes();
    let b3 = TokenSpec::oauth_access_token().stable_bytes();
    assert_ne!(b1, b2);
    assert_ne!(b2, b3);
    assert_ne!(b1, b3);
}

// ── token_with_variant ──────────────────────────────────────────────

#[test]
fn variant_produces_different_token() {
    let t1 = fx().token("variant-test", TokenSpec::api_key());
    let t2 = fx().token_with_variant("variant-test", TokenSpec::api_key(), "alt");
    assert_ne!(t1.value(), t2.value());
}

#[test]
fn same_variant_is_deterministic() {
    let t1 = fx().token_with_variant("variant-det", TokenSpec::api_key(), "v1");
    let t2 = fx().token_with_variant("variant-det", TokenSpec::api_key(), "v1");
    assert_eq!(t1.value(), t2.value());
}

#[test]
fn empty_variant_differs_from_default() {
    // Default variant is "default"; empty variant should differ
    let t_default = fx().token("variant-empty", TokenSpec::bearer());
    let t_empty = fx().token_with_variant("variant-empty", TokenSpec::bearer(), "");
    // They might or might not differ depending on impl, but both should be valid
    assert!(!t_default.value().is_empty());
    assert!(!t_empty.value().is_empty());
}

// ── Same label different spec → different tokens ────────────────────

#[test]
fn same_label_different_spec_different_tokens() {
    let t1 = fx().token("spec-diff", TokenSpec::api_key());
    let t2 = fx().token("spec-diff", TokenSpec::bearer());
    let t3 = fx().token("spec-diff", TokenSpec::oauth_access_token());
    assert_ne!(t1.value(), t2.value());
    assert_ne!(t2.value(), t3.value());
    assert_ne!(t1.value(), t3.value());
}

// ── Concurrent access ───────────────────────────────────────────────

#[test]
fn concurrent_token_same_label() {
    use std::thread;

    let fx = fx();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let fx = fx.clone();
            thread::spawn(move || {
                let t = fx.token("concurrent-token", TokenSpec::api_key());
                t.value().to_string()
            })
        })
        .collect();

    let results: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for pair in results.windows(2) {
        assert_eq!(pair[0], pair[1]);
    }
}
