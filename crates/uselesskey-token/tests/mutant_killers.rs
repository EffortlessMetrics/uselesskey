//! Mutation-hardening pins for `TokenSpec`.
//!
//! These tests pin the exact-value behaviour of `TokenSpec` constructors,
//! kind-name strings, stable byte encoding, and authorization scheme
//! mapping. The values are part of the public derivation contract — a silent
//! change here would invalidate caches and JWT-shaped fixtures downstream,
//! so any mutation must be intentional and accompanied by a derivation
//! version bump (see `crates/uselesskey-core` derivation policy).
//!
//! Mirrors the existing pattern in `uselesskey-rsa`, `uselesskey-ecdsa`,
//! `uselesskey-ed25519`, and `uselesskey-pgp` `tests/mutant_killers.rs`.

use uselesskey_token::TokenSpec;

#[test]
fn constructors_return_correct_variants() {
    assert_eq!(TokenSpec::api_key(), TokenSpec::ApiKey);
    assert_eq!(TokenSpec::bearer(), TokenSpec::Bearer);
    assert_eq!(TokenSpec::oauth_access_token(), TokenSpec::OAuthAccessToken);
}

#[test]
fn kind_names_exact() {
    assert_eq!(TokenSpec::ApiKey.kind_name(), "api_key");
    assert_eq!(TokenSpec::Bearer.kind_name(), "bearer");
    assert_eq!(
        TokenSpec::OAuthAccessToken.kind_name(),
        "oauth_access_token"
    );
}

#[test]
fn stable_bytes_exact() {
    // The exact byte encoding feeds into the per-process cache key and the
    // deterministic derivation. Treat this as a load-bearing contract.
    assert_eq!(TokenSpec::ApiKey.stable_bytes(), [0, 0, 0, 1]);
    assert_eq!(TokenSpec::Bearer.stable_bytes(), [0, 0, 0, 2]);
    assert_eq!(TokenSpec::OAuthAccessToken.stable_bytes(), [0, 0, 0, 3]);
}

#[test]
fn authorization_scheme_exact() {
    assert_eq!(TokenSpec::ApiKey.authorization_scheme(), "ApiKey");
    assert_eq!(TokenSpec::Bearer.authorization_scheme(), "Bearer");
    assert_eq!(TokenSpec::OAuthAccessToken.authorization_scheme(), "Bearer");
}
