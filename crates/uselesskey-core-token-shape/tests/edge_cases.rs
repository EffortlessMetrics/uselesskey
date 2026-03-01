//! Integration tests for token shape generation primitives — edge cases,
//! constants, and cross-kind behavior.

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

use uselesskey_core_token_shape::{
    API_KEY_PREFIX, API_KEY_RANDOM_LEN, BEARER_RANDOM_BYTES, OAUTH_JTI_BYTES,
    OAUTH_SIGNATURE_BYTES, TokenKind, authorization_scheme, generate_token, random_base62,
};

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

// ── constant values ──────────────────────────────────────────────────

#[test]
fn api_key_prefix_is_uk_test() {
    assert_eq!(API_KEY_PREFIX, "uk_test_");
}

#[test]
fn api_key_random_len_is_32() {
    assert_eq!(API_KEY_RANDOM_LEN, 32);
}

#[test]
fn bearer_random_bytes_is_32() {
    assert_eq!(BEARER_RANDOM_BYTES, 32);
}

#[test]
fn oauth_jti_bytes_is_16() {
    assert_eq!(OAUTH_JTI_BYTES, 16);
}

#[test]
fn oauth_signature_bytes_is_32() {
    assert_eq!(OAUTH_SIGNATURE_BYTES, 32);
}

// ── TokenKind derives ────────────────────────────────────────────────

#[test]
fn token_kind_debug_format() {
    assert_eq!(format!("{:?}", TokenKind::ApiKey), "ApiKey");
    assert_eq!(format!("{:?}", TokenKind::Bearer), "Bearer");
    assert_eq!(
        format!("{:?}", TokenKind::OAuthAccessToken),
        "OAuthAccessToken"
    );
}

#[test]
fn token_kind_clone_eq() {
    let a = TokenKind::Bearer;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn token_kind_hash_is_usable() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(TokenKind::ApiKey);
    set.insert(TokenKind::Bearer);
    set.insert(TokenKind::OAuthAccessToken);
    assert_eq!(set.len(), 3);
}

// ── random_base62 edge cases ─────────────────────────────────────────

#[test]
fn random_base62_zero_length() {
    let s = random_base62(&mut rng(1), 0);
    assert!(s.is_empty());
}

#[test]
fn random_base62_one_char() {
    let s = random_base62(&mut rng(2), 1);
    assert_eq!(s.len(), 1);
    assert!(s.chars().next().unwrap().is_ascii_alphanumeric());
}

#[test]
fn random_base62_large_length() {
    let s = random_base62(&mut rng(3), 1000);
    assert_eq!(s.len(), 1000);
    assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn random_base62_deterministic() {
    let a = random_base62(&mut rng(4), 50);
    let b = random_base62(&mut rng(4), 50);
    assert_eq!(a, b);
}

// ── cross-kind uniqueness ────────────────────────────────────────────

#[test]
fn same_seed_different_kinds_produce_different_tokens() {
    let api = generate_token("label", TokenKind::ApiKey, &mut rng(20));
    let bearer = generate_token("label", TokenKind::Bearer, &mut rng(20));
    let oauth = generate_token("label", TokenKind::OAuthAccessToken, &mut rng(20));

    assert_ne!(api, bearer);
    assert_ne!(api, oauth);
    assert_ne!(bearer, oauth);
}

// ── authorization_scheme exhaustive ──────────────────────────────────

#[test]
fn authorization_scheme_covers_all_kinds() {
    assert_eq!(authorization_scheme(TokenKind::ApiKey), "ApiKey");
    assert_eq!(authorization_scheme(TokenKind::Bearer), "Bearer");
    assert_eq!(authorization_scheme(TokenKind::OAuthAccessToken), "Bearer");
}

// ── different seeds produce different output ─────────────────────────

#[test]
fn different_seeds_produce_different_api_keys() {
    let a = generate_token("lbl", TokenKind::ApiKey, &mut rng(30));
    let b = generate_token("lbl", TokenKind::ApiKey, &mut rng(31));
    assert_ne!(a, b);
}

#[test]
fn different_seeds_produce_different_bearer_tokens() {
    let a = generate_token("lbl", TokenKind::Bearer, &mut rng(32));
    let b = generate_token("lbl", TokenKind::Bearer, &mut rng(33));
    assert_ne!(a, b);
}
