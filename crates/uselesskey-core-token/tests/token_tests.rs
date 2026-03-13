use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;
use uselesskey_core_seed::Seed;

use uselesskey_core_token::{
    API_KEY_PREFIX, API_KEY_RANDOM_LEN, BEARER_RANDOM_BYTES, OAUTH_JTI_BYTES,
    OAUTH_SIGNATURE_BYTES, TokenKind, authorization_scheme, generate_api_key,
    generate_bearer_token, generate_oauth_access_token, generate_token, random_base62,
};

// ─── TokenKind construction & equality ───────────────────────────────────

#[test]
fn token_kind_variants_are_distinct() {
    assert_ne!(TokenKind::ApiKey, TokenKind::Bearer);
    assert_ne!(TokenKind::ApiKey, TokenKind::OAuthAccessToken);
    assert_ne!(TokenKind::Bearer, TokenKind::OAuthAccessToken);
}

#[test]
fn token_kind_clone_is_equal() {
    let kinds = [
        TokenKind::ApiKey,
        TokenKind::Bearer,
        TokenKind::OAuthAccessToken,
    ];
    for kind in &kinds {
        assert_eq!(*kind, (*kind).clone());
    }
}

#[test]
fn token_kind_copy_semantics() {
    let kind = TokenKind::ApiKey;
    let copied = kind;
    assert_eq!(kind, copied);
}

#[test]
fn token_kind_hash_consistency() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(TokenKind::ApiKey);
    set.insert(TokenKind::Bearer);
    set.insert(TokenKind::OAuthAccessToken);
    assert_eq!(set.len(), 3);

    // Inserting duplicates doesn't change size.
    set.insert(TokenKind::ApiKey);
    assert_eq!(set.len(), 3);
}

// ─── Debug formatting ────────────────────────────────────────────────────

#[test]
fn debug_format_api_key() {
    let dbg = format!("{:?}", TokenKind::ApiKey);
    assert_eq!(dbg, "ApiKey");
}

#[test]
fn debug_format_bearer() {
    let dbg = format!("{:?}", TokenKind::Bearer);
    assert_eq!(dbg, "Bearer");
}

#[test]
fn debug_format_oauth() {
    let dbg = format!("{:?}", TokenKind::OAuthAccessToken);
    assert_eq!(dbg, "OAuthAccessToken");
}

// ─── Constants ───────────────────────────────────────────────────────────

#[test]
fn api_key_prefix_is_expected() {
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

// ─── authorization_scheme mapping ────────────────────────────────────────

#[test]
fn authorization_scheme_api_key() {
    assert_eq!(authorization_scheme(TokenKind::ApiKey), "ApiKey");
}

#[test]
fn authorization_scheme_bearer() {
    assert_eq!(authorization_scheme(TokenKind::Bearer), "Bearer");
}

#[test]
fn authorization_scheme_oauth_uses_bearer() {
    assert_eq!(authorization_scheme(TokenKind::OAuthAccessToken), "Bearer");
}

// ─── API key generation ──────────────────────────────────────────────────

#[test]
fn api_key_starts_with_prefix() {
    let rng = Seed::new([1u8; 32]);
    let key = generate_api_key(rng);
    assert!(key.starts_with(API_KEY_PREFIX));
}

#[test]
fn api_key_suffix_is_correct_length() {
    let rng = Seed::new([2u8; 32]);
    let key = generate_api_key(rng);
    let suffix = key.strip_prefix(API_KEY_PREFIX).unwrap();
    assert_eq!(suffix.len(), API_KEY_RANDOM_LEN);
}

#[test]
fn api_key_suffix_is_alphanumeric() {
    let rng = Seed::new([3u8; 32]);
    let key = generate_api_key(rng);
    let suffix = key.strip_prefix(API_KEY_PREFIX).unwrap();
    assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn api_key_total_length() {
    let rng = Seed::new([4u8; 32]);
    let key = generate_api_key(rng);
    assert_eq!(key.len(), API_KEY_PREFIX.len() + API_KEY_RANDOM_LEN);
}

// ─── Bearer token generation ─────────────────────────────────────────────

#[test]
fn bearer_token_is_valid_base64url() {
    let rng = Seed::new([5u8; 32]);
    let token = generate_bearer_token(rng);
    let decoded = URL_SAFE_NO_PAD.decode(&token);
    assert!(decoded.is_ok(), "bearer token should be valid base64url");
}

#[test]
fn bearer_token_decodes_to_correct_length() {
    let rng = Seed::new([6u8; 32]);
    let token = generate_bearer_token(rng);
    let decoded = URL_SAFE_NO_PAD.decode(&token).unwrap();
    assert_eq!(decoded.len(), BEARER_RANDOM_BYTES);
}

#[test]
fn bearer_token_string_length_is_43() {
    // 32 bytes → ceil(32*4/3) = 43 base64url chars (no padding).
    let rng = Seed::new([7u8; 32]);
    let token = generate_bearer_token(rng);
    assert_eq!(token.len(), 43);
}

// ─── OAuth access token generation ───────────────────────────────────────

#[test]
fn oauth_token_has_three_dot_separated_segments() {
    let rng = Seed::new([8u8; 32]);
    let token = generate_oauth_access_token("test-svc", rng);
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
}

#[test]
fn oauth_header_is_rs256_jwt() {
    let rng = Seed::new([9u8; 32]);
    let token = generate_oauth_access_token("issuer", rng);
    let header_segment = token.split('.').next().unwrap();
    let header_bytes = URL_SAFE_NO_PAD.decode(header_segment).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "JWT");
}

#[test]
fn oauth_payload_contains_expected_claims() {
    let rng = Seed::new([10u8; 32]);
    let token = generate_oauth_access_token("my-service", rng);
    let parts: Vec<&str> = token.split('.').collect();
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    assert_eq!(payload["iss"], "uselesskey");
    assert_eq!(payload["sub"], "my-service");
    assert_eq!(payload["aud"], "tests");
    assert_eq!(payload["scope"], "fixture.read");
    assert_eq!(payload["exp"], 2_000_000_000u64);
    assert!(payload["jti"].is_string());
}

#[test]
fn oauth_payload_sub_matches_label() {
    let rng = Seed::new([11u8; 32]);
    let token = generate_oauth_access_token("custom-label", rng);
    let parts: Vec<&str> = token.split('.').collect();
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(payload["sub"], "custom-label");
}

#[test]
fn oauth_signature_segment_is_valid_base64url() {
    let rng = Seed::new([12u8; 32]);
    let token = generate_oauth_access_token("test", rng);
    let sig = token.split('.').nth(2).unwrap();
    let decoded = URL_SAFE_NO_PAD.decode(sig);
    assert!(decoded.is_ok());
    assert_eq!(decoded.unwrap().len(), OAUTH_SIGNATURE_BYTES);
}

// ─── generate_token dispatch ─────────────────────────────────────────────

#[test]
fn generate_token_api_key_matches_direct_call() {
    let seed = [20u8; 32];
    let rng1 = Seed::new(seed);
    let rng2 = Seed::new(seed);

    let via_dispatch = generate_token("lbl", TokenKind::ApiKey, rng1);
    let via_direct = generate_api_key(rng2);
    assert_eq!(via_dispatch, via_direct);
}

#[test]
fn generate_token_bearer_matches_direct_call() {
    let seed = [21u8; 32];
    let rng1 = Seed::new(seed);
    let rng2 = Seed::new(seed);

    let via_dispatch = generate_token("lbl", TokenKind::Bearer, rng1);
    let via_direct = generate_bearer_token(rng2);
    assert_eq!(via_dispatch, via_direct);
}

#[test]
fn generate_token_oauth_matches_direct_call() {
    let seed = [22u8; 32];
    let rng1 = Seed::new(seed);
    let rng2 = Seed::new(seed);

    let via_dispatch = generate_token("lbl", TokenKind::OAuthAccessToken, rng1);
    let via_direct = generate_oauth_access_token("lbl", rng2);
    assert_eq!(via_dispatch, via_direct);
}

#[test]
fn generate_token_different_kinds_produce_different_output() {
    let seed = [23u8; 32];
    let api = generate_token("x", TokenKind::ApiKey, Seed::new(seed));
    let bearer = generate_token("x", TokenKind::Bearer, Seed::new(seed));
    let oauth = generate_token("x", TokenKind::OAuthAccessToken, Seed::new(seed));

    assert_ne!(api, bearer);
    assert_ne!(api, oauth);
    assert_ne!(bearer, oauth);
}

// ─── Determinism: same seed → same output ────────────────────────────────

#[test]
fn api_key_deterministic_with_same_seed() {
    let seed = [30u8; 32];
    let a = generate_api_key(Seed::new(seed));
    let b = generate_api_key(Seed::new(seed));
    assert_eq!(a, b);
}

#[test]
fn bearer_deterministic_with_same_seed() {
    let seed = [31u8; 32];
    let a = generate_bearer_token(Seed::new(seed));
    let b = generate_bearer_token(Seed::new(seed));
    assert_eq!(a, b);
}

#[test]
fn oauth_deterministic_with_same_seed() {
    let seed = [32u8; 32];
    let a = generate_oauth_access_token("svc", Seed::new(seed));
    let b = generate_oauth_access_token("svc", Seed::new(seed));
    assert_eq!(a, b);
}

// ─── Different seeds → different output ──────────────────────────────────

#[test]
fn different_seeds_produce_different_api_keys() {
    let a = generate_api_key(Seed::new([40u8; 32]));
    let b = generate_api_key(Seed::new([41u8; 32]));
    assert_ne!(a, b);
}

#[test]
fn different_seeds_produce_different_bearer_tokens() {
    let a = generate_bearer_token(Seed::new([42u8; 32]));
    let b = generate_bearer_token(Seed::new([43u8; 32]));
    assert_ne!(a, b);
}

#[test]
fn different_seeds_produce_different_oauth_tokens() {
    let a = generate_oauth_access_token("svc", Seed::new([44u8; 32]));
    let b = generate_oauth_access_token("svc", Seed::new([45u8; 32]));
    assert_ne!(a, b);
}

// ─── random_base62 ───────────────────────────────────────────────────────

#[test]
fn random_base62_zero_length() {
    let rng = Seed::new([50u8; 32]);
    let s = random_base62(rng, 0);
    assert!(s.is_empty());
}

#[test]
fn random_base62_one_char() {
    let rng = Seed::new([51u8; 32]);
    let s = random_base62(rng, 1);
    assert_eq!(s.len(), 1);
    assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn random_base62_large_length() {
    let rng = Seed::new([52u8; 32]);
    let s = random_base62(rng, 1000);
    assert_eq!(s.len(), 1000);
    assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn random_base62_deterministic() {
    let seed = [53u8; 32];
    let a = random_base62(Seed::new(seed), 64);
    let b = random_base62(Seed::new(seed), 64);
    assert_eq!(a, b);
}

#[test]
fn random_base62_different_seeds_differ() {
    let a = random_base62(Seed::new([54u8; 32]), 64);
    let b = random_base62(Seed::new([55u8; 32]), 64);
    assert_ne!(a, b);
}

// ─── OAuth with different labels ─────────────────────────────────────────

#[test]
fn oauth_different_labels_different_sub_claim() {
    let seed = [60u8; 32];
    let t1 = generate_oauth_access_token("alice", Seed::new(seed));
    let t2 = generate_oauth_access_token("bob", Seed::new(seed));

    let payload1: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(t1.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    let payload2: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(t2.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();

    assert_eq!(payload1["sub"], "alice");
    assert_eq!(payload2["sub"], "bob");
}

#[test]
fn oauth_same_label_same_seed_has_same_jti() {
    let seed = [61u8; 32];
    let t1 = generate_oauth_access_token("svc", Seed::new(seed));
    let t2 = generate_oauth_access_token("svc", Seed::new(seed));

    let jti1 = extract_jti(&t1);
    let jti2 = extract_jti(&t2);
    assert_eq!(jti1, jti2, "same seed+label → same jti");
}

fn extract_jti(token: &str) -> String {
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(token.split('.').nth(1).unwrap())
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    payload["jti"].as_str().unwrap().to_string()
}

// ─── Property-based tests ────────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_api_key_same_seed_same_output(seed in any::<[u8; 32]>()) {
        let a = generate_api_key(Seed::new(seed));
        let b = generate_api_key(Seed::new(seed));
        prop_assert_eq!(a, b);
    }

    #[test]
    fn prop_bearer_same_seed_same_output(seed in any::<[u8; 32]>()) {
        let a = generate_bearer_token(Seed::new(seed));
        let b = generate_bearer_token(Seed::new(seed));
        prop_assert_eq!(a, b);
    }

    #[test]
    fn prop_oauth_same_seed_same_output(
        seed in any::<[u8; 32]>(),
        label in "[a-z0-9_-]{1,16}"
    ) {
        let a = generate_oauth_access_token(&label, Seed::new(seed));
        let b = generate_oauth_access_token(&label, Seed::new(seed));
        prop_assert_eq!(a, b);
    }

    #[test]
    fn prop_different_seeds_different_api_keys(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>()
    ) {
        prop_assume!(seed_a != seed_b);
        let a = generate_api_key(Seed::new(seed_a));
        let b = generate_api_key(Seed::new(seed_b));
        prop_assert_ne!(a, b);
    }

    #[test]
    fn prop_different_seeds_different_bearer_tokens(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>()
    ) {
        prop_assume!(seed_a != seed_b);
        let a = generate_bearer_token(Seed::new(seed_a));
        let b = generate_bearer_token(Seed::new(seed_b));
        prop_assert_ne!(a, b);
    }

    #[test]
    fn prop_api_key_always_has_prefix_and_correct_length(seed in any::<[u8; 32]>()) {
        let key = generate_api_key(Seed::new(seed));
        prop_assert!(key.starts_with(API_KEY_PREFIX));
        let suffix = &key[API_KEY_PREFIX.len()..];
        prop_assert_eq!(suffix.len(), API_KEY_RANDOM_LEN);
        prop_assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn prop_bearer_always_43_chars_valid_base64url(seed in any::<[u8; 32]>()) {
        let token = generate_bearer_token(Seed::new(seed));
        prop_assert_eq!(token.len(), 43);
        let decoded = URL_SAFE_NO_PAD.decode(&token);
        prop_assert!(decoded.is_ok());
        prop_assert_eq!(decoded.unwrap().len(), BEARER_RANDOM_BYTES);
    }

    #[test]
    fn prop_oauth_always_three_segments(
        seed in any::<[u8; 32]>(),
        label in "[a-z0-9_-]{1,16}"
    ) {
        let token = generate_oauth_access_token(&label, Seed::new(seed));
        prop_assert_eq!(token.matches('.').count(), 2);
    }

    #[test]
    fn prop_random_base62_correct_length_and_charset(
        seed in any::<[u8; 32]>(),
        len in 0usize..256
    ) {
        let s = random_base62(Seed::new(seed), len);
        prop_assert_eq!(s.len(), len);
        prop_assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
