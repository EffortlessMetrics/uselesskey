//! Mutant-killing tests for token shape generation.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uselesskey_core_seed::Seed;
use uselesskey_core_token_shape::{
    API_KEY_PREFIX, API_KEY_RANDOM_LEN, BEARER_RANDOM_BYTES, OAUTH_JTI_BYTES,
    OAUTH_SIGNATURE_BYTES, TokenKind, authorization_scheme, generate_api_key,
    generate_bearer_token, generate_oauth_access_token, generate_token,
};

#[test]
fn api_key_prefix_exact() {
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

#[test]
fn authorization_scheme_api_key() {
    assert_eq!(authorization_scheme(TokenKind::ApiKey), "ApiKey");
}

#[test]
fn authorization_scheme_bearer() {
    assert_eq!(authorization_scheme(TokenKind::Bearer), "Bearer");
}

#[test]
fn authorization_scheme_oauth_is_bearer() {
    assert_eq!(authorization_scheme(TokenKind::OAuthAccessToken), "Bearer");
}

#[test]
fn api_key_exact_length() {
    let rng = Seed::new([1u8; 32]);
    let key = generate_api_key(rng);
    assert_eq!(key.len(), API_KEY_PREFIX.len() + API_KEY_RANDOM_LEN);
}

#[test]
fn api_key_starts_with_prefix() {
    let rng = Seed::new([2u8; 32]);
    let key = generate_api_key(rng);
    assert!(key.starts_with(API_KEY_PREFIX));
}

#[test]
fn api_key_suffix_is_alphanumeric() {
    let rng = Seed::new([3u8; 32]);
    let key = generate_api_key(rng);
    let suffix = &key[API_KEY_PREFIX.len()..];
    assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn bearer_token_length_is_43() {
    // 32 bytes base64url = ceil(32 * 4 / 3) = 43 chars (no padding)
    let rng = Seed::new([4u8; 32]);
    let token = generate_bearer_token(rng);
    assert_eq!(token.len(), 43);
}

#[test]
fn bearer_token_decodes_to_32_bytes() {
    let rng = Seed::new([5u8; 32]);
    let token = generate_bearer_token(rng);
    let decoded = URL_SAFE_NO_PAD.decode(&token).unwrap();
    assert_eq!(decoded.len(), BEARER_RANDOM_BYTES);
}

#[test]
fn oauth_token_has_exactly_three_segments() {
    let rng = Seed::new([6u8; 32]);
    let token = generate_oauth_access_token("test-label", rng);
    let segments: Vec<&str> = token.split('.').collect();
    assert_eq!(segments.len(), 3);
}

#[test]
fn oauth_header_decodes_to_rs256_jwt() {
    let rng = Seed::new([7u8; 32]);
    let token = generate_oauth_access_token("test-label", rng);
    let header_segment = token.split('.').next().unwrap();
    let header_bytes = URL_SAFE_NO_PAD.decode(header_segment).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "JWT");
}

#[test]
fn oauth_payload_contains_expected_claims() {
    let rng = Seed::new([8u8; 32]);
    let token = generate_oauth_access_token("my-service", rng);
    let payload_segment = token.split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    assert_eq!(payload["iss"], "uselesskey");
    assert_eq!(payload["sub"], "my-service");
    assert_eq!(payload["aud"], "tests");
    assert_eq!(payload["scope"], "fixture.read");
    assert_eq!(payload["exp"], 2_000_000_000u64);
    assert!(payload["jti"].is_string());
}

#[test]
fn generate_token_dispatches_correctly() {
    let seed = [9u8; 32];

    let rng1 = Seed::new(seed);
    let via_dispatch = generate_token("label", TokenKind::ApiKey, rng1);

    let rng2 = Seed::new(seed);
    let via_direct = generate_api_key(rng2);

    assert_eq!(via_dispatch, via_direct);
}

#[test]
fn generate_token_bearer_dispatch() {
    let seed = [10u8; 32];

    let rng1 = Seed::new(seed);
    let via_dispatch = generate_token("label", TokenKind::Bearer, rng1);

    let rng2 = Seed::new(seed);
    let via_direct = generate_bearer_token(rng2);

    assert_eq!(via_dispatch, via_direct);
}

#[test]
fn generate_token_oauth_dispatch() {
    let seed = [11u8; 32];

    let rng1 = Seed::new(seed);
    let via_dispatch = generate_token("label", TokenKind::OAuthAccessToken, rng1);

    let rng2 = Seed::new(seed);
    let via_direct = generate_oauth_access_token("label", rng2);

    assert_eq!(via_dispatch, via_direct);
}
