use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

use uselesskey_core_token::{
    API_KEY_PREFIX, API_KEY_RANDOM_LEN, BEARER_RANDOM_BYTES, OAUTH_JTI_BYTES,
    OAUTH_SIGNATURE_BYTES, TokenKind, authorization_scheme, generate_api_key,
    generate_bearer_token, generate_oauth_access_token, generate_token, random_base62,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn api_key_prefix_is_expected_value() {
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

// ---------------------------------------------------------------------------
// TokenKind traits
// ---------------------------------------------------------------------------

#[test]
fn token_kind_debug_representation() {
    assert_eq!(format!("{:?}", TokenKind::ApiKey), "ApiKey");
    assert_eq!(format!("{:?}", TokenKind::Bearer), "Bearer");
    assert_eq!(
        format!("{:?}", TokenKind::OAuthAccessToken),
        "OAuthAccessToken"
    );
}

#[test]
fn token_kind_clone_and_eq() {
    let original = TokenKind::Bearer;
    let cloned = original;
    assert_eq!(original, cloned);
}

#[test]
fn token_kind_hash_consistency() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(TokenKind::ApiKey);
    set.insert(TokenKind::Bearer);
    set.insert(TokenKind::OAuthAccessToken);
    assert_eq!(set.len(), 3);

    // Inserting duplicates should not grow the set.
    set.insert(TokenKind::ApiKey);
    assert_eq!(set.len(), 3);
}

// ---------------------------------------------------------------------------
// API key generation
// ---------------------------------------------------------------------------

#[test]
fn api_key_has_correct_prefix() {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let key = generate_api_key(&mut rng);
    assert!(key.starts_with(API_KEY_PREFIX));
}

#[test]
fn api_key_total_length() {
    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    let key = generate_api_key(&mut rng);
    // prefix (8 chars "uk_test_") + 32 random base62 chars = 40
    assert_eq!(key.len(), API_KEY_PREFIX.len() + API_KEY_RANDOM_LEN);
    assert_eq!(key.len(), 40);
}

#[test]
fn api_key_suffix_is_base62() {
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    let key = generate_api_key(&mut rng);
    let suffix = key.strip_prefix(API_KEY_PREFIX).unwrap();
    assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn api_key_deterministic_across_calls() {
    let seed = [42u8; 32];
    let a = generate_api_key(&mut ChaCha20Rng::from_seed(seed));
    let b = generate_api_key(&mut ChaCha20Rng::from_seed(seed));
    assert_eq!(a, b);
}

#[test]
fn api_key_different_seeds_differ() {
    let a = generate_api_key(&mut ChaCha20Rng::from_seed([10u8; 32]));
    let b = generate_api_key(&mut ChaCha20Rng::from_seed([11u8; 32]));
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// Bearer token generation
// ---------------------------------------------------------------------------

#[test]
fn bearer_token_is_base64url() {
    let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
    let token = generate_bearer_token(&mut rng);
    // Must decode without error.
    let decoded = URL_SAFE_NO_PAD.decode(&token).expect("valid base64url");
    assert_eq!(decoded.len(), BEARER_RANDOM_BYTES);
}

#[test]
fn bearer_token_length_is_43() {
    // base64url of 32 bytes without padding = ceil(32*4/3) = 43 chars
    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
    let token = generate_bearer_token(&mut rng);
    assert_eq!(token.len(), 43);
}

#[test]
fn bearer_token_contains_no_padding() {
    let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
    let token = generate_bearer_token(&mut rng);
    assert!(!token.contains('='));
}

#[test]
fn bearer_token_deterministic() {
    let seed = [50u8; 32];
    let a = generate_bearer_token(&mut ChaCha20Rng::from_seed(seed));
    let b = generate_bearer_token(&mut ChaCha20Rng::from_seed(seed));
    assert_eq!(a, b);
}

#[test]
fn bearer_token_different_seeds_differ() {
    let a = generate_bearer_token(&mut ChaCha20Rng::from_seed([20u8; 32]));
    let b = generate_bearer_token(&mut ChaCha20Rng::from_seed([21u8; 32]));
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// OAuth access token generation
// ---------------------------------------------------------------------------

#[test]
fn oauth_token_has_three_dot_separated_segments() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let token = generate_oauth_access_token("svc", &mut rng);
    let segments: Vec<&str> = token.split('.').collect();
    assert_eq!(segments.len(), 3);
}

#[test]
fn oauth_token_header_is_jwt_rs256() {
    let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
    let token = generate_oauth_access_token("svc", &mut rng);
    let header_segment = token.split('.').next().unwrap();
    let header_bytes = URL_SAFE_NO_PAD.decode(header_segment).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "JWT");
}

#[test]
fn oauth_token_payload_contains_expected_claims() {
    let label = "my-service";
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let token = generate_oauth_access_token(label, &mut rng);
    let payload_segment = token.split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    assert_eq!(payload["iss"], "uselesskey");
    assert_eq!(payload["sub"], label);
    assert_eq!(payload["aud"], "tests");
    assert_eq!(payload["scope"], "fixture.read");
    assert_eq!(payload["exp"], 2_000_000_000u64);
    assert!(payload["jti"].is_string());
}

#[test]
fn oauth_token_jti_is_base64url_of_16_bytes() {
    let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
    let token = generate_oauth_access_token("svc", &mut rng);
    let payload_segment = token.split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    let jti = payload["jti"].as_str().unwrap();
    let jti_bytes = URL_SAFE_NO_PAD.decode(jti).unwrap();
    assert_eq!(jti_bytes.len(), OAUTH_JTI_BYTES);
}

#[test]
fn oauth_token_signature_segment_is_base64url_of_32_bytes() {
    let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
    let token = generate_oauth_access_token("svc", &mut rng);
    let sig_segment = token.split('.').nth(2).unwrap();
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_segment).unwrap();
    assert_eq!(sig_bytes.len(), OAUTH_SIGNATURE_BYTES);
}

#[test]
fn oauth_token_deterministic() {
    let seed = [60u8; 32];
    let a = generate_oauth_access_token("x", &mut ChaCha20Rng::from_seed(seed));
    let b = generate_oauth_access_token("x", &mut ChaCha20Rng::from_seed(seed));
    assert_eq!(a, b);
}

#[test]
fn oauth_token_label_affects_payload() {
    let seed = [70u8; 32];
    let a = generate_oauth_access_token("alpha", &mut ChaCha20Rng::from_seed(seed));
    let b = generate_oauth_access_token("beta", &mut ChaCha20Rng::from_seed(seed));
    // Same seed but different label means the payload (subject) differs.
    let payload_a = a.split('.').nth(1).unwrap();
    let payload_b = b.split('.').nth(1).unwrap();
    assert_ne!(payload_a, payload_b);
}

#[test]
fn oauth_token_empty_label() {
    let mut rng = ChaCha20Rng::from_seed([80u8; 32]);
    let token = generate_oauth_access_token("", &mut rng);
    let payload_segment = token.split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(payload["sub"], "");
}

// ---------------------------------------------------------------------------
// generate_token dispatch
// ---------------------------------------------------------------------------

#[test]
fn generate_token_dispatches_api_key() {
    let seed = [30u8; 32];
    let via_dispatch = generate_token("lbl", TokenKind::ApiKey, &mut ChaCha20Rng::from_seed(seed));
    let via_direct = generate_api_key(&mut ChaCha20Rng::from_seed(seed));
    assert_eq!(via_dispatch, via_direct);
}

#[test]
fn generate_token_dispatches_bearer() {
    let seed = [31u8; 32];
    let via_dispatch = generate_token("lbl", TokenKind::Bearer, &mut ChaCha20Rng::from_seed(seed));
    let via_direct = generate_bearer_token(&mut ChaCha20Rng::from_seed(seed));
    assert_eq!(via_dispatch, via_direct);
}

#[test]
fn generate_token_dispatches_oauth() {
    let seed = [32u8; 32];
    let via_dispatch = generate_token(
        "lbl",
        TokenKind::OAuthAccessToken,
        &mut ChaCha20Rng::from_seed(seed),
    );
    let via_direct = generate_oauth_access_token("lbl", &mut ChaCha20Rng::from_seed(seed));
    assert_eq!(via_dispatch, via_direct);
}

// ---------------------------------------------------------------------------
// authorization_scheme
// ---------------------------------------------------------------------------

#[test]
fn authorization_scheme_api_key() {
    assert_eq!(authorization_scheme(TokenKind::ApiKey), "ApiKey");
}

#[test]
fn authorization_scheme_bearer() {
    assert_eq!(authorization_scheme(TokenKind::Bearer), "Bearer");
}

#[test]
fn authorization_scheme_oauth() {
    assert_eq!(authorization_scheme(TokenKind::OAuthAccessToken), "Bearer");
}

// ---------------------------------------------------------------------------
// random_base62
// ---------------------------------------------------------------------------

#[test]
fn random_base62_zero_length() {
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let value = random_base62(&mut rng, 0);
    assert!(value.is_empty());
}

#[test]
fn random_base62_length_one() {
    let mut rng = ChaCha20Rng::from_seed([100u8; 32]);
    let value = random_base62(&mut rng, 1);
    assert_eq!(value.len(), 1);
    assert!(value.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn random_base62_exact_length() {
    let mut rng = ChaCha20Rng::from_seed([101u8; 32]);
    for len in [1, 2, 10, 63, 64, 65, 128, 256] {
        let value = random_base62(&mut rng, len);
        assert_eq!(value.len(), len, "expected length {len}");
    }
}

#[test]
fn random_base62_charset_only_alphanumeric() {
    let mut rng = ChaCha20Rng::from_seed([102u8; 32]);
    let value = random_base62(&mut rng, 200);
    assert!(value.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn random_base62_deterministic() {
    let seed = [103u8; 32];
    let a = random_base62(&mut ChaCha20Rng::from_seed(seed), 50);
    let b = random_base62(&mut ChaCha20Rng::from_seed(seed), 50);
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Cross-kind uniqueness
// ---------------------------------------------------------------------------

#[test]
fn all_three_kinds_produce_different_output_same_seed() {
    let seed = [55u8; 32];
    let api = generate_token("t", TokenKind::ApiKey, &mut ChaCha20Rng::from_seed(seed));
    let bearer = generate_token("t", TokenKind::Bearer, &mut ChaCha20Rng::from_seed(seed));
    let oauth = generate_token(
        "t",
        TokenKind::OAuthAccessToken,
        &mut ChaCha20Rng::from_seed(seed),
    );
    // Different kinds must produce structurally different tokens.
    assert_ne!(api, bearer);
    assert_ne!(api, oauth);
    assert_ne!(bearer, oauth);
}

#[test]
fn api_key_never_looks_like_jwt() {
    let mut rng = ChaCha20Rng::from_seed([66u8; 32]);
    let key = generate_api_key(&mut rng);
    assert!(!key.contains('.'), "API key should not contain dots");
}

#[test]
fn bearer_never_looks_like_jwt() {
    let mut rng = ChaCha20Rng::from_seed([67u8; 32]);
    let token = generate_bearer_token(&mut rng);
    // base64url can contain dots only if padding is present; verify no dots.
    assert!(
        token.matches('.').count() != 2,
        "bearer should not look like a JWT"
    );
}

// ---------------------------------------------------------------------------
// proptest
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_api_key_format(seed in any::<[u8; 32]>()) {
        let key = generate_api_key(&mut ChaCha20Rng::from_seed(seed));
        prop_assert!(key.starts_with(API_KEY_PREFIX));
        prop_assert_eq!(key.len(), 40);
        let suffix = &key[API_KEY_PREFIX.len()..];
        prop_assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn prop_bearer_decodes_to_32_bytes(seed in any::<[u8; 32]>()) {
        let token = generate_bearer_token(&mut ChaCha20Rng::from_seed(seed));
        let decoded = URL_SAFE_NO_PAD.decode(&token).expect("decode");
        prop_assert_eq!(decoded.len(), BEARER_RANDOM_BYTES);
    }

    #[test]
    fn prop_oauth_three_segments_and_valid_json(
        seed in any::<[u8; 32]>(),
        label in "[a-zA-Z0-9_-]{0,32}"
    ) {
        let token = generate_oauth_access_token(&label, &mut ChaCha20Rng::from_seed(seed));
        let parts: Vec<&str> = token.split('.').collect();
        prop_assert_eq!(parts.len(), 3);

        // Header must be valid JSON.
        let h = URL_SAFE_NO_PAD.decode(parts[0]).expect("header decode");
        let _: serde_json::Value = serde_json::from_slice(&h).expect("header json");

        // Payload must be valid JSON containing the label as subject.
        let p = URL_SAFE_NO_PAD.decode(parts[1]).expect("payload decode");
        let pj: serde_json::Value = serde_json::from_slice(&p).expect("payload json");
        prop_assert_eq!(pj["sub"].as_str().unwrap(), label.as_str());
    }

    #[test]
    fn prop_deterministic_generation(
        seed in any::<[u8; 32]>(),
        kind_idx in 0u8..3u8,
        label in "[a-z]{1,8}"
    ) {
        let kind = match kind_idx {
            0 => TokenKind::ApiKey,
            1 => TokenKind::Bearer,
            _ => TokenKind::OAuthAccessToken,
        };
        let a = generate_token(&label, kind, &mut ChaCha20Rng::from_seed(seed));
        let b = generate_token(&label, kind, &mut ChaCha20Rng::from_seed(seed));
        prop_assert_eq!(a, b);
    }

    #[test]
    fn prop_random_base62_always_correct_length(
        seed in any::<[u8; 32]>(),
        len in 0usize..300
    ) {
        let value = random_base62(&mut ChaCha20Rng::from_seed(seed), len);
        prop_assert_eq!(value.len(), len);
        prop_assert!(value.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn prop_different_seeds_produce_different_api_keys(
        s1 in any::<[u8; 32]>(),
        s2 in any::<[u8; 32]>()
    ) {
        prop_assume!(s1 != s2);
        let a = generate_api_key(&mut ChaCha20Rng::from_seed(s1));
        let b = generate_api_key(&mut ChaCha20Rng::from_seed(s2));
        prop_assert_ne!(a, b);
    }
}
