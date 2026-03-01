use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use uselesskey_core_token_shape::{
    API_KEY_PREFIX, API_KEY_RANDOM_LEN, BEARER_RANDOM_BYTES, OAUTH_JTI_BYTES,
    OAUTH_SIGNATURE_BYTES, TokenKind, authorization_scheme, generate_api_key,
    generate_bearer_token, generate_oauth_access_token, generate_token, random_base62,
};

// ---------------------------------------------------------------------------
// 1. Token generation produces non-empty strings
// ---------------------------------------------------------------------------

#[test]
fn api_key_is_non_empty() {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let token = generate_api_key(&mut rng);
    assert!(!token.is_empty());
}

#[test]
fn bearer_token_is_non_empty() {
    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    let token = generate_bearer_token(&mut rng);
    assert!(!token.is_empty());
}

#[test]
fn oauth_token_is_non_empty() {
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    let token = generate_oauth_access_token("svc", &mut rng);
    assert!(!token.is_empty());
}

#[test]
fn generate_token_non_empty_for_all_kinds() {
    for kind in [
        TokenKind::ApiKey,
        TokenKind::Bearer,
        TokenKind::OAuthAccessToken,
    ] {
        let mut rng = ChaCha20Rng::from_seed([4u8; 32]);
        let token = generate_token("lbl", kind, &mut rng);
        assert!(!token.is_empty(), "token for {kind:?} must be non-empty");
    }
}

// ---------------------------------------------------------------------------
// 2. Generated tokens match expected format patterns
// ---------------------------------------------------------------------------

#[test]
fn api_key_has_prefix_and_suffix() {
    let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
    let token = generate_api_key(&mut rng);
    assert!(token.starts_with(API_KEY_PREFIX));
    let suffix = &token[API_KEY_PREFIX.len()..];
    assert_eq!(suffix.len(), API_KEY_RANDOM_LEN);
}

#[test]
fn bearer_token_is_valid_base64url() {
    let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
    let token = generate_bearer_token(&mut rng);
    assert!(
        URL_SAFE_NO_PAD.decode(&token).is_ok(),
        "bearer token must be valid base64url"
    );
}

#[test]
fn oauth_token_is_dot_separated_three_parts() {
    let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
    let token = generate_oauth_access_token("test-subject", &mut rng);
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "OAuth token must have header.payload.signature"
    );
    for (i, part) in parts.iter().enumerate() {
        assert!(
            URL_SAFE_NO_PAD.decode(part).is_ok(),
            "segment {i} must be valid base64url"
        );
    }
}

#[test]
fn oauth_header_contains_expected_alg() {
    let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
    let token = generate_oauth_access_token("x", &mut rng);
    let header_segment = token.split('.').next().unwrap();
    let header_bytes = URL_SAFE_NO_PAD.decode(header_segment).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "JWT");
}

#[test]
fn oauth_payload_contains_required_claims() {
    let mut rng = ChaCha20Rng::from_seed([14u8; 32]);
    let token = generate_oauth_access_token("my-service", &mut rng);
    let payload_segment = token.split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    assert_eq!(claims["iss"], "uselesskey");
    assert_eq!(claims["sub"], "my-service");
    assert_eq!(claims["aud"], "tests");
    assert_eq!(claims["scope"], "fixture.read");
    assert_eq!(claims["exp"], 2_000_000_000u64);
    assert!(claims["jti"].is_string(), "jti must be present as a string");
}

// ---------------------------------------------------------------------------
// 3. Determinism: same RNG seed produces same token
// ---------------------------------------------------------------------------

#[test]
fn api_key_deterministic() {
    let a = generate_api_key(&mut ChaCha20Rng::from_seed([20u8; 32]));
    let b = generate_api_key(&mut ChaCha20Rng::from_seed([20u8; 32]));
    assert_eq!(a, b);
}

#[test]
fn bearer_token_deterministic() {
    let a = generate_bearer_token(&mut ChaCha20Rng::from_seed([21u8; 32]));
    let b = generate_bearer_token(&mut ChaCha20Rng::from_seed([21u8; 32]));
    assert_eq!(a, b);
}

#[test]
fn oauth_token_deterministic() {
    let a = generate_oauth_access_token("svc", &mut ChaCha20Rng::from_seed([22u8; 32]));
    let b = generate_oauth_access_token("svc", &mut ChaCha20Rng::from_seed([22u8; 32]));
    assert_eq!(a, b);
}

#[test]
fn generate_token_deterministic_all_kinds() {
    let seed = [25u8; 32];
    for kind in [
        TokenKind::ApiKey,
        TokenKind::Bearer,
        TokenKind::OAuthAccessToken,
    ] {
        let a = generate_token("lbl", kind, &mut ChaCha20Rng::from_seed(seed));
        let b = generate_token("lbl", kind, &mut ChaCha20Rng::from_seed(seed));
        assert_eq!(a, b, "determinism broken for {kind:?}");
    }
}

// ---------------------------------------------------------------------------
// 4. Different token specs produce different shapes
// ---------------------------------------------------------------------------

#[test]
fn different_kinds_produce_different_tokens() {
    let seed = [30u8; 32];
    let api = generate_token("x", TokenKind::ApiKey, &mut ChaCha20Rng::from_seed(seed));
    let bearer = generate_token("x", TokenKind::Bearer, &mut ChaCha20Rng::from_seed(seed));
    let oauth = generate_token(
        "x",
        TokenKind::OAuthAccessToken,
        &mut ChaCha20Rng::from_seed(seed),
    );

    assert_ne!(api, bearer);
    assert_ne!(api, oauth);
    assert_ne!(bearer, oauth);
}

#[test]
fn different_seeds_produce_different_api_keys() {
    let a = generate_api_key(&mut ChaCha20Rng::from_seed([40u8; 32]));
    let b = generate_api_key(&mut ChaCha20Rng::from_seed([41u8; 32]));
    assert_ne!(a, b);
}

#[test]
fn different_seeds_produce_different_bearer_tokens() {
    let a = generate_bearer_token(&mut ChaCha20Rng::from_seed([50u8; 32]));
    let b = generate_bearer_token(&mut ChaCha20Rng::from_seed([51u8; 32]));
    assert_ne!(a, b);
}

#[test]
fn different_labels_produce_different_oauth_tokens() {
    let seed = [60u8; 32];
    let a = generate_oauth_access_token("alpha", &mut ChaCha20Rng::from_seed(seed));
    let b = generate_oauth_access_token("beta", &mut ChaCha20Rng::from_seed(seed));
    // Same seed but different labels → different payload (sub differs)
    assert_ne!(a, b);
}

#[test]
fn authorization_scheme_api_key_differs_from_bearer() {
    assert_ne!(
        authorization_scheme(TokenKind::ApiKey),
        authorization_scheme(TokenKind::Bearer)
    );
}

// ---------------------------------------------------------------------------
// 5. Token length matches specification
// ---------------------------------------------------------------------------

#[test]
fn api_key_total_length() {
    let mut rng = ChaCha20Rng::from_seed([70u8; 32]);
    let token = generate_api_key(&mut rng);
    assert_eq!(token.len(), API_KEY_PREFIX.len() + API_KEY_RANDOM_LEN);
}

#[test]
fn bearer_token_length_is_43() {
    // base64url of 32 bytes without padding = ceil(32*4/3) = 43 chars
    let mut rng = ChaCha20Rng::from_seed([71u8; 32]);
    let token = generate_bearer_token(&mut rng);
    assert_eq!(token.len(), 43);
}

#[test]
fn bearer_token_decodes_to_expected_bytes() {
    let mut rng = ChaCha20Rng::from_seed([72u8; 32]);
    let token = generate_bearer_token(&mut rng);
    let decoded = URL_SAFE_NO_PAD.decode(&token).unwrap();
    assert_eq!(decoded.len(), BEARER_RANDOM_BYTES);
}

#[test]
fn oauth_signature_segment_decodes_to_expected_bytes() {
    let mut rng = ChaCha20Rng::from_seed([73u8; 32]);
    let token = generate_oauth_access_token("svc", &mut rng);
    let sig_segment = token.split('.').nth(2).unwrap();
    let decoded = URL_SAFE_NO_PAD.decode(sig_segment).unwrap();
    assert_eq!(decoded.len(), OAUTH_SIGNATURE_BYTES);
}

#[test]
fn oauth_jti_has_expected_decoded_length() {
    let mut rng = ChaCha20Rng::from_seed([74u8; 32]);
    let token = generate_oauth_access_token("svc", &mut rng);
    let payload_segment = token.split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    let jti = claims["jti"].as_str().unwrap();
    let jti_decoded = URL_SAFE_NO_PAD.decode(jti).unwrap();
    assert_eq!(jti_decoded.len(), OAUTH_JTI_BYTES);
}

// ---------------------------------------------------------------------------
// 6. Character set verification
// ---------------------------------------------------------------------------

#[test]
fn api_key_suffix_is_alphanumeric() {
    let mut rng = ChaCha20Rng::from_seed([80u8; 32]);
    let token = generate_api_key(&mut rng);
    let suffix = &token[API_KEY_PREFIX.len()..];
    assert!(
        suffix.chars().all(|c| c.is_ascii_alphanumeric()),
        "API key suffix must be base62 (alphanumeric only)"
    );
}

#[test]
fn bearer_token_is_base64url_charset() {
    let mut rng = ChaCha20Rng::from_seed([81u8; 32]);
    let token = generate_bearer_token(&mut rng);
    assert!(
        token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "bearer token must use base64url charset (no padding)"
    );
}

#[test]
fn random_base62_only_alphanumeric() {
    let mut rng = ChaCha20Rng::from_seed([82u8; 32]);
    for len in [0, 1, 10, 100, 256] {
        let s = random_base62(&mut rng, len);
        assert_eq!(s.len(), len);
        assert!(
            s.chars().all(|c| c.is_ascii_alphanumeric()),
            "random_base62({len}) produced non-alphanumeric chars"
        );
    }
}

#[test]
fn random_base62_zero_length() {
    let mut rng = ChaCha20Rng::from_seed([83u8; 32]);
    let s = random_base62(&mut rng, 0);
    assert!(s.is_empty());
}

// ---------------------------------------------------------------------------
// 7. Rejection sampling produces roughly uniform output
// ---------------------------------------------------------------------------

#[test]
fn random_base62_distribution_roughly_uniform() {
    // Generate a large sample and check that all 62 characters appear
    // and no character is grossly over- or under-represented.
    let mut rng = ChaCha20Rng::from_seed([90u8; 32]);
    let sample_len = 62_000;
    let s = random_base62(&mut rng, sample_len);

    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
    }

    // All 62 base62 characters should appear
    assert_eq!(counts.len(), 62, "all 62 base62 characters should appear");

    let expected = sample_len as f64 / 62.0; // ~1000
    for (&ch, &count) in &counts {
        let ratio = count as f64 / expected;
        assert!(
            (0.8..=1.2).contains(&ratio),
            "character '{ch}' count {count} deviates too far from expected {expected:.0} (ratio={ratio:.3})"
        );
    }
}

#[test]
fn random_base62_large_length_is_exact() {
    let mut rng = ChaCha20Rng::from_seed([91u8; 32]);
    let s = random_base62(&mut rng, 1000);
    assert_eq!(s.len(), 1000);
}

// ---------------------------------------------------------------------------
// Property-based tests (proptest)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_api_key_length_matches_spec(seed in any::<[u8; 32]>()) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let token = generate_api_key(&mut rng);
        prop_assert_eq!(token.len(), API_KEY_PREFIX.len() + API_KEY_RANDOM_LEN);
    }

    #[test]
    fn prop_api_key_suffix_is_alphanumeric(seed in any::<[u8; 32]>()) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let token = generate_api_key(&mut rng);
        let suffix = &token[API_KEY_PREFIX.len()..];
        prop_assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn prop_api_key_deterministic(seed in any::<[u8; 32]>()) {
        let a = generate_api_key(&mut ChaCha20Rng::from_seed(seed));
        let b = generate_api_key(&mut ChaCha20Rng::from_seed(seed));
        prop_assert_eq!(a, b);
    }

    #[test]
    fn prop_bearer_token_length_is_43(seed in any::<[u8; 32]>()) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let token = generate_bearer_token(&mut rng);
        prop_assert_eq!(token.len(), 43);
    }

    #[test]
    fn prop_bearer_token_is_valid_base64url(seed in any::<[u8; 32]>()) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let token = generate_bearer_token(&mut rng);
        prop_assert!(URL_SAFE_NO_PAD.decode(&token).is_ok());
    }

    #[test]
    fn prop_bearer_decodes_to_32_bytes(seed in any::<[u8; 32]>()) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let token = generate_bearer_token(&mut rng);
        let decoded = URL_SAFE_NO_PAD.decode(&token).unwrap();
        prop_assert_eq!(decoded.len(), BEARER_RANDOM_BYTES);
    }

    #[test]
    fn prop_oauth_has_three_segments(seed in any::<[u8; 32]>(), label in "[a-z0-9_-]{1,32}") {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let token = generate_oauth_access_token(&label, &mut rng);
        let count = token.split('.').count();
        prop_assert_eq!(count, 3);
    }

    #[test]
    fn prop_oauth_payload_sub_matches_label(seed in any::<[u8; 32]>(), label in "[a-z][a-z0-9_-]{0,15}") {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let token = generate_oauth_access_token(&label, &mut rng);
        let payload_segment = token.split('.').nth(1).unwrap();
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        prop_assert_eq!(claims["sub"].as_str().unwrap(), label.as_str());
    }

    #[test]
    fn prop_random_base62_exact_length(seed in any::<[u8; 32]>(), len in 0usize..512) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let s = random_base62(&mut rng, len);
        prop_assert_eq!(s.len(), len);
    }

    #[test]
    fn prop_random_base62_valid_charset(seed in any::<[u8; 32]>(), len in 1usize..256) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let s = random_base62(&mut rng, len);
        prop_assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn prop_generate_token_deterministic(
        seed in any::<[u8; 32]>(),
        kind_idx in 0u8..3,
    ) {
        let kind = match kind_idx {
            0 => TokenKind::ApiKey,
            1 => TokenKind::Bearer,
            _ => TokenKind::OAuthAccessToken,
        };
        let a = generate_token("lbl", kind, &mut ChaCha20Rng::from_seed(seed));
        let b = generate_token("lbl", kind, &mut ChaCha20Rng::from_seed(seed));
        prop_assert_eq!(a, b);
    }
}
