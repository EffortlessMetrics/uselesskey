//! Comprehensive shape generation tests — Wave 91.
//!
//! Covers shape generation with various parameters, edge cases
//! (empty/very long labels), character set compliance, and additional
//! property-based tests for format invariants.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use uselesskey_core_token_shape::{
    API_KEY_PREFIX, OAUTH_JTI_BYTES, OAUTH_SIGNATURE_BYTES, TokenKind, authorization_scheme,
    generate_api_key, generate_bearer_token, generate_oauth_access_token, generate_token,
    random_base62,
};

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

// =========================================================================
// 1. Shape generation with various parameters
// =========================================================================

#[test]
fn generate_token_with_all_kinds() {
    for kind in [
        TokenKind::ApiKey,
        TokenKind::Bearer,
        TokenKind::OAuthAccessToken,
    ] {
        let token = generate_token("svc", kind, &mut rng(1));
        assert!(!token.is_empty(), "token for {kind:?} must be non-empty");
    }
}

#[test]
fn generate_token_api_key_matches_generate_api_key() {
    let a = generate_token("label", TokenKind::ApiKey, &mut rng(10));
    let b = generate_api_key(&mut rng(10));
    assert_eq!(a, b);
}

#[test]
fn generate_token_bearer_matches_generate_bearer_token() {
    let a = generate_token("label", TokenKind::Bearer, &mut rng(11));
    let b = generate_bearer_token(&mut rng(11));
    assert_eq!(a, b);
}

#[test]
fn generate_token_oauth_matches_generate_oauth() {
    let a = generate_token("label", TokenKind::OAuthAccessToken, &mut rng(12));
    let b = generate_oauth_access_token("label", &mut rng(12));
    assert_eq!(a, b);
}

// =========================================================================
// 2. Edge cases — labels
// =========================================================================

#[test]
fn oauth_empty_label_produces_valid_token() {
    let token = generate_oauth_access_token("", &mut rng(20));
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(claims["sub"], "");
}

#[test]
fn oauth_very_long_label_produces_valid_token() {
    let long_label = "x".repeat(10_000);
    let token = generate_oauth_access_token(&long_label, &mut rng(21));
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(claims["sub"], long_label);
}

#[test]
fn oauth_unicode_label_produces_valid_token() {
    let token = generate_oauth_access_token("🔑テスト", &mut rng(22));
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(claims["sub"], "🔑テスト");
}

#[test]
fn oauth_label_with_special_json_chars() {
    let label = r#"test"label\with/special"#;
    let token = generate_oauth_access_token(label, &mut rng(23));
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(claims["sub"].as_str().unwrap(), label);
}

// =========================================================================
// 3. Edge cases — random_base62 lengths
// =========================================================================

#[test]
fn random_base62_zero_returns_empty() {
    let s = random_base62(&mut rng(30), 0);
    assert!(s.is_empty());
}

#[test]
fn random_base62_one_is_valid() {
    let s = random_base62(&mut rng(31), 1);
    assert_eq!(s.len(), 1);
    assert!(s.chars().next().unwrap().is_ascii_alphanumeric());
}

#[test]
fn random_base62_exact_boundary_lengths() {
    for len in [62, 63, 64, 127, 128, 255, 256, 512] {
        let s = random_base62(&mut rng(32), len);
        assert_eq!(s.len(), len, "failed for len={len}");
        assert!(
            s.chars().all(|c| c.is_ascii_alphanumeric()),
            "non-base62 chars for len={len}"
        );
    }
}

#[test]
fn random_base62_very_large() {
    let s = random_base62(&mut rng(33), 10_000);
    assert_eq!(s.len(), 10_000);
    assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
}

// =========================================================================
// 4. Character set compliance
// =========================================================================

#[test]
fn api_key_prefix_is_exactly_uk_test_underscore() {
    assert_eq!(API_KEY_PREFIX, "uk_test_");
    assert_eq!(API_KEY_PREFIX.len(), 8);
}

#[test]
fn bearer_token_chars_are_base64url_only() {
    for seed_byte in 0u8..20 {
        let token = generate_bearer_token(&mut rng(seed_byte));
        for ch in token.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "seed={seed_byte}: unexpected char '{ch}' in bearer"
            );
        }
    }
}

#[test]
fn oauth_no_padding_in_any_segment() {
    for seed_byte in 0u8..20 {
        let token = generate_oauth_access_token("svc", &mut rng(seed_byte));
        assert!(
            !token.contains('='),
            "seed={seed_byte}: OAuth must not have padding"
        );
    }
}

// =========================================================================
// 5. Determinism
// =========================================================================

#[test]
fn determinism_across_many_seeds() {
    for seed_byte in 0u8..50 {
        let seed = [seed_byte; 32];
        let a = generate_api_key(&mut ChaCha20Rng::from_seed(seed));
        let b = generate_api_key(&mut ChaCha20Rng::from_seed(seed));
        assert_eq!(a, b, "api key not deterministic for seed_byte={seed_byte}");

        let a = generate_bearer_token(&mut ChaCha20Rng::from_seed(seed));
        let b = generate_bearer_token(&mut ChaCha20Rng::from_seed(seed));
        assert_eq!(a, b, "bearer not deterministic for seed_byte={seed_byte}");

        let a = generate_oauth_access_token("label", &mut ChaCha20Rng::from_seed(seed));
        let b = generate_oauth_access_token("label", &mut ChaCha20Rng::from_seed(seed));
        assert_eq!(a, b, "oauth not deterministic for seed_byte={seed_byte}");
    }
}

// =========================================================================
// 6. OAuth structure — header, payload, signature
// =========================================================================

#[test]
fn oauth_header_is_static_rs256() {
    // The header is always the same static JSON regardless of seed
    let h1 = generate_oauth_access_token("a", &mut rng(40));
    let h2 = generate_oauth_access_token("b", &mut rng(41));

    let header1 = h1.split('.').next().unwrap();
    let header2 = h2.split('.').next().unwrap();
    assert_eq!(header1, header2, "header should be static RS256 JWT");
}

#[test]
fn oauth_signature_segment_length_consistent() {
    for seed_byte in 0u8..20 {
        let token = generate_oauth_access_token("svc", &mut rng(seed_byte));
        let sig = token.split('.').nth(2).unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(sig).unwrap();
        assert_eq!(
            decoded.len(),
            OAUTH_SIGNATURE_BYTES,
            "signature length for seed_byte={seed_byte}"
        );
    }
}

#[test]
fn oauth_jti_length_consistent() {
    for seed_byte in 0u8..20 {
        let token = generate_oauth_access_token("svc", &mut rng(seed_byte));
        let payload_segment = token.split('.').nth(1).unwrap();
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        let jti = claims["jti"].as_str().unwrap();
        let jti_decoded = URL_SAFE_NO_PAD.decode(jti).unwrap();
        assert_eq!(
            jti_decoded.len(),
            OAUTH_JTI_BYTES,
            "jti length for seed_byte={seed_byte}"
        );
    }
}

// =========================================================================
// 7. Authorization scheme exhaustive
// =========================================================================

#[test]
fn authorization_scheme_values() {
    assert_eq!(authorization_scheme(TokenKind::ApiKey), "ApiKey");
    assert_eq!(authorization_scheme(TokenKind::Bearer), "Bearer");
    assert_eq!(authorization_scheme(TokenKind::OAuthAccessToken), "Bearer");
}

// =========================================================================
// 8. Property-based tests — additional invariants
// =========================================================================

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn prop_api_key_never_contains_dots(seed in any::<[u8; 32]>()) {
        let key = generate_api_key(&mut ChaCha20Rng::from_seed(seed));
        prop_assert!(!key.contains('.'), "api key must not contain dots");
    }

    #[test]
    fn prop_bearer_never_contains_dots(seed in any::<[u8; 32]>()) {
        let token = generate_bearer_token(&mut ChaCha20Rng::from_seed(seed));
        prop_assert!(!token.contains('.'), "bearer must not contain dots");
    }

    #[test]
    fn prop_oauth_always_exactly_two_dots(seed in any::<[u8; 32]>()) {
        let token = generate_oauth_access_token("svc", &mut ChaCha20Rng::from_seed(seed));
        prop_assert_eq!(token.matches('.').count(), 2);
    }

    #[test]
    fn prop_api_key_no_whitespace(seed in any::<[u8; 32]>()) {
        let key = generate_api_key(&mut ChaCha20Rng::from_seed(seed));
        prop_assert!(!key.chars().any(|c| c.is_whitespace()));
    }

    #[test]
    fn prop_bearer_no_whitespace(seed in any::<[u8; 32]>()) {
        let token = generate_bearer_token(&mut ChaCha20Rng::from_seed(seed));
        prop_assert!(!token.chars().any(|c| c.is_whitespace()));
    }

    #[test]
    fn prop_oauth_no_whitespace_except_dots(seed in any::<[u8; 32]>()) {
        let token = generate_oauth_access_token("svc", &mut ChaCha20Rng::from_seed(seed));
        prop_assert!(!token.chars().any(|c| c.is_whitespace()));
    }

    #[test]
    fn prop_random_base62_deterministic(seed in any::<[u8; 32]>(), len in 0usize..128) {
        let a = random_base62(&mut ChaCha20Rng::from_seed(seed), len);
        let b = random_base62(&mut ChaCha20Rng::from_seed(seed), len);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn prop_oauth_claims_always_have_required_fields(
        seed in any::<[u8; 32]>(),
        label in "[a-z][a-z0-9]{0,15}"
    ) {
        let token = generate_oauth_access_token(&label, &mut ChaCha20Rng::from_seed(seed));
        let payload_segment = token.split('.').nth(1).unwrap();
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        prop_assert!(claims.get("iss").is_some());
        prop_assert!(claims.get("sub").is_some());
        prop_assert!(claims.get("aud").is_some());
        prop_assert!(claims.get("exp").is_some());
        prop_assert!(claims.get("jti").is_some());
        prop_assert!(claims.get("scope").is_some());
    }

    #[test]
    fn prop_different_seeds_different_output(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
        kind_idx in 0u8..3
    ) {
        prop_assume!(seed_a != seed_b);
        let kind = match kind_idx {
            0 => TokenKind::ApiKey,
            1 => TokenKind::Bearer,
            _ => TokenKind::OAuthAccessToken,
        };
        let a = generate_token("lbl", kind, &mut ChaCha20Rng::from_seed(seed_a));
        let b = generate_token("lbl", kind, &mut ChaCha20Rng::from_seed(seed_b));
        prop_assert_ne!(a, b);
    }
}
