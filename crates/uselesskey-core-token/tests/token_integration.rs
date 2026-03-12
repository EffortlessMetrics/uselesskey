//! Integration tests for token generation facade — covers all token kinds,
//! determinism, and structural invariants.

use uselesskey_core_seed::Seed;

use uselesskey_core_token::{
    TokenKind, authorization_scheme, generate_api_key, generate_bearer_token,
    generate_oauth_access_token, generate_token,
};

fn seed(seed: u8) -> Seed {
    Seed::new([seed; 32])
}

// ── API key structural invariants ────────────────────────────────────

#[test]
fn api_key_starts_with_prefix() {
    let key = generate_api_key(seed(1));
    assert!(key.starts_with("uk_test_"));
}

#[test]
fn api_key_is_exactly_40_chars() {
    let key = generate_api_key(seed(2));
    assert_eq!(key.len(), 40); // 8 prefix + 32 random base62
}

#[test]
fn api_key_suffix_is_alphanumeric() {
    let key = generate_api_key(seed(3));
    let suffix = key.strip_prefix("uk_test_").unwrap();
    assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
}

// ── bearer token structural invariants ───────────────────────────────

#[test]
fn bearer_token_is_base64url() {
    let token = generate_bearer_token(seed(4));
    for ch in token.chars() {
        assert!(
            ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
            "unexpected char: {ch}"
        );
    }
}

#[test]
fn bearer_token_is_43_chars() {
    let token = generate_bearer_token(seed(5));
    assert_eq!(token.len(), 43); // ceil(32 * 4/3) = 43 with no padding
}

#[test]
fn bearer_token_decodes_to_32_bytes() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let token = generate_bearer_token(seed(6));
    let decoded = URL_SAFE_NO_PAD.decode(token).unwrap();
    assert_eq!(decoded.len(), 32);
}

// ── OAuth access token structural invariants ─────────────────────────

#[test]
fn oauth_token_has_three_dot_separated_segments() {
    let token = generate_oauth_access_token("svc", seed(7));
    assert_eq!(token.matches('.').count(), 2);
}

#[test]
fn oauth_token_payload_contains_label_as_sub() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let token = generate_oauth_access_token("my-service", seed(8));
    let parts: Vec<&str> = token.split('.').collect();
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(json["sub"], "my-service");
    assert_eq!(json["iss"], "uselesskey");
    assert_eq!(json["aud"], "tests");
}

#[test]
fn oauth_token_header_is_rs256_jwt() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let token = generate_oauth_access_token("svc", seed(9));
    let parts: Vec<&str> = token.split('.').collect();
    let header = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&header).unwrap();
    assert_eq!(json["alg"], "RS256");
    assert_eq!(json["typ"], "JWT");
}

// ── generate_token dispatches correctly ──────────────────────────────

#[test]
fn generate_token_api_key_matches_direct() {
    let a = generate_token("label", TokenKind::ApiKey, seed(10));
    let b = generate_api_key(seed(10));
    assert_eq!(a, b);
}

#[test]
fn generate_token_bearer_matches_direct() {
    let a = generate_token("label", TokenKind::Bearer, seed(11));
    let b = generate_bearer_token(seed(11));
    assert_eq!(a, b);
}

#[test]
fn generate_token_oauth_matches_direct() {
    let a = generate_token("label", TokenKind::OAuthAccessToken, seed(12));
    let b = generate_oauth_access_token("label", seed(12));
    assert_eq!(a, b);
}

// ── authorization_scheme ─────────────────────────────────────────────

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

// ── determinism ──────────────────────────────────────────────────────

#[test]
fn all_token_kinds_are_deterministic() {
    for kind in [
        TokenKind::ApiKey,
        TokenKind::Bearer,
        TokenKind::OAuthAccessToken,
    ] {
        let a = generate_token("lbl", kind, seed(50));
        let b = generate_token("lbl", kind, seed(50));
        assert_eq!(a, b, "kind {kind:?} not deterministic");
    }
}

#[test]
fn different_labels_produce_different_oauth_tokens() {
    let a = generate_oauth_access_token("service-a", seed(60));
    let b = generate_oauth_access_token("service-b", seed(60));
    // Same seed but different labels → different payload → different token
    assert_ne!(a, b);
}
