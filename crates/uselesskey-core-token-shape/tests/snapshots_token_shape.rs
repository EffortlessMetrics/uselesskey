//! Insta snapshot tests for uselesskey-core-token-shape.
//!
//! Snapshot token format shapes — lengths, prefixes, segment counts.
//! No actual token content is captured.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use uselesskey_core_token_shape::{
    API_KEY_PREFIX, API_KEY_RANDOM_LEN, BEARER_RANDOM_BYTES, TokenKind, authorization_scheme,
    generate_token,
};

#[derive(Serialize)]
#[allow(dead_code)]
struct TokenShapeSnapshot {
    kind: &'static str,
    total_len: usize,
    auth_scheme: &'static str,
}

#[test]
fn snapshot_api_key_shape() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let token = generate_token("test-svc", TokenKind::ApiKey, &mut rng);

    #[derive(Serialize)]
    struct ApiKeyShape {
        prefix: &'static str,
        prefix_len: usize,
        random_suffix_len: usize,
        total_len: usize,
        starts_with_prefix: bool,
        suffix_all_alphanumeric: bool,
    }

    let suffix = &token[API_KEY_PREFIX.len()..];
    let result = ApiKeyShape {
        prefix: API_KEY_PREFIX,
        prefix_len: API_KEY_PREFIX.len(),
        random_suffix_len: API_KEY_RANDOM_LEN,
        total_len: token.len(),
        starts_with_prefix: token.starts_with(API_KEY_PREFIX),
        suffix_all_alphanumeric: suffix.chars().all(|c| c.is_ascii_alphanumeric()),
    };

    insta::assert_yaml_snapshot!("token_api_key_shape", result);
}

#[test]
fn snapshot_bearer_token_shape() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let token = generate_token("test-svc", TokenKind::Bearer, &mut rng);

    #[derive(Serialize)]
    struct BearerShape {
        encoded_len: usize,
        raw_random_bytes: usize,
        is_base64url: bool,
    }

    let result = BearerShape {
        encoded_len: token.len(),
        raw_random_bytes: BEARER_RANDOM_BYTES,
        is_base64url: token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
    };

    insta::assert_yaml_snapshot!("token_bearer_shape", result);
}

#[test]
fn snapshot_oauth_token_shape() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let token = generate_token("test-svc", TokenKind::OAuthAccessToken, &mut rng);

    #[derive(Serialize)]
    struct OAuthShape {
        segment_count: usize,
        total_len: usize,
        is_jwt_shaped: bool,
    }

    let segments: Vec<&str> = token.split('.').collect();
    let result = OAuthShape {
        segment_count: segments.len(),
        total_len: token.len(),
        is_jwt_shaped: segments.len() == 3,
    };

    insta::assert_yaml_snapshot!("token_oauth_shape", result);
}

#[test]
fn snapshot_authorization_schemes() {
    #[derive(Serialize)]
    struct AuthSchemes {
        api_key: &'static str,
        bearer: &'static str,
        oauth: &'static str,
    }

    let result = AuthSchemes {
        api_key: authorization_scheme(TokenKind::ApiKey),
        bearer: authorization_scheme(TokenKind::Bearer),
        oauth: authorization_scheme(TokenKind::OAuthAccessToken),
    };

    insta::assert_yaml_snapshot!("token_auth_schemes", result);
}
