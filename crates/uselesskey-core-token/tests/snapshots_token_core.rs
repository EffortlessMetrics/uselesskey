//! Insta snapshot tests for uselesskey-core-token.
//!
//! Snapshot token generation metadata — format shapes, lengths, schemes.
//! All actual token values are redacted.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use uselesskey_core_token::{
    API_KEY_PREFIX, API_KEY_RANDOM_LEN, BEARER_RANDOM_BYTES, TokenKind, authorization_scheme,
    generate_token,
};

#[derive(Serialize)]
struct TokenMetadata {
    kind: &'static str,
    total_len: usize,
    auth_scheme: &'static str,
}

#[test]
fn snapshot_all_token_kinds_metadata() {
    let seed = [42u8; 32];
    let kinds = [
        ("ApiKey", TokenKind::ApiKey),
        ("Bearer", TokenKind::Bearer),
        ("OAuthAccessToken", TokenKind::OAuthAccessToken),
    ];

    let results: Vec<TokenMetadata> = kinds
        .iter()
        .map(|(name, kind)| {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let token = generate_token("test-label", *kind, &mut rng);
            TokenMetadata {
                kind: name,
                total_len: token.len(),
                auth_scheme: authorization_scheme(*kind),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("token_core_all_kinds", results);
}

#[test]
fn snapshot_api_key_structure() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let token = generate_token("my-service", TokenKind::ApiKey, &mut rng);

    #[derive(Serialize)]
    struct ApiKeyStructure {
        prefix: &'static str,
        prefix_len: usize,
        random_suffix_len: usize,
        total_len: usize,
        has_correct_prefix: bool,
        suffix_all_alphanumeric: bool,
    }

    let suffix = &token[API_KEY_PREFIX.len()..];
    let result = ApiKeyStructure {
        prefix: API_KEY_PREFIX,
        prefix_len: API_KEY_PREFIX.len(),
        random_suffix_len: API_KEY_RANDOM_LEN,
        total_len: token.len(),
        has_correct_prefix: token.starts_with(API_KEY_PREFIX),
        suffix_all_alphanumeric: suffix.chars().all(|c| c.is_ascii_alphanumeric()),
    };

    insta::assert_yaml_snapshot!("token_core_api_key_structure", result);
}

#[test]
fn snapshot_bearer_token_structure() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let token = generate_token("my-service", TokenKind::Bearer, &mut rng);

    #[derive(Serialize)]
    struct BearerStructure {
        encoded_len: usize,
        raw_random_bytes: usize,
        is_base64url: bool,
    }

    let result = BearerStructure {
        encoded_len: token.len(),
        raw_random_bytes: BEARER_RANDOM_BYTES,
        is_base64url: token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
    };

    insta::assert_yaml_snapshot!("token_core_bearer_structure", result);
}

#[test]
fn snapshot_oauth_token_structure() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let token = generate_token("my-service", TokenKind::OAuthAccessToken, &mut rng);

    #[derive(Serialize)]
    struct OAuthStructure {
        segment_count: usize,
        is_jwt_shaped: bool,
        total_len: usize,
    }

    let segments: Vec<&str> = token.split('.').collect();
    let result = OAuthStructure {
        segment_count: segments.len(),
        is_jwt_shaped: segments.len() == 3,
        total_len: token.len(),
    };

    insta::assert_yaml_snapshot!("token_core_oauth_structure", result);
}

#[test]
fn snapshot_token_determinism() {
    let seed = [7u8; 32];

    #[derive(Serialize)]
    struct TokenDeterminism {
        kind: &'static str,
        same_seed_matches: bool,
    }

    let kinds = [
        ("ApiKey", TokenKind::ApiKey),
        ("Bearer", TokenKind::Bearer),
        ("OAuthAccessToken", TokenKind::OAuthAccessToken),
    ];

    let results: Vec<TokenDeterminism> = kinds
        .iter()
        .map(|(name, kind)| {
            let mut rng_a = ChaCha20Rng::from_seed(seed);
            let mut rng_b = ChaCha20Rng::from_seed(seed);
            let a = generate_token("label", *kind, &mut rng_a);
            let b = generate_token("label", *kind, &mut rng_b);
            TokenDeterminism {
                kind: name,
                same_seed_matches: a == b,
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("token_core_determinism", results);
}
