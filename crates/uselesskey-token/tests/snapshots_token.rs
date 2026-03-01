//! Insta snapshot tests for uselesskey-token.
//!
//! These tests snapshot token shapes and metadata to detect
//! unintended changes in deterministic token generation.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_token::{TokenFactoryExt, TokenSpec};

#[derive(Serialize)]
struct TokenSnapshot {
    label: &'static str,
    kind: &'static str,
    value_len: usize,
    starts_with_uk_test: bool,
    authorization_header_prefix: String,
}

#[test]
fn snapshot_api_key_shape() {
    let fx = fx();
    let tok = fx.token("snapshot-api-key", TokenSpec::api_key());

    let result = TokenSnapshot {
        label: "snapshot-api-key",
        kind: "api_key",
        value_len: tok.value().len(),
        starts_with_uk_test: tok.value().starts_with("uk_test_"),
        authorization_header_prefix: tok
            .authorization_header()
            .split(' ')
            .next()
            .unwrap_or("")
            .to_string(),
    };

    insta::assert_yaml_snapshot!("token_api_key_shape", result);
}

#[test]
fn snapshot_bearer_shape() {
    let fx = fx();
    let tok = fx.token("snapshot-bearer", TokenSpec::bearer());

    let result = TokenSnapshot {
        label: "snapshot-bearer",
        kind: "bearer",
        value_len: tok.value().len(),
        starts_with_uk_test: tok.value().starts_with("uk_test_"),
        authorization_header_prefix: tok
            .authorization_header()
            .split(' ')
            .next()
            .unwrap_or("")
            .to_string(),
    };

    insta::assert_yaml_snapshot!("token_bearer_shape", result);
}

#[test]
fn snapshot_oauth_jwt_shape() {
    let fx = fx();
    let tok = fx.token("snapshot-oauth", TokenSpec::oauth_access_token());

    #[derive(Serialize)]
    struct OAuthSnapshot {
        label: &'static str,
        value_len: usize,
        has_three_segments: bool,
        authorization_header_prefix: String,
    }

    let segments: Vec<&str> = tok.value().split('.').collect();

    let result = OAuthSnapshot {
        label: "snapshot-oauth",
        value_len: tok.value().len(),
        has_three_segments: segments.len() == 3,
        authorization_header_prefix: tok
            .authorization_header()
            .split(' ')
            .next()
            .unwrap_or("")
            .to_string(),
    };

    insta::assert_yaml_snapshot!("token_oauth_jwt_shape", result);
}
