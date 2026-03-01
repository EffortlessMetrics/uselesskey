//! Insta snapshot tests for uselesskey-token.
//!
//! These tests snapshot token shapes produced by deterministic keys
//! to detect unintended changes in token format, length, or structure.

mod testutil;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use testutil::fx;
use uselesskey_token::{TokenFactoryExt, TokenSpec};

// =========================================================================
// Snapshot structs
// =========================================================================

#[derive(Serialize)]
struct ApiKeyShape {
    kind: &'static str,
    prefix: String,
    suffix_len: usize,
    suffix_all_alphanumeric: bool,
    total_len: usize,
    authorization_scheme: String,
}

#[derive(Serialize)]
struct BearerShape {
    kind: &'static str,
    value_len: usize,
    decoded_byte_count: usize,
    is_valid_base64url: bool,
    authorization_scheme: String,
}

#[derive(Serialize)]
struct OAuthShape {
    kind: &'static str,
    segment_count: usize,
    header_alg: String,
    header_typ: String,
    payload_iss: String,
    payload_sub: String,
    payload_aud: String,
    payload_scope: String,
    has_jti: bool,
    has_exp: bool,
    authorization_scheme: String,
}

#[derive(Serialize)]
struct TokenMatrixEntry {
    label: &'static str,
    spec: &'static str,
    value_len: usize,
    deterministic: bool,
}

// =========================================================================
// API key shape snapshot
// =========================================================================

#[test]
fn snapshot_api_key_shape() {
    let fx = fx();
    let token = fx.token("snap-api", TokenSpec::api_key());
    let value = token.value();
    let prefix = "uk_test_";
    let suffix = value.strip_prefix(prefix).unwrap_or("");

    let result = ApiKeyShape {
        kind: "api_key",
        prefix: prefix.to_string(),
        suffix_len: suffix.len(),
        suffix_all_alphanumeric: suffix.chars().all(|c| c.is_ascii_alphanumeric()),
        total_len: value.len(),
        authorization_scheme: "ApiKey".to_string(),
    };

    insta::assert_yaml_snapshot!("api_key_shape", result);
}

// =========================================================================
// Bearer token shape snapshot
// =========================================================================

#[test]
fn snapshot_bearer_shape() {
    let fx = fx();
    let token = fx.token("snap-bearer", TokenSpec::bearer());
    let value = token.value();
    let decoded = URL_SAFE_NO_PAD.decode(value);

    let result = BearerShape {
        kind: "bearer",
        value_len: value.len(),
        decoded_byte_count: decoded.as_ref().map_or(0, |b| b.len()),
        is_valid_base64url: decoded.is_ok(),
        authorization_scheme: "Bearer".to_string(),
    };

    insta::assert_yaml_snapshot!("bearer_shape", result);
}

// =========================================================================
// OAuth access token shape snapshot
// =========================================================================

#[test]
fn snapshot_oauth_access_token_shape() {
    let fx = fx();
    let token = fx.token("snap-oauth", TokenSpec::oauth_access_token());
    let value = token.value();
    let parts: Vec<&str> = value.split('.').collect();

    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).expect("decode header");
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("parse header");

    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("decode payload");
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).expect("parse payload");

    let result = OAuthShape {
        kind: "oauth_access_token",
        segment_count: parts.len(),
        header_alg: header["alg"].as_str().unwrap_or("").to_string(),
        header_typ: header["typ"].as_str().unwrap_or("").to_string(),
        payload_iss: payload["iss"].as_str().unwrap_or("").to_string(),
        payload_sub: payload["sub"].as_str().unwrap_or("").to_string(),
        payload_aud: payload["aud"].as_str().unwrap_or("").to_string(),
        payload_scope: payload["scope"].as_str().unwrap_or("").to_string(),
        has_jti: payload.get("jti").is_some(),
        has_exp: payload.get("exp").is_some(),
        authorization_scheme: "Bearer".to_string(),
    };

    insta::assert_yaml_snapshot!("oauth_access_token_shape", result);
}

// =========================================================================
// Token spec matrix snapshot
// =========================================================================

#[test]
fn snapshot_token_spec_matrix() {
    let fx = fx();

    let specs: Vec<(&str, TokenSpec)> = vec![
        ("api_key", TokenSpec::api_key()),
        ("bearer", TokenSpec::bearer()),
        ("oauth_access_token", TokenSpec::oauth_access_token()),
    ];

    let entries: Vec<TokenMatrixEntry> = specs
        .into_iter()
        .map(|(name, spec)| {
            let t1 = fx.token("matrix-label", spec);
            let t2 = fx.token("matrix-label", spec);

            TokenMatrixEntry {
                label: "matrix-label",
                spec: name,
                value_len: t1.value().len(),
                deterministic: t1.value() == t2.value(),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("token_spec_matrix", entries);
}

// =========================================================================
// Different labels produce different tokens (all specs)
// =========================================================================

#[derive(Serialize)]
struct LabelDivergence {
    spec: &'static str,
    labels_differ: bool,
}

#[test]
fn snapshot_label_divergence() {
    let fx = fx();

    let specs: Vec<(&str, TokenSpec)> = vec![
        ("api_key", TokenSpec::api_key()),
        ("bearer", TokenSpec::bearer()),
        ("oauth_access_token", TokenSpec::oauth_access_token()),
    ];

    let entries: Vec<LabelDivergence> = specs
        .into_iter()
        .map(|(name, spec)| {
            let a = fx.token("label-a", spec);
            let b = fx.token("label-b", spec);
            LabelDivergence {
                spec: name,
                labels_differ: a.value() != b.value(),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("label_divergence", entries);
}

// =========================================================================
// Variant divergence snapshot
// =========================================================================

#[derive(Serialize)]
struct VariantDivergence {
    spec: &'static str,
    good_vs_custom_differ: bool,
}

#[test]
fn snapshot_variant_divergence() {
    let fx = fx();

    let specs: Vec<(&str, TokenSpec)> = vec![
        ("api_key", TokenSpec::api_key()),
        ("bearer", TokenSpec::bearer()),
        ("oauth_access_token", TokenSpec::oauth_access_token()),
    ];

    let entries: Vec<VariantDivergence> = specs
        .into_iter()
        .map(|(name, spec)| {
            let good = fx.token("variant-snap", spec);
            let custom = fx.token_with_variant("variant-snap", spec, "custom");
            VariantDivergence {
                spec: name,
                good_vs_custom_differ: good.value() != custom.value(),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("variant_divergence", entries);
}

// =========================================================================
// Debug safety snapshot
// =========================================================================

#[derive(Serialize)]
struct DebugSafety {
    contains_struct_name: bool,
    contains_label: bool,
    contains_token_value: bool,
    uses_non_exhaustive: bool,
}

#[test]
fn snapshot_debug_safety() {
    let fx = fx();
    let token = fx.token("debug-snap", TokenSpec::api_key());
    let dbg = format!("{token:?}");

    let result = DebugSafety {
        contains_struct_name: dbg.contains("TokenFixture"),
        contains_label: dbg.contains("debug-snap"),
        contains_token_value: dbg.contains(token.value()),
        uses_non_exhaustive: dbg.contains(".."),
    };

    insta::assert_yaml_snapshot!("debug_safety", result);
}
