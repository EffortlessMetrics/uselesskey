//! Additional snapshot tests for token fixture metadata — Wave 91.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_token::{TokenFactoryExt, TokenSpec};

// =========================================================================
// All specs summary snapshot
// =========================================================================

#[derive(Serialize)]
struct AllSpecsSummary {
    api_key_len: usize,
    api_key_prefix: String,
    bearer_len: usize,
    oauth_segment_count: usize,
    oauth_has_header_payload_sig: bool,
}

#[test]
fn snapshot_all_specs_summary() {
    let fx = fx();
    let api = fx.token("snap-summary", TokenSpec::api_key());
    let bearer = fx.token("snap-summary", TokenSpec::bearer());
    let oauth = fx.token("snap-summary", TokenSpec::oauth_access_token());

    let oauth_segments: Vec<&str> = oauth.value().split('.').collect();

    let result = AllSpecsSummary {
        api_key_len: api.value().len(),
        api_key_prefix: api.value().chars().take(8).collect(),
        bearer_len: bearer.value().len(),
        oauth_segment_count: oauth_segments.len(),
        oauth_has_header_payload_sig: oauth_segments.len() == 3,
    };

    insta::assert_yaml_snapshot!("token_all_specs_summary", result);
}

// =========================================================================
// OAuth claims shape snapshot
// =========================================================================

#[derive(Serialize)]
struct OAuthClaimsShape {
    has_iss: bool,
    has_sub: bool,
    has_aud: bool,
    has_scope: bool,
    has_exp: bool,
    has_jti: bool,
    iss_value: String,
    sub_value: String,
    aud_value: String,
    scope_value: String,
}

#[test]
fn snapshot_oauth_claims_shape() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let fx = fx();
    let tok = fx.token("snap-oauth-claims", TokenSpec::oauth_access_token());
    let payload_segment = tok.value().split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    let result = OAuthClaimsShape {
        has_iss: claims.get("iss").is_some(),
        has_sub: claims.get("sub").is_some(),
        has_aud: claims.get("aud").is_some(),
        has_scope: claims.get("scope").is_some(),
        has_exp: claims.get("exp").is_some(),
        has_jti: claims.get("jti").is_some(),
        iss_value: claims["iss"].as_str().unwrap_or("").to_string(),
        sub_value: claims["sub"].as_str().unwrap_or("").to_string(),
        aud_value: claims["aud"].as_str().unwrap_or("").to_string(),
        scope_value: claims["scope"].as_str().unwrap_or("").to_string(),
    };

    insta::assert_yaml_snapshot!("token_oauth_claims_shape", result);
}

// =========================================================================
// Variant shapes snapshot
// =========================================================================

#[derive(Serialize)]
struct VariantShape {
    spec: &'static str,
    default_len: usize,
    alt_len: usize,
    values_differ: bool,
}

#[test]
fn snapshot_variant_shapes() {
    let fx = fx();

    let specs: Vec<(TokenSpec, &'static str)> = vec![
        (TokenSpec::api_key(), "api_key"),
        (TokenSpec::bearer(), "bearer"),
        (TokenSpec::oauth_access_token(), "oauth_access_token"),
    ];

    let results: Vec<VariantShape> = specs
        .into_iter()
        .map(|(spec, name)| {
            let default = fx.token("snap-variant", spec);
            let alt = fx.token_with_variant("snap-variant", spec, "alt");
            VariantShape {
                spec: name,
                default_len: default.value().len(),
                alt_len: alt.value().len(),
                values_differ: default.value() != alt.value(),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("token_variant_shapes", results);
}
