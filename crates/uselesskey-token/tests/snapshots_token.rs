mod testutil;

use insta::{assert_yaml_snapshot, with_settings};
use testutil::fx;
use uselesskey_token::{TokenFactoryExt, TokenSpec};

#[test]
fn snapshots_api_key_shape() {
    let token = fx().token("snapshot-svc", TokenSpec::api_key());
    let value = token.value();

    let info = serde_json::json!({
        "prefix": &value[.."uk_test_".len()],
        "suffix_len": value["uk_test_".len()..].len(),
        "suffix_is_alphanumeric": value["uk_test_".len()..].chars().all(|c| c.is_ascii_alphanumeric()),
        "total_len": value.len(),
    });

    with_settings!({
        description => "API key shape: uk_test_ prefix + 32 alphanumeric chars",
    }, {
        assert_yaml_snapshot!("api_key_shape", info);
    });
}

#[test]
fn snapshots_bearer_token_shape() {
    let token = fx().token("snapshot-svc", TokenSpec::bearer());
    let value = token.value();

    let is_base64url = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');

    let info = serde_json::json!({
        "len": value.len(),
        "is_base64url_chars": is_base64url,
        "authorization_header_prefix": &token.authorization_header()[..7],
    });

    with_settings!({
        description => "Bearer token: base64url body with Bearer auth scheme",
    }, {
        assert_yaml_snapshot!("bearer_token_shape", info);
    });
}

#[test]
fn snapshots_oauth_access_token_shape() {
    let token = fx().token("snapshot-issuer", TokenSpec::oauth_access_token());
    let value = token.value();

    let parts: Vec<&str> = value.split('.').collect();

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).expect("decode JWT header");
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("decode JWT payload");

    let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("header json");
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).expect("payload json");

    let info = serde_json::json!({
        "segment_count": parts.len(),
        "header": {
            "alg": header["alg"],
            "typ": header["typ"],
        },
        "payload": {
            "sub": payload["sub"],
            "iss": payload["iss"],
            "has_iat": payload.get("iat").is_some(),
            "has_exp": payload.get("exp").is_some(),
        },
        "authorization_header_prefix": &token.authorization_header()[..7],
    });

    with_settings!({
        description => "OAuth access token: JWT shape with 3 segments, RS256 header, issuer payload",
    }, {
        assert_yaml_snapshot!("oauth_access_token_shape", info);
    });
}

#[test]
fn snapshots_token_determinism() {
    let fx = fx();
    let t1 = fx.token("snapshot-det", TokenSpec::api_key());
    let t2 = fx.token("snapshot-det", TokenSpec::api_key());

    let info = serde_json::json!({
        "values_match": t1.value() == t2.value(),
        "spec": "api_key",
    });

    assert_yaml_snapshot!("token_determinism", info);
}

#[test]
fn snapshots_all_token_kinds() {
    let fx = fx();

    let api_key = fx.token("snapshot-all", TokenSpec::api_key());
    let bearer = fx.token("snapshot-all", TokenSpec::bearer());
    let oauth = fx.token("snapshot-all", TokenSpec::oauth_access_token());

    let info = serde_json::json!({
        "api_key": {
            "starts_with_prefix": api_key.value().starts_with("uk_test_"),
            "len": api_key.value().len(),
        },
        "bearer": {
            "len": bearer.value().len(),
            "has_dot_segments": bearer.value().contains('.'),
        },
        "oauth": {
            "segment_count": oauth.value().split('.').count(),
            "has_dot_segments": true,
        },
    });

    with_settings!({
        description => "All token kinds side by side — shape comparison",
    }, {
        assert_yaml_snapshot!("all_token_kinds", info);
    });
}
