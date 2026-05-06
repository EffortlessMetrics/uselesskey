use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use uselesskey_core_seed::Seed;
use uselesskey_core_token_shape::{
    API_KEY_PREFIX, API_KEY_RANDOM_LEN, NegativeToken, TokenKind, generate_negative_token,
    generate_token,
};

const SCANNER_SAFE_INVALID_TOKEN_SEGMENT: &str = "not_base64url!*";
const NEAR_MISS_API_KEY_PREFIX: &str = "uk_tset_";

fn fixture(variant: NegativeToken) -> String {
    generate_negative_token(
        "issuer",
        TokenKind::OAuthAccessToken,
        Seed::new([31u8; 32]),
        variant,
    )
}

fn parts(token: &str) -> Vec<&str> {
    token.split('.').collect()
}

fn decode_json(segment: &str) -> Value {
    let bytes = URL_SAFE_NO_PAD.decode(segment).expect("decode JWT segment");
    serde_json::from_slice(&bytes).expect("parse JWT JSON segment")
}

fn header(token: &str) -> Value {
    decode_json(parts(token)[0])
}

fn payload(token: &str) -> Value {
    decode_json(parts(token)[1])
}

#[test]
fn malformed_jwt_segment_count_emits_two_segments() {
    let value = fixture(NegativeToken::MalformedJwtSegmentCount);

    assert_eq!(parts(&value).len(), 2);
    assert_ne!(
        value,
        generate_token("issuer", TokenKind::OAuthAccessToken, Seed::new([31u8; 32]))
    );
}

#[test]
fn bad_base64url_segment_preserves_jwt_shape_but_breaks_payload_decode() {
    let value = fixture(NegativeToken::BadBase64UrlSegment);
    let parts = parts(&value);

    assert_eq!(parts.len(), 3);
    assert_eq!(parts[1], SCANNER_SAFE_INVALID_TOKEN_SEGMENT);
    assert!(URL_SAFE_NO_PAD.decode(parts[1]).is_err());
    assert!(decode_json(parts[0]).is_object());
}

#[test]
fn invalid_header_shape_is_json_but_not_an_object() {
    let value = fixture(NegativeToken::InvalidJwtHeaderShape);

    assert_eq!(parts(&value).len(), 3);
    assert!(header(&value).is_array());
}

#[test]
fn missing_alg_removes_only_algorithm_header() {
    let value = fixture(NegativeToken::MissingAlg);
    let header = header(&value);

    assert!(header.get("alg").is_none());
    assert_eq!(header["typ"], "JWT");
    assert_eq!(payload(&value)["iss"], "uselesskey");
}

#[test]
fn alg_none_preserves_jwt_shape() {
    let value = fixture(NegativeToken::AlgNone);
    let header = header(&value);

    assert_eq!(parts(&value).len(), 3);
    assert_eq!(header["alg"], "none");
    assert_eq!(header["typ"], "JWT");
}

#[test]
fn mismatched_kid_uses_different_header_and_payload_values() {
    let value = fixture(NegativeToken::MismatchedKid);

    assert_eq!(header(&value)["kid"], "unknown-kid");
    assert_eq!(payload(&value)["kid"], "expected-kid");
    assert_ne!(header(&value)["kid"], payload(&value)["kid"]);
}

#[test]
fn expired_claims_are_shape_realistic() {
    let value = fixture(NegativeToken::ExpiredClaims);
    let payload = payload(&value);

    assert_eq!(parts(&value).len(), 3);
    assert_eq!(payload["exp"], 1);
    assert_eq!(payload["iss"], "uselesskey");
}

#[test]
fn not_yet_valid_claims_keep_future_window() {
    let value = fixture(NegativeToken::NotYetValidClaims);
    let payload = payload(&value);

    assert_eq!(payload["nbf"], 4_000_000_000u64);
    assert_eq!(payload["exp"], 4_100_000_000u64);
    assert!(payload["nbf"].as_u64().expect("nbf should be numeric") > 2_000_000_000u64);
}

#[test]
fn bad_issuer_replaces_expected_claim_only() {
    let value = fixture(NegativeToken::BadIssuer);
    let payload = payload(&value);

    assert_eq!(payload["iss"], "wrong-issuer");
    assert_eq!(payload["aud"], "tests");
}

#[test]
fn bad_audience_replaces_expected_claim_only() {
    let value = fixture(NegativeToken::BadAudience);
    let payload = payload(&value);

    assert_eq!(payload["iss"], "uselesskey");
    assert_eq!(payload["aud"], "wrong-audience");
}

#[test]
fn malformed_bearer_is_scanner_safe_invalid_material() {
    let value = generate_negative_token(
        "gateway",
        TokenKind::Bearer,
        Seed::new([37u8; 32]),
        NegativeToken::MalformedBearer,
    );

    assert_ne!(value, SCANNER_SAFE_INVALID_TOKEN_SEGMENT);
    assert!(value.contains('!'));
    assert_eq!(value.matches('.').count(), 0);
    assert_eq!(value.len(), 43);
    assert!(URL_SAFE_NO_PAD.decode(value).is_err());
}

#[test]
fn near_miss_api_key_keeps_length_but_breaks_prefix() {
    let value = generate_negative_token(
        "billing",
        TokenKind::ApiKey,
        Seed::new([41u8; 32]),
        NegativeToken::NearMissApiKey,
    );

    assert!(value.starts_with(NEAR_MISS_API_KEY_PREFIX));
    assert!(!value.starts_with(API_KEY_PREFIX));
    assert_eq!(
        value.len(),
        NEAR_MISS_API_KEY_PREFIX.len() + API_KEY_RANDOM_LEN
    );
    assert!(
        value
            .strip_prefix(NEAR_MISS_API_KEY_PREFIX)
            .expect("near-miss prefix")
            .chars()
            .all(|c| c.is_ascii_alphanumeric())
    );
}

#[test]
fn negative_generation_is_stable_for_same_identity() {
    let a = generate_negative_token(
        "stable",
        TokenKind::OAuthAccessToken,
        Seed::new([43u8; 32]),
        NegativeToken::ExpiredClaims,
    );
    let b = generate_negative_token(
        "stable",
        TokenKind::OAuthAccessToken,
        Seed::new([43u8; 32]),
        NegativeToken::ExpiredClaims,
    );
    let good = generate_token("stable", TokenKind::OAuthAccessToken, Seed::new([43u8; 32]));

    assert_eq!(a, b);
    assert_ne!(a, good);
}
