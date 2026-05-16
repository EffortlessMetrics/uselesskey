use serde_json::{Value, json};
use uselesskey_core::Seed;

use super::jwt::{decode_object, encode_json, encode_object, jwt_header, oauth_parts};
use super::{
    API_KEY_PREFIX, NEAR_MISS_API_KEY_PREFIX, SCANNER_SAFE_INVALID_TOKEN_SEGMENT, TokenKind,
    generate_api_key, generate_bearer_token,
};

/// Negative token shape variants for downstream parser and validator tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegativeToken {
    /// Emit a JWT-like value with the wrong number of dot-separated segments.
    MalformedJwtSegmentCount,
    /// Replace one JWT segment with scanner-safe invalid base64url text.
    BadBase64UrlSegment,
    /// Encode a JWT header that is JSON, but not a header object.
    InvalidJwtHeaderShape,
    /// Remove `alg` from the JWT header.
    MissingAlg,
    /// Set the JWT header algorithm to `none`.
    AlgNone,
    /// Emit different `kid` values in the header and payload.
    MismatchedKid,
    /// Set an already-expired `exp` claim.
    ExpiredClaims,
    /// Set a future `nbf` claim.
    NotYetValidClaims,
    /// Replace the expected issuer claim.
    BadIssuer,
    /// Replace the expected audience claim.
    BadAudience,
    /// Emit a bearer-like token that is not valid base64url.
    MalformedBearer,
    /// Emit an API-key near miss that is close to, but not, `uk_test_`.
    NearMissApiKey,
}

impl NegativeToken {
    /// Stable cache/disposition name for this negative token variant.
    pub const fn variant_name(&self) -> &'static str {
        match self {
            Self::MalformedJwtSegmentCount => "malformed_jwt_segment_count",
            Self::BadBase64UrlSegment => "bad_base64url_segment",
            Self::InvalidJwtHeaderShape => "invalid_jwt_header_shape",
            Self::MissingAlg => "missing_alg",
            Self::AlgNone => "alg_none",
            Self::MismatchedKid => "mismatched_kid",
            Self::ExpiredClaims => "expired_claims",
            Self::NotYetValidClaims => "not_yet_valid_claims",
            Self::BadIssuer => "bad_issuer",
            Self::BadAudience => "bad_audience",
            Self::MalformedBearer => "malformed_bearer",
            Self::NearMissApiKey => "near_miss_api_key",
        }
    }
}

/// Generate a scanner-safe negative token value for parser and validator tests.
pub fn generate_negative_token(
    label: &str,
    kind: TokenKind,
    seed: Seed,
    variant: NegativeToken,
) -> String {
    match variant {
        NegativeToken::MalformedJwtSegmentCount => malformed_jwt_segment_count(label, seed),
        NegativeToken::BadBase64UrlSegment => bad_base64url_segment(label, seed),
        NegativeToken::InvalidJwtHeaderShape => invalid_jwt_header_shape(label, seed),
        NegativeToken::MissingAlg => missing_alg(label, seed),
        NegativeToken::AlgNone => alg_none(label, seed),
        NegativeToken::MismatchedKid => mismatched_kid(label, seed),
        NegativeToken::ExpiredClaims => token_with_payload_claim(label, seed, "exp", json!(1u64)),
        NegativeToken::NotYetValidClaims => not_yet_valid_claims(label, seed),
        NegativeToken::BadIssuer => {
            token_with_payload_claim(label, seed, "iss", json!("wrong-issuer"))
        }
        NegativeToken::BadAudience => {
            token_with_payload_claim(label, seed, "aud", json!("wrong-audience"))
        }
        NegativeToken::MalformedBearer => malformed_bearer(seed),
        NegativeToken::NearMissApiKey => near_miss_api_key(kind, seed),
    }
}

fn malformed_jwt_segment_count(label: &str, seed: Seed) -> String {
    let [header, payload, _signature] = oauth_parts(label, seed);
    format!("{header}.{payload}")
}

fn bad_base64url_segment(label: &str, seed: Seed) -> String {
    let [header, _payload, signature] = oauth_parts(label, seed);
    format!("{header}.{SCANNER_SAFE_INVALID_TOKEN_SEGMENT}.{signature}")
}

fn invalid_jwt_header_shape(label: &str, seed: Seed) -> String {
    let [_header, payload, signature] = oauth_parts(label, seed);
    let header = encode_json(&json!(["not-a-header"]));
    format!("{header}.{payload}.{signature}")
}

fn missing_alg(label: &str, seed: Seed) -> String {
    let [_header, payload, signature] = oauth_parts(label, seed);
    let header = encode_json(&json!({ "typ": "JWT" }));
    format!("{header}.{payload}.{signature}")
}

fn alg_none(label: &str, seed: Seed) -> String {
    token_with_header_claim(label, seed, "alg", json!("none"))
}

fn mismatched_kid(label: &str, seed: Seed) -> String {
    let [_header, payload, signature] = oauth_parts(label, seed);
    let mut header = jwt_header();
    header.insert("kid".to_string(), json!("unknown-kid"));

    let mut payload = decode_object(&payload);
    payload.insert("kid".to_string(), json!("expected-kid"));

    format!(
        "{}.{}.{}",
        encode_object(&header),
        encode_object(&payload),
        signature
    )
}

fn not_yet_valid_claims(label: &str, seed: Seed) -> String {
    let [_header, payload, signature] = oauth_parts(label, seed);
    let mut claims = decode_object(&payload);
    claims.insert("nbf".to_string(), json!(4_000_000_000u64));
    claims.insert("exp".to_string(), json!(4_100_000_000u64));

    format!(
        "{}.{}.{}",
        encode_object(&jwt_header()),
        encode_object(&claims),
        signature
    )
}

fn token_with_header_claim(label: &str, seed: Seed, claim: &str, value: Value) -> String {
    let [_header, payload, signature] = oauth_parts(label, seed);
    let mut header = jwt_header();
    header.insert(claim.to_string(), value);

    format!("{}.{}.{}", encode_object(&header), payload, signature)
}

fn token_with_payload_claim(label: &str, seed: Seed, claim: &str, value: Value) -> String {
    let [_header, payload, signature] = oauth_parts(label, seed);
    let mut claims = decode_object(&payload);
    claims.insert(claim.to_string(), value);

    format!(
        "{}.{}.{}",
        encode_object(&jwt_header()),
        encode_object(&claims),
        signature
    )
}

fn malformed_bearer(seed: Seed) -> String {
    let mut value = generate_bearer_token(seed);
    value.replace_range(0..1, "!");
    value
}

fn near_miss_api_key(_kind: TokenKind, seed: Seed) -> String {
    let valid = generate_api_key(seed);
    let suffix = valid.strip_prefix(API_KEY_PREFIX).unwrap_or(&valid);

    format!("{NEAR_MISS_API_KEY_PREFIX}{suffix}")
}

