//! Token shape generation primitives for test fixtures.
//!
//! Generates realistic-looking API keys, bearer tokens, OAuth access tokens,
//! and scanner-safe negative token shapes from deterministic seed material.
//!
//! # Examples
//!
//! ```
//! use uselesskey_token::srp::shape::{
//!     NegativeToken, authorization_scheme, generate_negative_token, generate_token, TokenKind,
//! };
//! use uselesskey_core::Seed;
//!
//! let seed = Seed::new([42u8; 32]);
//!
//! // Generate an API key (prefixed with `uk_test_`)
//! let api_key = generate_token("my-service", TokenKind::ApiKey, seed);
//! assert!(api_key.starts_with("uk_test_"));
//!
//! // Generate a bearer token (base64url-encoded random bytes)
//! let bearer = generate_token("my-service", TokenKind::Bearer, seed);
//! assert_eq!(authorization_scheme(TokenKind::Bearer), "Bearer");
//!
//! // Generate an OAuth access token (JWT-shaped: header.payload.signature)
//! let oauth = generate_token("my-service", TokenKind::OAuthAccessToken, seed);
//! assert_eq!(oauth.matches('.').count(), 2);
//!
//! // Generate a scanner-safe negative token for validator error paths.
//! let expired = generate_negative_token(
//!     "my-service",
//!     TokenKind::OAuthAccessToken,
//!     seed,
//!     NegativeToken::ExpiredClaims,
//! );
//! assert_eq!(expired.matches('.').count(), 2);
//! ```

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};

use serde_json::{Map, Value, json};
use uselesskey_core::Seed;

pub use super::base62::random_base62;

/// Prefix used for API-key token fixtures.
pub const API_KEY_PREFIX: &str = "uk_test_";

/// Number of random base62 characters used in API-key fixtures.
pub const API_KEY_RANDOM_LEN: usize = 32;

/// Number of raw random bytes in opaque bearer tokens.
pub const BEARER_RANDOM_BYTES: usize = 32;

/// Number of random bytes used for OAuth `jti`.
pub const OAUTH_JTI_BYTES: usize = 16;

/// Number of random bytes used for OAuth signature-like segment.
pub const OAUTH_SIGNATURE_BYTES: usize = 32;

const SCANNER_SAFE_INVALID_TOKEN_SEGMENT: &str = "not_base64url!*";

const NEAR_MISS_API_KEY_PREFIX: &str = "uk_tset_";

/// Token shape kind.
pub use super::spec::TokenSpec as TokenKind;

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

/// Generate a token value for the provided shape kind.
pub fn generate_token(label: &str, kind: TokenKind, seed: Seed) -> String {
    match kind {
        TokenKind::ApiKey => generate_api_key(seed),
        TokenKind::Bearer => generate_bearer_token(seed),
        TokenKind::OAuthAccessToken => generate_oauth_access_token(label, seed),
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

/// Return HTTP authorization scheme for the token kind.
pub fn authorization_scheme(kind: TokenKind) -> &'static str {
    kind.authorization_scheme()
}

/// Generate an API-key style token fixture (`uk_test_<base62>`).
pub fn generate_api_key(seed: Seed) -> String {
    let mut out = String::from(API_KEY_PREFIX);
    out.push_str(&random_base62(seed, API_KEY_RANDOM_LEN));
    out
}

/// Generate an opaque bearer token fixture (base64url of 32 random bytes).
pub fn generate_bearer_token(seed: Seed) -> String {
    let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
    let mut bytes = [0u8; BEARER_RANDOM_BYTES];
    rng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate an OAuth access token fixture in JWT shape (`header.payload.signature`).
pub fn generate_oauth_access_token(label: &str, seed: Seed) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let mut rng = ChaCha20Rng::from_seed(*seed.bytes());

    let mut jti = [0u8; OAUTH_JTI_BYTES];
    rng.fill_bytes(&mut jti);

    let payload = json!({
        "iss": "uselesskey",
        "sub": label,
        "aud": "tests",
        "scope": "fixture.read",
        "jti": URL_SAFE_NO_PAD.encode(jti),
        "exp": 2_000_000_000u64,
    });
    let payload_json = serde_json::to_vec(&payload).expect("payload JSON");
    let payload_segment = URL_SAFE_NO_PAD.encode(payload_json);

    let mut signature = [0u8; OAUTH_SIGNATURE_BYTES];
    rng.fill_bytes(&mut signature);
    let signature_segment = URL_SAFE_NO_PAD.encode(signature);

    format!("{header}.{payload_segment}.{signature_segment}")
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
    token_with_header(label, seed, encode_json(&json!(["not-a-header"])))
}

fn missing_alg(label: &str, seed: Seed) -> String {
    token_with_header(label, seed, encode_json(&json!({ "typ": "JWT" })))
}

fn alg_none(label: &str, seed: Seed) -> String {
    token_with_header_claim(label, seed, "alg", json!("none"))
}

fn mismatched_kid(label: &str, seed: Seed) -> String {
    token_with_header_and_payload(label, seed, |header, claims| {
        header.insert("kid".to_string(), json!("unknown-kid"));
        claims.insert("kid".to_string(), json!("expected-kid"));
    })
}

fn not_yet_valid_claims(label: &str, seed: Seed) -> String {
    token_with_payload(label, seed, |claims| {
        claims.insert("nbf".to_string(), json!(4_000_000_000u64));
        claims.insert("exp".to_string(), json!(4_100_000_000u64));
    })
}

fn token_with_header_claim(label: &str, seed: Seed, claim: &str, value: Value) -> String {
    token_with_header_and_payload(label, seed, |header, _claims| {
        header.insert(claim.to_string(), value);
    })
}

fn token_with_payload_claim(label: &str, seed: Seed, claim: &str, value: Value) -> String {
    token_with_payload(label, seed, |claims| {
        claims.insert(claim.to_string(), value);
    })
}

fn token_with_header(label: &str, seed: Seed, header: String) -> String {
    let [_header, payload, signature] = oauth_parts(label, seed);
    encode_token(&header, &payload, &signature)
}

fn token_with_payload(
    label: &str,
    seed: Seed,
    mutate: impl FnOnce(&mut Map<String, Value>),
) -> String {
    token_with_header_and_payload(label, seed, |_header, claims| mutate(claims))
}

fn token_with_header_and_payload(
    label: &str,
    seed: Seed,
    mutate: impl FnOnce(&mut Map<String, Value>, &mut Map<String, Value>),
) -> String {
    let [_header, payload, signature] = oauth_parts(label, seed);
    let mut header = jwt_header();
    let mut claims = decode_object(&payload);
    mutate(&mut header, &mut claims);

    encode_token(&encode_object(&header), &encode_object(&claims), &signature)
}

fn encode_token(header: &str, payload: &str, signature: &str) -> String {
    format!("{header}.{payload}.{signature}")
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

fn oauth_parts(label: &str, seed: Seed) -> [String; 3] {
    let token = generate_oauth_access_token(label, seed);
    let mut parts = token.split('.');
    let header = parts.next().expect("JWT header segment").to_string();
    let payload = parts.next().expect("JWT payload segment").to_string();
    let signature = parts.next().expect("JWT signature segment").to_string();
    assert!(
        parts.next().is_none(),
        "JWT should have exactly three segments"
    );

    [header, payload, signature]
}

fn jwt_header() -> Map<String, Value> {
    Map::from_iter([
        ("alg".to_string(), json!("RS256")),
        ("typ".to_string(), json!("JWT")),
    ])
}

fn decode_object(segment: &str) -> Map<String, Value> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .expect("decode generated JWT JSON segment");
    let value: Value = serde_json::from_slice(&bytes).expect("parse generated JWT JSON segment");
    value
        .as_object()
        .expect("generated JWT JSON segment should be an object")
        .clone()
}

fn encode_object(value: &Map<String, Value>) -> String {
    encode_json(&Value::Object(value.clone()))
}

fn encode_json(value: &Value) -> String {
    let json = serde_json::to_vec(value).expect("serialize token JSON");
    URL_SAFE_NO_PAD.encode(json)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use proptest::prelude::*;
    use uselesskey_core::Seed;

    use super::{
        API_KEY_PREFIX, API_KEY_RANDOM_LEN, BEARER_RANDOM_BYTES, NEAR_MISS_API_KEY_PREFIX,
        NegativeToken, SCANNER_SAFE_INVALID_TOKEN_SEGMENT, TokenKind, authorization_scheme,
        generate_api_key, generate_bearer_token, generate_negative_token,
        generate_oauth_access_token, generate_token, random_base62,
    };

    #[test]
    fn api_key_shape_is_stable() {
        let value = generate_api_key(Seed::new([7u8; 32]));

        assert!(value.starts_with(API_KEY_PREFIX));
        let suffix = value
            .strip_prefix(API_KEY_PREFIX)
            .expect("API key prefix should be present");
        assert_eq!(suffix.len(), API_KEY_RANDOM_LEN);
        assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn bearer_shape_decodes_to_32_bytes() {
        let value = generate_bearer_token(Seed::new([9u8; 32]));
        let decoded = URL_SAFE_NO_PAD.decode(value).expect("base64url decode");
        assert_eq!(decoded.len(), BEARER_RANDOM_BYTES);
    }

    #[test]
    fn oauth_shape_has_three_segments_and_subject() {
        let value = generate_oauth_access_token("issuer", Seed::new([11u8; 32]));
        let parts: Vec<&str> = value.split('.').collect();
        assert_eq!(parts.len(), 3);

        let payload = URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("decode payload segment");
        let json: serde_json::Value = serde_json::from_slice(&payload).expect("parse payload");
        assert_eq!(json["sub"], "issuer");
        assert_eq!(json["iss"], "uselesskey");
    }

    #[test]
    fn authorization_scheme_matches_kind() {
        assert_eq!(authorization_scheme(TokenKind::ApiKey), "ApiKey");
        assert_eq!(authorization_scheme(TokenKind::Bearer), "Bearer");
        assert_eq!(authorization_scheme(TokenKind::OAuthAccessToken), "Bearer");
    }

    #[test]
    fn generate_token_varies_by_kind() {
        let seed = [13u8; 32];

        let api = generate_token("label", TokenKind::ApiKey, Seed::new(seed));
        let bearer = generate_token("label", TokenKind::Bearer, Seed::new(seed));
        let oauth = generate_token("label", TokenKind::OAuthAccessToken, Seed::new(seed));

        assert_ne!(api, bearer);
        assert_ne!(api, oauth);
        assert_ne!(bearer, oauth);
    }

    #[test]
    fn negative_token_variant_names_are_stable() {
        assert_eq!(
            NegativeToken::MalformedJwtSegmentCount.variant_name(),
            "malformed_jwt_segment_count"
        );
        assert_eq!(
            NegativeToken::BadBase64UrlSegment.variant_name(),
            "bad_base64url_segment"
        );
        assert_eq!(
            NegativeToken::InvalidJwtHeaderShape.variant_name(),
            "invalid_jwt_header_shape"
        );
        assert_eq!(NegativeToken::MissingAlg.variant_name(), "missing_alg");
        assert_eq!(NegativeToken::AlgNone.variant_name(), "alg_none");
        assert_eq!(
            NegativeToken::MismatchedKid.variant_name(),
            "mismatched_kid"
        );
        assert_eq!(
            NegativeToken::ExpiredClaims.variant_name(),
            "expired_claims"
        );
        assert_eq!(
            NegativeToken::NotYetValidClaims.variant_name(),
            "not_yet_valid_claims"
        );
        assert_eq!(NegativeToken::BadIssuer.variant_name(), "bad_issuer");
        assert_eq!(NegativeToken::BadAudience.variant_name(), "bad_audience");
        assert_eq!(
            NegativeToken::MalformedBearer.variant_name(),
            "malformed_bearer"
        );
        assert_eq!(
            NegativeToken::NearMissApiKey.variant_name(),
            "near_miss_api_key"
        );
    }

    #[test]
    fn negative_api_key_near_miss_is_scanner_safe() {
        let value = generate_negative_token(
            "svc",
            TokenKind::ApiKey,
            Seed::new([19u8; 32]),
            NegativeToken::NearMissApiKey,
        );

        assert!(value.starts_with(NEAR_MISS_API_KEY_PREFIX));
        assert!(!value.starts_with(API_KEY_PREFIX));
        assert_eq!(
            value.len(),
            NEAR_MISS_API_KEY_PREFIX.len() + API_KEY_RANDOM_LEN
        );
    }

    #[test]
    fn negative_malformed_bearer_is_not_base64url() {
        let value = generate_negative_token(
            "svc",
            TokenKind::Bearer,
            Seed::new([23u8; 32]),
            NegativeToken::MalformedBearer,
        );

        assert_ne!(value, SCANNER_SAFE_INVALID_TOKEN_SEGMENT);
        assert!(value.contains('!'));
        assert_eq!(value.len(), 43);
        assert!(URL_SAFE_NO_PAD.decode(value).is_err());
    }

    #[test]
    fn negative_jwt_segment_count_keeps_two_decodable_segments() {
        let value = generate_negative_token(
            "svc",
            TokenKind::OAuthAccessToken,
            Seed::new([31u8; 32]),
            NegativeToken::MalformedJwtSegmentCount,
        );
        let parts = jwt_parts(&value);

        assert_eq!(parts.len(), 2);
        assert_eq!(decode_object_segment(parts[0])["alg"], "RS256");
        assert_eq!(decode_object_segment(parts[0])["typ"], "JWT");
        assert_eq!(decode_object_segment(parts[1])["sub"], "svc");
    }

    #[test]
    fn negative_bad_base64url_replaces_payload_only() {
        let value = generate_negative_token(
            "svc",
            TokenKind::OAuthAccessToken,
            Seed::new([32u8; 32]),
            NegativeToken::BadBase64UrlSegment,
        );
        let parts = jwt_parts(&value);

        assert_eq!(parts.len(), 3);
        assert_eq!(decode_object_segment(parts[0])["alg"], "RS256");
        assert_eq!(parts[1], SCANNER_SAFE_INVALID_TOKEN_SEGMENT);
        assert!(URL_SAFE_NO_PAD.decode(parts[1]).is_err());
        assert!(!parts[2].is_empty());
    }

    #[test]
    fn negative_invalid_header_shape_keeps_payload_and_signature() {
        let value = generate_negative_token(
            "svc",
            TokenKind::OAuthAccessToken,
            Seed::new([33u8; 32]),
            NegativeToken::InvalidJwtHeaderShape,
        );
        let parts = jwt_parts(&value);

        assert_eq!(parts.len(), 3);
        assert_eq!(
            decode_json_segment(parts[0]),
            serde_json::json!(["not-a-header"])
        );
        assert_eq!(decode_object_segment(parts[1])["sub"], "svc");
        assert!(!parts[2].is_empty());
    }

    #[test]
    fn negative_missing_alg_keeps_typ_and_claims() {
        let value = generate_negative_token(
            "svc",
            TokenKind::OAuthAccessToken,
            Seed::new([34u8; 32]),
            NegativeToken::MissingAlg,
        );
        let parts = jwt_parts(&value);
        let header = decode_object_segment(parts[0]);

        assert_eq!(parts.len(), 3);
        assert!(!header.contains_key("alg"));
        assert_eq!(header["typ"], "JWT");
        assert_eq!(decode_object_segment(parts[1])["sub"], "svc");
    }

    #[test]
    fn negative_alg_none_changes_alg_only() {
        let value = generate_negative_token(
            "svc",
            TokenKind::OAuthAccessToken,
            Seed::new([35u8; 32]),
            NegativeToken::AlgNone,
        );
        let parts = jwt_parts(&value);
        let header = decode_object_segment(parts[0]);

        assert_eq!(parts.len(), 3);
        assert_eq!(header["alg"], "none");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(decode_object_segment(parts[1])["sub"], "svc");
    }

    #[test]
    fn negative_mismatched_kid_keeps_header_and_payload_context() {
        let value = generate_negative_token(
            "svc",
            TokenKind::OAuthAccessToken,
            Seed::new([36u8; 32]),
            NegativeToken::MismatchedKid,
        );
        let parts = jwt_parts(&value);
        let header = decode_object_segment(parts[0]);
        let payload = decode_object_segment(parts[1]);

        assert_eq!(parts.len(), 3);
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], "unknown-kid");
        assert_eq!(payload["sub"], "svc");
        assert_eq!(payload["kid"], "expected-kid");
        assert_ne!(header["kid"], payload["kid"]);
    }

    #[test]
    fn negative_not_yet_valid_keeps_future_window_and_subject() {
        let value = generate_negative_token(
            "svc",
            TokenKind::OAuthAccessToken,
            Seed::new([37u8; 32]),
            NegativeToken::NotYetValidClaims,
        );
        let parts = jwt_parts(&value);
        let header = decode_object_segment(parts[0]);
        let payload = decode_object_segment(parts[1]);

        assert_eq!(parts.len(), 3);
        assert_eq!(header["alg"], "RS256");
        assert_eq!(payload["sub"], "svc");
        assert_eq!(payload["nbf"], 4_000_000_000u64);
        assert_eq!(payload["exp"], 4_100_000_000u64);
    }

    fn jwt_parts(value: &str) -> Vec<&str> {
        value.split('.').collect()
    }

    fn decode_object_segment(segment: &str) -> serde_json::Map<String, serde_json::Value> {
        decode_json_segment(segment)
            .as_object()
            .expect("JWT segment should decode to an object")
            .clone()
    }

    fn decode_json_segment(segment: &str) -> serde_json::Value {
        let bytes = URL_SAFE_NO_PAD.decode(segment).expect("decode JWT segment");
        serde_json::from_slice(&bytes).expect("parse JWT segment JSON")
    }

    #[test]
    fn random_base62_length_and_charset() {
        let value = random_base62(Seed::new([17u8; 32]), 64);
        assert_eq!(value.len(), 64);
        assert!(value.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    proptest! {
        #[test]
        fn api_key_same_seed_stable(seed in any::<[u8; 32]>()) {
            let a = generate_api_key(Seed::new(seed));
            let b = generate_api_key(Seed::new(seed));
            prop_assert_eq!(a, b);
        }

        #[test]
        fn bearer_token_always_43_chars(seed in any::<[u8; 32]>()) {
            let token = generate_bearer_token(Seed::new(seed));
            prop_assert_eq!(token.len(), 43);
        }

        #[test]
        fn oauth_has_three_segments(seed in any::<[u8; 32]>(), label in "[a-z0-9_-]{1,16}") {
            let token = generate_oauth_access_token(&label, Seed::new(seed));
            prop_assert_eq!(token.matches('.').count(), 2);
        }
    }
}
