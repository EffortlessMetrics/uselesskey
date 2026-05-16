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

mod jwt;
mod negative;
mod standard;

pub use negative::{NegativeToken, generate_negative_token};
pub use standard::{generate_api_key, generate_bearer_token, generate_oauth_access_token};

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

/// Generate a token value for the provided shape kind.
pub fn generate_token(label: &str, kind: TokenKind, seed: Seed) -> String {
    match kind {
        TokenKind::ApiKey => generate_api_key(seed),
        TokenKind::Bearer => generate_bearer_token(seed),
        TokenKind::OAuthAccessToken => generate_oauth_access_token(label, seed),
    }
}

/// Return HTTP authorization scheme for the token kind.
pub fn authorization_scheme(kind: TokenKind) -> &'static str {
    kind.authorization_scheme()
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
