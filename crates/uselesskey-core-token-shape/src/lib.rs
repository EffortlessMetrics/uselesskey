#![forbid(unsafe_code)]

//! Token shape generation primitives for test fixtures.
//!
//! Generates realistic-looking API keys, bearer tokens, and OAuth access
//! tokens from deterministic seed material.
//!
//! # Examples
//!
//! ```
//! use uselesskey_core_token_shape::{generate_token, TokenKind, authorization_scheme};
//! use uselesskey_core_seed::Seed;
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
//! ```

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};

use serde_json::json;
pub use uselesskey_core_base62::random_base62;
use uselesskey_core_seed::Seed;

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

/// Token shape kind.
pub use uselesskey_token_spec::TokenSpec as TokenKind;

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

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use proptest::prelude::*;
    use uselesskey_core_seed::Seed;

    use super::{
        API_KEY_PREFIX, API_KEY_RANDOM_LEN, BEARER_RANDOM_BYTES, TokenKind, authorization_scheme,
        generate_api_key, generate_bearer_token, generate_oauth_access_token, generate_token,
    };
    use uselesskey_core_base62::random_base62;

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
