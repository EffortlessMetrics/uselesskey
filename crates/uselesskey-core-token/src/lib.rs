#![forbid(unsafe_code)]

//! Deterministic token-shape helpers used by `uselesskey` fixture crates.
//!
//! This crate intentionally focuses on output shape generation:
//! - API key format
//! - opaque bearer token format
//! - OAuth-style JWT-shape access tokens

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::RngCore;

const BASE62: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TokenKind {
    ApiKey,
    Bearer,
    OAuthAccessToken,
}

/// Generate a token value for the provided shape kind.
pub fn generate_token(label: &str, kind: TokenKind, rng: &mut impl RngCore) -> String {
    match kind {
        TokenKind::ApiKey => generate_api_key(rng),
        TokenKind::Bearer => generate_bearer_token(rng),
        TokenKind::OAuthAccessToken => generate_oauth_access_token(label, rng),
    }
}

/// HTTP authorization scheme for the token kind.
pub fn authorization_scheme(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::ApiKey => "ApiKey",
        TokenKind::Bearer | TokenKind::OAuthAccessToken => "Bearer",
    }
}

/// Generate an API-key style token fixture (`uk_test_<base62>`).
pub fn generate_api_key(rng: &mut impl RngCore) -> String {
    let mut out = String::from(API_KEY_PREFIX);
    out.push_str(&random_base62(rng, API_KEY_RANDOM_LEN));
    out
}

/// Generate an opaque bearer token fixture (base64url of 32 random bytes).
pub fn generate_bearer_token(rng: &mut impl RngCore) -> String {
    let mut bytes = [0u8; BEARER_RANDOM_BYTES];
    rng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate an OAuth access token fixture in JWT shape (`header.payload.signature`).
pub fn generate_oauth_access_token(label: &str, rng: &mut impl RngCore) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);

    let mut jti = [0u8; OAUTH_JTI_BYTES];
    rng.fill_bytes(&mut jti);

    let payload = serde_json::json!({
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

/// Generate a random base62 string of the requested length.
pub fn random_base62(rng: &mut impl RngCore, len: usize) -> String {
    let mut out = String::with_capacity(len);
    let mut byte = [0u8; 1];

    while out.len() < len {
        rng.fill_bytes(&mut byte);
        let idx = byte[0] as usize % BASE62.len();
        out.push(BASE62[idx] as char);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn api_key_shape_is_stable() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let value = generate_api_key(&mut rng);

        assert!(value.starts_with(API_KEY_PREFIX));
        let suffix = value
            .strip_prefix(API_KEY_PREFIX)
            .expect("API key prefix should be present");
        assert_eq!(suffix.len(), API_KEY_RANDOM_LEN);
        assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn bearer_shape_decodes_to_32_bytes() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let value = generate_bearer_token(&mut rng);
        let decoded = URL_SAFE_NO_PAD.decode(value).expect("base64url decode");
        assert_eq!(decoded.len(), BEARER_RANDOM_BYTES);
    }

    #[test]
    fn oauth_shape_has_three_segments_and_subject() {
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let value = generate_oauth_access_token("issuer", &mut rng);
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

        let mut rng = ChaCha20Rng::from_seed(seed);
        let api = generate_token("label", TokenKind::ApiKey, &mut rng);

        let mut rng = ChaCha20Rng::from_seed(seed);
        let bearer = generate_token("label", TokenKind::Bearer, &mut rng);

        let mut rng = ChaCha20Rng::from_seed(seed);
        let oauth = generate_token("label", TokenKind::OAuthAccessToken, &mut rng);

        assert_ne!(api, bearer);
        assert_ne!(api, oauth);
        assert_ne!(bearer, oauth);
    }

    #[test]
    fn random_base62_length_and_charset() {
        let mut rng = ChaCha20Rng::from_seed([17u8; 32]);
        let value = random_base62(&mut rng, 64);
        assert_eq!(value.len(), 64);
        assert!(value.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn random_base62_uses_modulo_indexing() {
        struct ByteSeqRng {
            bytes: [u8; 5],
            pos: usize,
        }

        impl ByteSeqRng {
            fn next_byte(&mut self) -> u8 {
                let b = self.bytes[self.pos % self.bytes.len()];
                self.pos += 1;
                b
            }
        }

        impl RngCore for ByteSeqRng {
            fn next_u32(&mut self) -> u32 {
                u32::from_le_bytes([
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                ])
            }

            fn next_u64(&mut self) -> u64 {
                u64::from_le_bytes([
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                ])
            }

            fn fill_bytes(&mut self, dst: &mut [u8]) {
                for b in dst {
                    *b = self.next_byte();
                }
            }

            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dst);
                Ok(())
            }
        }

        let mut rng = ByteSeqRng {
            bytes: [0, 61, 62, 123, 255],
            pos: 0,
        };
        let value = random_base62(&mut rng, 5);

        assert_eq!(value, "A9A9H");
    }
}
