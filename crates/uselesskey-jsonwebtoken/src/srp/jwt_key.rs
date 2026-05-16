use jsonwebtoken::{DecodingKey, EncodingKey};

/// Extension trait for uselesskey keypairs to produce jsonwebtoken keys.
///
/// This trait is implemented for RSA, ECDSA, Ed25519 keypairs, and HMAC secrets
/// when the corresponding features are enabled.
pub trait JwtKeyExt {
    /// Create a `jsonwebtoken::EncodingKey` for signing JWTs.
    ///
    /// # Panics
    ///
    /// Panics if the key cannot be parsed (should not happen with valid uselesskey fixtures).
    fn encoding_key(&self) -> EncodingKey;

    /// Create a `jsonwebtoken::DecodingKey` for verifying JWTs.
    ///
    /// # Panics
    ///
    /// Panics if the key cannot be parsed (should not happen with valid uselesskey fixtures).
    fn decoding_key(&self) -> DecodingKey;
}
