//! JWT Integration Tests
//!
//! Tests cross-crate JWT functionality:
//! - JWT signing/verification flows across different key types
//! - JWT with JWKS for key lookup
//! - Cross-crate compatibility between uselesskey-jsonwebtoken and other key crates
//! - JWT with different crypto backends (ring, aws-lc-rs, rustcrypto)

mod testutil;

use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use jsonwebtoken::jwk::Jwk;
use serde::{Deserialize, Serialize};
use testutil::fx;
use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
use uselesskey_jsonwebtoken::JwtKeyExt;
use uselesskey_jwk::{AnyJwk, JwksBuilder};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct JwtClaims {
    sub: String,
    exp: usize,
    iat: usize,
    iss: String,
}

impl JwtClaims {
    fn new(sub: &str, exp: usize, iat: usize, iss: &str) -> Self {
        Self {
            sub: sub.to_string(),
            exp,
            iat,
            iss: iss.to_string(),
        }
    }
}

// =========================================================================
// RSA JWT Integration Tests
// =========================================================================

#[cfg(feature = "jwt")]
mod rsa_jwt_tests {
    use super::*;

    #[test]
    fn test_rsa_rs256_sign_verify() {
        let fx = fx();
        let keypair = fx.rsa("test-rs256", RsaSpec::rs256());

        let claims = JwtClaims::new("user123", 9999999999, 1234567890, "test-issuer");
        let header = Header::new(Algorithm::RS256);

        let token = encode(&header, &claims, &keypair.encoding_key())
            .unwrap_or_else(|e| panic!("Failed to encode with RS256: {:?}", e));

        let validation = Validation::new(Algorithm::RS256);
        let decoded = decode::<JwtClaims>(&token, &keypair.decoding_key(), &validation)
            .unwrap_or_else(|e| panic!("Failed to decode with RS256: {:?}", e));

        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn test_rsa_custom_key_sizes() {
        let test_cases = [
            (2048, "rsa-2048"),
            (3072, "rsa-3072"),
            (4096, "rsa-4096"),
        ];

        for (bits, label) in test_cases {
            let fx = fx();
            let keypair = fx.rsa(label, RsaSpec::new(bits));

            let claims = JwtClaims::new("user123", 9999999999, 1234567890, label);
            let header = Header::new(Algorithm::RS256);

            let token = encode(&header, &claims, &keypair.encoding_key())
                .unwrap_or_else(|e| panic!("Failed to encode with {}-bit key: {:?}", bits, e));

            let validation = Validation::new(Algorithm::RS256);
            let decoded = decode::<JwtClaims>(&token, &keypair.decoding_key(), &validation)
                .unwrap_or_else(|e| panic!("Failed to decode with {}-bit key: {:?}", bits, e));

            assert_eq!(decoded.claims, claims, "Claims mismatch for {}-bit key", bits);
        }
    }

    #[test]
    fn test_rsa_algorithm_mismatch_fails() {
        let fx = fx();
        let keypair = fx.rsa("mismatch-test", RsaSpec::rs256());

        let claims = JwtClaims::new("user000", 9999999999, 1234567890, "mismatch-test");
        let header = Header::new(Algorithm::RS256);

        let token = encode(&header, &claims, &keypair.encoding_key())
            .expect("Failed to encode JWT");

        // Try to decode with wrong algorithm
        let validation = Validation::new(Algorithm::RS384);
        let result = decode::<JwtClaims>(&token, &keypair.decoding_key(), &validation);

        assert!(result.is_err(), "Should fail with algorithm mismatch");
    }
}

// =========================================================================
// ECDSA JWT Integration Tests
// =========================================================================

#[cfg(feature = "jwt")]
mod ecdsa_jwt_tests {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn test_jwt_ecdsa_es256_sign_verify() {
        let fx = fx();
        let keypair = fx.ecdsa("es256-issuer", EcdsaSpec::Es256);

        let claims = JwtClaims::new("user123", 9999999999, 1234567890, "es256-issuer");
        let header = Header::new(Algorithm::ES256);

        let token = encode(&header, &claims, &keypair.encoding_key())
            .expect("Failed to encode JWT with ES256");

        let validation = Validation::new(Algorithm::ES256);
        let decoded = decode::<JwtClaims>(&token, &keypair.decoding_key(), &validation)
            .expect("Failed to decode JWT with ES256");

        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn test_jwt_ecdsa_es384_sign_verify() {
        let fx = fx();
        let keypair = fx.ecdsa("es384-issuer", EcdsaSpec::Es384);

        let claims = JwtClaims::new("user456", 9999999999, 1234567890, "es384-issuer");
        let header = Header::new(Algorithm::ES384);

        let token = encode(&header, &claims, &keypair.encoding_key())
            .expect("Failed to encode JWT with ES384");

        let validation = Validation::new(Algorithm::ES384);
        let decoded = decode::<JwtClaims>(&token, &keypair.decoding_key(), &validation)
            .expect("Failed to decode JWT with ES384");

        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn test_jwt_ecdsa_algorithm_mismatch_fails() {
        let fx = fx();
        let keypair = fx.ecdsa("es256-mismatch", EcdsaSpec::Es256);

        let claims = JwtClaims::new("user000", 9999999999, 1234567890, "es256-mismatch");
        let header = Header::new(Algorithm::ES256);

        let token = encode(&header, &claims, &keypair.encoding_key())
            .expect("Failed to encode JWT");

        // Try to decode with wrong algorithm
        let validation = Validation::new(Algorithm::ES384);
        let result = decode::<JwtClaims>(&token, &keypair.decoding_key(), &validation);

        assert!(result.is_err(), "Should fail with algorithm mismatch");
    }
}

// =========================================================================
// Ed25519 JWT Integration Tests
// =========================================================================

#[cfg(feature = "jwt")]
mod ed25519_jwt_tests {
    use super::*;
    use uselesskey_ed25519::Ed25519FactoryExt;

    #[test]
    fn test_jwt_ed25519_sign_verify() {
        let fx = fx();
        let keypair = fx.ed25519("ed25519-issuer", Ed25519Spec::new());

        let claims = JwtClaims::new("user123", 9999999999, 1234567890, "ed25519-issuer");
        let header = Header::new(Algorithm::EdDSA);

        let token = encode(&header, &claims, &keypair.encoding_key())
            .expect("Failed to encode JWT with Ed25519");

        let validation = Validation::new(Algorithm::EdDSA);
        let decoded = decode::<JwtClaims>(&token, &keypair.decoding_key(), &validation)
            .expect("Failed to decode JWT with Ed25519");

        assert_eq!(decoded.claims, claims);
    }
}

// =========================================================================
// HMAC JWT Integration Tests
// =========================================================================

#[cfg(feature = "jwt")]
mod hmac_jwt_tests {
    use super::*;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    #[test]
    fn test_jwt_hmac_hs256_sign_verify() {
        let fx = fx();
        let secret = fx.hmac("hs256-issuer", HmacSpec::Hs256);

        let claims = JwtClaims::new("user123", 9999999999, 1234567890, "hs256-issuer");
        let header = Header::new(Algorithm::HS256);

        let token = encode(&header, &claims, &secret.encoding_key())
            .expect("Failed to encode JWT with HS256");

        let validation = Validation::new(Algorithm::HS256);
        let decoded = decode::<JwtClaims>(&token, &secret.decoding_key(), &validation)
            .expect("Failed to decode JWT with HS256");

        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn test_jwt_hmac_hs384_sign_verify() {
        let fx = fx();
        let secret = fx.hmac("hs384-issuer", HmacSpec::Hs384);

        let claims = JwtClaims::new("user456", 9999999999, 1234567890, "hs384-issuer");
        let header = Header::new(Algorithm::HS384);

        let token = encode(&header, &claims, &secret.encoding_key())
            .expect("Failed to encode JWT with HS384");

        let validation = Validation::new(Algorithm::HS384);
        let decoded = decode::<JwtClaims>(&token, &secret.decoding_key(), &validation)
            .expect("Failed to decode JWT with HS384");

        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn test_jwt_hmac_hs512_sign_verify() {
        let fx = fx();
        let secret = fx.hmac("hs512-issuer", HmacSpec::Hs512);

        let claims = JwtClaims::new("user789", 9999999999, 1234567890, "hs512-issuer");
        let header = Header::new(Algorithm::HS512);

        let token = encode(&header, &claims, &secret.encoding_key())
            .expect("Failed to encode JWT with HS512");

        let validation = Validation::new(Algorithm::HS512);
        let decoded = decode::<JwtClaims>(&token, &secret.decoding_key(), &validation)
            .expect("Failed to decode JWT with HS512");

        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn test_jwt_hmac_wrong_secret_fails() {
        let fx = fx();
        let secret1 = fx.hmac("secret1", HmacSpec::Hs256);
        let secret2 = fx.hmac("secret2", HmacSpec::Hs256);

        let claims = JwtClaims::new("user000", 9999999999, 1234567890, "secret1");
        let header = Header::new(Algorithm::HS256);

        let token = encode(&header, &claims, &secret1.encoding_key())
            .expect("Failed to encode JWT");

        // Try to decode with wrong secret
        let validation = Validation::new(Algorithm::HS256);
        let result = decode::<JwtClaims>(&token, &secret2.decoding_key(), &validation);

        assert!(result.is_err(), "Should fail with wrong secret");
    }
}

// =========================================================================
// JWKS Integration Tests
// =========================================================================

#[cfg(feature = "jwt")]
mod jwks_integration_tests {
    use super::*;

    #[test]
    fn test_jwt_jwks_multi_key_lookup() {
        let fx = fx();

        // Create multiple keys for different issuers
        let issuer1 = fx.rsa("issuer1", RsaSpec::rs256());
        let issuer2 = fx.rsa("issuer2", RsaSpec::rs256());
        let issuer3 = fx.rsa("issuer3", RsaSpec::rs256());

        // Build JWKS with all keys
        let jwks = JwksBuilder::new()
            .add_public(issuer1.public_jwk().into())
            .add_public(issuer2.public_jwk().into())
            .add_public(issuer3.public_jwk().into())
            .build();

        // Verify all keys are in JWKS
        assert_eq!(jwks.keys.len(), 3);

        // Sign JWT with issuer2
        let claims = JwtClaims::new("user123", 9999999999, 1234567890, "issuer2");
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(issuer2.kid().to_string());

        let token = encode(&header, &claims, &issuer2.encoding_key())
            .expect("Failed to encode JWT");

        // Find correct key from JWKS by kid
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid() == issuer2.kid())
            .expect("Key not found in JWKS");

        // Convert AnyJwk to jsonwebtoken::Jwk
        let jwk_value = serde_json::to_value(jwk).expect("Failed to serialize JWK");
        let jwk_json: Jwk = serde_json::from_value(jwk_value)
            .expect("Failed to deserialize JWK");

        // Convert JWK to DecodingKey
        let decoding_key = DecodingKey::from_jwk(&jwk_json)
            .expect("Failed to create DecodingKey from JWK");

        let validation = Validation::new(Algorithm::RS256);
        let decoded = decode::<JwtClaims>(&token, &decoding_key, &validation)
            .expect("Failed to decode JWT with JWKS key");

        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn test_jwt_jwks_key_rotation_scenario() {
        let fx = fx();

        // Old key (still valid for verification)
        let old_key = fx.rsa("old-key", RsaSpec::rs256());

        // New key (used for signing)
        let new_key = fx.rsa("new-key", RsaSpec::rs256());

        // Build JWKS with both keys
        let jwks = JwksBuilder::new()
            .add_public(old_key.public_jwk().into())
            .add_public(new_key.public_jwk().into())
            .build();

        // Sign JWT with new key
        let claims = JwtClaims::new("user123", 9999999999, 1234567890, "new-key");
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(new_key.kid().to_string());

        let token = encode(&header, &claims, &new_key.encoding_key())
            .expect("Failed to encode JWT");

        // Verify with JWKS (should find new key)
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid() == new_key.kid())
            .expect("New key not found in JWKS");

        // Convert AnyJwk to jsonwebtoken::Jwk
        let jwk_value = serde_json::to_value(jwk).expect("Failed to serialize JWK");
        let jwk_json: Jwk = serde_json::from_value(jwk_value)
            .expect("Failed to deserialize JWK");

        let decoding_key = DecodingKey::from_jwk(&jwk_json)
            .expect("Failed to create DecodingKey from JWK");

        let validation = Validation::new(Algorithm::RS256);
        let decoded = decode::<JwtClaims>(&token, &decoding_key, &validation)
            .expect("Failed to decode JWT with JWKS key");

        assert_eq!(decoded.claims, claims);

        // Verify old key is still in JWKS for validating old tokens
        assert!(jwks.keys.iter().any(|k| k.kid() == old_key.kid()));
    }
}

// =========================================================================
// Cross-Crate Compatibility Tests
// =========================================================================

#[cfg(feature = "jwt")]
mod cross_crate_compatibility_tests {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::Ed25519FactoryExt;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    #[test]
    fn test_all_key_types_produce_valid_jwts() {
        let fx = fx();

        let test_cases = vec![
            ("rsa", Algorithm::RS256),
            ("ecdsa", Algorithm::ES256),
            ("ed25519", Algorithm::EdDSA),
            ("hmac", Algorithm::HS256),
        ];

        for (key_type, alg) in test_cases {
            let claims = JwtClaims::new(
                "user123",
                9999999999,
                1234567890,
                &format!("{}-issuer", key_type),
            );
            let header = Header::new(alg);

            let token = match key_type {
                "rsa" => {
                    let keypair = fx.rsa("rsa-issuer", RsaSpec::rs256());
                    encode(&header, &claims, &keypair.encoding_key())
                }
                "ecdsa" => {
                    let keypair = fx.ecdsa("ecdsa-issuer", EcdsaSpec::Es256);
                    encode(&header, &claims, &keypair.encoding_key())
                }
                "ed25519" => {
                    let keypair = fx.ed25519("ed25519-issuer", Ed25519Spec::new());
                    encode(&header, &claims, &keypair.encoding_key())
                }
                "hmac" => {
                    let secret = fx.hmac("hmac-issuer", HmacSpec::Hs256);
                    encode(&header, &claims, &secret.encoding_key())
                }
                _ => panic!("Unknown key type: {}", key_type),
            }
            .expect(&format!("Failed to encode JWT with {}", key_type));

            // Verify token can be decoded
            let validation = Validation::new(alg);
            let decoded = match key_type {
                "rsa" => {
                    let keypair = fx.rsa("rsa-issuer", RsaSpec::rs256());
                    decode::<JwtClaims>(&token, &keypair.decoding_key(), &validation)
                }
                "ecdsa" => {
                    let keypair = fx.ecdsa("ecdsa-issuer", EcdsaSpec::Es256);
                    decode::<JwtClaims>(&token, &keypair.decoding_key(), &validation)
                }
                "ed25519" => {
                    let keypair = fx.ed25519("ed25519-issuer", Ed25519Spec::new());
                    decode::<JwtClaims>(&token, &keypair.decoding_key(), &validation)
                }
                "hmac" => {
                    let secret = fx.hmac("hmac-issuer", HmacSpec::Hs256);
                    decode::<JwtClaims>(&token, &secret.decoding_key(), &validation)
                }
                _ => panic!("Unknown key type: {}", key_type),
            }
            .expect(&format!("Failed to decode JWT with {}", key_type));

            assert_eq!(decoded.claims, claims);
        }
    }

    #[test]
    fn test_key_id_consistency_across_formats() {
        let fx = fx();
        let keypair = fx.rsa("kid-test", RsaSpec::rs256());

        // Verify kid is consistent across different formats
        let kid_from_keypair = keypair.kid();
        let public_jwk = keypair.public_jwk();
        let kid_from_jwk = public_jwk.kid();
        let public_jwks = keypair.public_jwks();
        let kid_from_jwks = public_jwks.keys[0].kid();

        assert_eq!(kid_from_keypair, kid_from_jwk);
        assert_eq!(kid_from_keypair, kid_from_jwks);
    }
}

// =========================================================================
// Determinism Tests
// =========================================================================

#[cfg(feature = "jwt")]
mod determinism_tests {
    use super::*;

    #[test]
    fn test_deterministic_keys_produce_same_jwts() {
        let fx1 = fx();
        let fx2 = fx();

        // Generate same key from same seed
        let keypair1 = fx1.rsa("deterministic-jwt", RsaSpec::rs256());
        let keypair2 = fx2.rsa("deterministic-jwt", RsaSpec::rs256());

        // Sign same claims with both keys
        let claims = JwtClaims::new("user123", 9999999999, 1234567890, "deterministic-jwt");
        let header = Header::new(Algorithm::RS256);

        let token1 = encode(&header, &claims, &keypair1.encoding_key())
            .expect("Failed to encode JWT 1");
        let token2 = encode(&header, &claims, &keypair2.encoding_key())
            .expect("Failed to encode JWT 2");

        // Tokens should be identical (same key + same claims)
        assert_eq!(token1, token2, "Deterministic keys should produce identical JWTs");

        // Verify both tokens decode correctly
        let validation = Validation::new(Algorithm::RS256);
        let decoded1 = decode::<JwtClaims>(&token1, &keypair1.decoding_key(), &validation)
            .expect("Failed to decode JWT 1");
        let decoded2 = decode::<JwtClaims>(&token2, &keypair2.decoding_key(), &validation)
            .expect("Failed to decode JWT 2");

        assert_eq!(decoded1.claims, claims);
        assert_eq!(decoded2.claims, claims);
    }

    #[test]
    fn test_different_labels_produce_different_jwts() {
        let fx = fx();

        // Generate keys with different labels
        let keypair1 = fx.rsa("label-1", RsaSpec::rs256());
        let keypair2 = fx.rsa("label-2", RsaSpec::rs256());

        // Sign same claims with both keys
        let claims = JwtClaims::new("user123", 9999999999, 1234567890, "test");
        let header = Header::new(Algorithm::RS256);

        let token1 = encode(&header, &claims, &keypair1.encoding_key())
            .expect("Failed to encode JWT 1");
        let token2 = encode(&header, &claims, &keypair2.encoding_key())
            .expect("Failed to encode JWT 2");

        // Tokens should be different (different keys)
        assert_ne!(token1, token2, "Different labels should produce different JWTs");
    }
}
