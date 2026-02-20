//! Comprehensive tests for uselesskey-jsonwebtoken integration
//!
//! Tests cover:
//! - JWT encoding/decoding with all key types
//! - Error handling for mismatched algorithms
//! - Key conversion edge cases
//! - Cross-key type validation failures
//! - Deterministic key behavior
//! - Negative test cases

mod testutil;

use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, encode, errors::ErrorKind};
use serde::{Deserialize, Serialize};
use testutil::fx;
use uselesskey_core::{Factory, Seed};
use uselesskey_jsonwebtoken::JwtKeyExt;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TestClaims {
    sub: String,
    exp: usize,
    iat: usize,
    iss: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    custom: Option<String>,
}

impl TestClaims {
    fn new(sub: &str, exp: usize, iat: usize, iss: &str) -> Self {
        Self {
            sub: sub.to_string(),
            exp,
            iat,
            iss: iss.to_string(),
            custom: None,
        }
    }

    fn with_custom(mut self, custom: &str) -> Self {
        self.custom = Some(custom.to_string());
        self
    }
}

#[cfg(feature = "rsa")]
mod rsa_tests {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn test_rsa_rs256_algorithm() {
        let fx = fx();
        let keypair = fx.rsa("test-rs256", RsaSpec::rs256());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer");
        let header = Header::new(Algorithm::RS256);

        let token = encode(&header, &claims, &keypair.encoding_key())
            .unwrap_or_else(|e| panic!("Failed to encode with RS256: {:?}", e));

        let validation = Validation::new(Algorithm::RS256);
        let decoded = decode::<TestClaims>(&token, &keypair.decoding_key(), &validation)
            .unwrap_or_else(|e| panic!("Failed to decode with RS256: {:?}", e));

        assert_eq!(decoded.claims, claims, "Claims mismatch for RS256");
    }

    #[test]
    fn test_rsa_custom_key_sizes() {
        let test_cases = [(2048, "rsa-2048"), (3072, "rsa-3072"), (4096, "rsa-4096")];

        for (bits, label) in test_cases {
            let fx = fx();
            let keypair = fx.rsa(label, RsaSpec::new(bits));

            let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, label);
            let header = Header::new(Algorithm::RS256);

            let token = encode(&header, &claims, &keypair.encoding_key())
                .unwrap_or_else(|e| panic!("Failed to encode with {}-bit key: {:?}", bits, e));

            let validation = Validation::new(Algorithm::RS256);
            let decoded = decode::<TestClaims>(&token, &keypair.decoding_key(), &validation)
                .unwrap_or_else(|e| panic!("Failed to decode with {}-bit key: {:?}", bits, e));

            assert_eq!(
                decoded.claims, claims,
                "Claims mismatch for {}-bit key",
                bits
            );
        }
    }

    #[test]
    fn test_rsa_algorithm_mismatch_fails() {
        let fx = fx();
        let keypair = fx.rsa("test-mismatch", RsaSpec::rs256());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer");

        // Sign with RS256
        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

        // Try to decode with RS384 validation (even though we don't support RS384, this tests validation)
        let validation = Validation::new(Algorithm::RS384);
        let result = decode::<TestClaims>(&token, &keypair.decoding_key(), &validation);

        assert!(result.is_err(), "Decoding with wrong algorithm should fail");
        match result.unwrap_err().kind() {
            ErrorKind::InvalidAlgorithm => {} // Expected
            other => panic!("Expected InvalidAlgorithm error, got: {:?}", other),
        }
    }

    #[test]
    fn test_rsa_cross_key_validation_fails() {
        let fx = fx();
        let key_a = fx.rsa("issuer-a", RsaSpec::rs256());
        let key_b = fx.rsa("issuer-b", RsaSpec::rs256());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "issuer-a");

        // Sign with key_a
        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, &key_a.encoding_key()).unwrap();

        // Try to decode with key_b
        let validation = Validation::new(Algorithm::RS256);
        let result = decode::<TestClaims>(&token, &key_b.decoding_key(), &validation);

        assert!(result.is_err(), "Decoding with wrong key should fail");
        match result.unwrap_err().kind() {
            ErrorKind::InvalidSignature => {} // Expected
            other => panic!("Expected InvalidSignature error, got: {:?}", other),
        }
    }

    #[test]
    fn test_rsa_mismatched_key_rejects_signature() {
        let fx = fx();
        let rsa = fx.rsa("mismatch-test", RsaSpec::rs256());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer");
        let header = Header::new(Algorithm::RS256);

        // Sign a token with the real private key
        let token = encode(&header, &claims, &rsa.encoding_key()).unwrap();

        // Build a DecodingKey from the mismatched public key DER
        let mismatched_der = rsa.mismatched_public_key_spki_der();
        let mismatched_decoding_key = DecodingKey::from_rsa_der(&mismatched_der);

        // Attempting to verify with the mismatched key should fail
        let validation = Validation::new(Algorithm::RS256);
        let result = decode::<TestClaims>(&token, &mismatched_decoding_key, &validation);

        assert!(
            result.is_err(),
            "Decoding with mismatched public key should fail"
        );
        match result.unwrap_err().kind() {
            ErrorKind::InvalidSignature => {} // Expected
            other => panic!("Expected InvalidSignature error, got: {:?}", other),
        }
    }

    #[test]
    fn test_rsa_deterministic_keys() {
        let seed = Seed::from_env_value("deterministic-test-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let key1 = fx1.rsa("deterministic-test", RsaSpec::rs256());
        let key2 = fx2.rsa("deterministic-test", RsaSpec::rs256());

        // Keys should be identical
        assert_eq!(
            key1.private_key_pkcs8_pem(),
            key2.private_key_pkcs8_pem(),
            "Deterministic keys should be identical"
        );

        // Test JWT creation with deterministic keys
        let claims = TestClaims::new("det-user", 2_000_000_000, 1234567890, "det-issuer");
        let header = Header::new(Algorithm::RS256);

        let token1 = encode(&header, &claims, &key1.encoding_key()).unwrap();
        let token2 = encode(&header, &claims, &key2.encoding_key()).unwrap();

        // Tokens should be identical when using identical keys and claims
        assert_eq!(
            token1, token2,
            "Tokens should be identical with deterministic keys"
        );

        // Both tokens should decode correctly
        let validation = Validation::new(Algorithm::RS256);
        let decoded1 = decode::<TestClaims>(&token1, &key1.decoding_key(), &validation).unwrap();
        let decoded2 = decode::<TestClaims>(&token2, &key2.decoding_key(), &validation).unwrap();

        assert_eq!(decoded1.claims, claims);
        assert_eq!(decoded2.claims, claims);
    }

    #[test]
    fn test_rsa_key_conversion_edge_cases() {
        let fx = fx();
        let keypair = fx.rsa("edge-case-test", RsaSpec::rs256());

        // Test that encoding and decoding keys can be created multiple times
        let enc_key1 = keypair.encoding_key();
        let enc_key2 = keypair.encoding_key();
        let dec_key1 = keypair.decoding_key();
        let dec_key2 = keypair.decoding_key();

        // Keys should be functionally identical
        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer");
        let header = Header::new(Algorithm::RS256);

        let token1 = encode(&header, &claims, &enc_key1).unwrap();
        let token2 = encode(&header, &claims, &enc_key2).unwrap();

        // Tokens should be identical
        assert_eq!(token1, token2);

        // Both decoding keys should work
        let validation = Validation::new(Algorithm::RS256);
        let decoded1 = decode::<TestClaims>(&token1, &dec_key1, &validation).unwrap();
        let decoded2 = decode::<TestClaims>(&token2, &dec_key2, &validation).unwrap();

        assert_eq!(decoded1.claims, claims);
        assert_eq!(decoded2.claims, claims);
    }
}

#[cfg(feature = "ecdsa")]
mod ecdsa_tests {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn test_ecdsa_es256_algorithm() {
        let fx = fx();
        let keypair = fx.ecdsa("test-es256", EcdsaSpec::es256());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer");
        let header = Header::new(Algorithm::ES256);

        let token = encode(&header, &claims, &keypair.encoding_key())
            .unwrap_or_else(|e| panic!("Failed to encode with ES256: {:?}", e));

        let validation = Validation::new(Algorithm::ES256);
        let decoded = decode::<TestClaims>(&token, &keypair.decoding_key(), &validation)
            .unwrap_or_else(|e| panic!("Failed to decode with ES256: {:?}", e));

        assert_eq!(decoded.claims, claims, "Claims mismatch for ES256");
    }

    #[test]
    fn test_ecdsa_es384_algorithm() {
        let fx = fx();
        let keypair = fx.ecdsa("test-es384", EcdsaSpec::es384());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer");
        let header = Header::new(Algorithm::ES384);

        let token = encode(&header, &claims, &keypair.encoding_key())
            .unwrap_or_else(|e| panic!("Failed to encode with ES384: {:?}", e));

        let validation = Validation::new(Algorithm::ES384);
        let decoded = decode::<TestClaims>(&token, &keypair.decoding_key(), &validation)
            .unwrap_or_else(|e| panic!("Failed to decode with ES384: {:?}", e));

        assert_eq!(decoded.claims, claims, "Claims mismatch for ES384");
    }

    #[test]
    fn test_ecdsa_algorithm_mismatch_fails() {
        let fx = fx();
        let keypair = fx.ecdsa("test-mismatch", EcdsaSpec::es256());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer");

        // Sign with ES256
        let header = Header::new(Algorithm::ES256);
        let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

        // Try to decode with ES384 validation
        let validation = Validation::new(Algorithm::ES384);
        let result = decode::<TestClaims>(&token, &keypair.decoding_key(), &validation);

        assert!(result.is_err(), "Decoding with wrong algorithm should fail");
        match result.unwrap_err().kind() {
            ErrorKind::InvalidAlgorithm => {} // Expected
            other => panic!("Expected InvalidAlgorithm error, got: {:?}", other),
        }
    }

    #[test]
    fn test_ecdsa_cross_key_validation_fails() {
        let fx = fx();
        let key_a = fx.ecdsa("issuer-a", EcdsaSpec::es256());
        let key_b = fx.ecdsa("issuer-b", EcdsaSpec::es256());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "issuer-a");

        // Sign with key_a
        let header = Header::new(Algorithm::ES256);
        let token = encode(&header, &claims, &key_a.encoding_key()).unwrap();

        // Try to decode with key_b
        let validation = Validation::new(Algorithm::ES256);
        let result = decode::<TestClaims>(&token, &key_b.decoding_key(), &validation);

        assert!(result.is_err(), "Decoding with wrong key should fail");
        match result.unwrap_err().kind() {
            ErrorKind::InvalidSignature => {} // Expected
            other => panic!("Expected InvalidSignature error, got: {:?}", other),
        }
    }
}

#[cfg(feature = "ed25519")]
mod ed25519_tests {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn test_ed25519_sign_and_verify() {
        let fx = fx();
        let keypair = fx.ed25519("test-ed25519", Ed25519Spec::new());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer")
            .with_custom("ed25519-test");

        let header = Header::new(Algorithm::EdDSA);
        let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

        let validation = Validation::new(Algorithm::EdDSA);
        let decoded = decode::<TestClaims>(&token, &keypair.decoding_key(), &validation).unwrap();

        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn test_ed25519_cross_key_validation_fails() {
        let fx = fx();
        let key_a = fx.ed25519("issuer-a", Ed25519Spec::new());
        let key_b = fx.ed25519("issuer-b", Ed25519Spec::new());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "issuer-a");

        // Sign with key_a
        let header = Header::new(Algorithm::EdDSA);
        let token = encode(&header, &claims, &key_a.encoding_key()).unwrap();

        // Try to decode with key_b
        let validation = Validation::new(Algorithm::EdDSA);
        let result = decode::<TestClaims>(&token, &key_b.decoding_key(), &validation);

        assert!(result.is_err(), "Decoding with wrong key should fail");
        match result.unwrap_err().kind() {
            ErrorKind::InvalidSignature => {} // Expected
            other => panic!("Expected InvalidSignature error, got: {:?}", other),
        }
    }

    #[test]
    fn test_ed25519_algorithm_mismatch_fails() {
        let fx = fx();
        let keypair = fx.ed25519("test-mismatch", Ed25519Spec::new());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer");

        // Sign with EdDSA
        let header = Header::new(Algorithm::EdDSA);
        let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

        // Try to decode with RS256 validation (completely different algorithm family)
        let validation = Validation::new(Algorithm::RS256);
        let result = decode::<TestClaims>(&token, &keypair.decoding_key(), &validation);

        assert!(result.is_err(), "Decoding with wrong algorithm should fail");
        match result.unwrap_err().kind() {
            ErrorKind::InvalidAlgorithm => {} // Expected
            other => panic!("Expected InvalidAlgorithm error, got: {:?}", other),
        }
    }
}

#[cfg(feature = "hmac")]
mod hmac_tests {
    use super::*;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    #[test]
    fn test_hmac_hs256_algorithm() {
        let fx = fx();
        let secret = fx.hmac("test-hs256", HmacSpec::hs256());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer");
        let header = Header::new(Algorithm::HS256);

        let token = encode(&header, &claims, &secret.encoding_key())
            .unwrap_or_else(|e| panic!("Failed to encode with HS256: {:?}", e));

        let validation = Validation::new(Algorithm::HS256);
        let decoded = decode::<TestClaims>(&token, &secret.decoding_key(), &validation)
            .unwrap_or_else(|e| panic!("Failed to decode with HS256: {:?}", e));

        assert_eq!(decoded.claims, claims, "Claims mismatch for HS256");
    }

    #[test]
    fn test_hmac_hs384_algorithm() {
        let fx = fx();
        let secret = fx.hmac("test-hs384", HmacSpec::hs384());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer");
        let header = Header::new(Algorithm::HS384);

        let token = encode(&header, &claims, &secret.encoding_key())
            .unwrap_or_else(|e| panic!("Failed to encode with HS384: {:?}", e));

        let validation = Validation::new(Algorithm::HS384);
        let decoded = decode::<TestClaims>(&token, &secret.decoding_key(), &validation)
            .unwrap_or_else(|e| panic!("Failed to decode with HS384: {:?}", e));

        assert_eq!(decoded.claims, claims, "Claims mismatch for HS384");
    }

    #[test]
    fn test_hmac_hs512_algorithm() {
        let fx = fx();
        let secret = fx.hmac("test-hs512", HmacSpec::hs512());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer");
        let header = Header::new(Algorithm::HS512);

        let token = encode(&header, &claims, &secret.encoding_key())
            .unwrap_or_else(|e| panic!("Failed to encode with HS512: {:?}", e));

        let validation = Validation::new(Algorithm::HS512);
        let decoded = decode::<TestClaims>(&token, &secret.decoding_key(), &validation)
            .unwrap_or_else(|e| panic!("Failed to decode with HS512: {:?}", e));

        assert_eq!(decoded.claims, claims, "Claims mismatch for HS512");
    }

    #[test]
    fn test_hmac_algorithm_mismatch_fails() {
        let fx = fx();
        let secret = fx.hmac("test-mismatch", HmacSpec::hs256());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer");

        // Sign with HS256
        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &secret.encoding_key()).unwrap();

        // Try to decode with HS384 validation
        let validation = Validation::new(Algorithm::HS384);
        let result = decode::<TestClaims>(&token, &secret.decoding_key(), &validation);

        assert!(result.is_err(), "Decoding with wrong algorithm should fail");
        match result.unwrap_err().kind() {
            ErrorKind::InvalidAlgorithm => {} // Expected
            other => panic!("Expected InvalidAlgorithm error, got: {:?}", other),
        }
    }

    #[test]
    fn test_hmac_cross_secret_validation_fails() {
        let fx = fx();
        let secret_a = fx.hmac("secret-a", HmacSpec::hs256());
        let secret_b = fx.hmac("secret-b", HmacSpec::hs256());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer");

        // Sign with secret_a
        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &secret_a.encoding_key()).unwrap();

        // Try to decode with secret_b
        let validation = Validation::new(Algorithm::HS256);
        let result = decode::<TestClaims>(&token, &secret_b.decoding_key(), &validation);

        assert!(result.is_err(), "Decoding with wrong secret should fail");
        match result.unwrap_err().kind() {
            ErrorKind::InvalidSignature => {} // Expected
            other => panic!("Expected InvalidSignature error, got: {:?}", other),
        }
    }

    #[test]
    fn test_hmac_deterministic_secrets() {
        let seed = Seed::from_env_value("hmac-deterministic-test-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let secret1 = fx1.hmac("deterministic-test", HmacSpec::hs256());
        let secret2 = fx2.hmac("deterministic-test", HmacSpec::hs256());

        // Secrets should be identical
        assert_eq!(
            secret1.secret_bytes(),
            secret2.secret_bytes(),
            "Deterministic secrets should be identical"
        );

        // Test JWT creation with deterministic secrets
        let claims = TestClaims::new("det-user", 2_000_000_000, 1234567890, "det-issuer");
        let header = Header::new(Algorithm::HS256);

        let token1 = encode(&header, &claims, &secret1.encoding_key()).unwrap();
        let token2 = encode(&header, &claims, &secret2.encoding_key()).unwrap();

        // Tokens should be identical when using identical secrets and claims
        assert_eq!(
            token1, token2,
            "Tokens should be identical with deterministic secrets"
        );

        // Both tokens should decode correctly
        let validation = Validation::new(Algorithm::HS256);
        let decoded1 = decode::<TestClaims>(&token1, &secret1.decoding_key(), &validation).unwrap();
        let decoded2 = decode::<TestClaims>(&token2, &secret2.decoding_key(), &validation).unwrap();

        assert_eq!(decoded1.claims, claims);
        assert_eq!(decoded2.claims, claims);
    }
}

#[cfg(all(feature = "rsa", feature = "ecdsa"))]
mod cross_algorithm_tests {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn test_cross_algorithm_family_fails() {
        let fx = fx();
        let rsa_key = fx.rsa("rsa-test", RsaSpec::rs256());
        let ecdsa_key = fx.ecdsa("ecdsa-test", EcdsaSpec::es256());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer");

        // Sign with RSA
        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, &rsa_key.encoding_key()).unwrap();

        // Try to decode with ECDSA key
        let validation = Validation::new(Algorithm::RS256);
        let result = decode::<TestClaims>(&token, &ecdsa_key.decoding_key(), &validation);

        assert!(
            result.is_err(),
            "Decoding RSA token with ECDSA key should fail"
        );
    }

    #[test]
    fn test_cross_algorithm_validation_fails() {
        let fx = fx();
        let rsa_key = fx.rsa("rsa-test", RsaSpec::rs256());

        let claims = TestClaims::new("user123", 2_000_000_000, 1234567890, "test-issuer");

        // Sign with RSA
        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, &rsa_key.encoding_key()).unwrap();

        // Try to decode with ES256 validation
        let validation = Validation::new(Algorithm::ES256);
        let result = decode::<TestClaims>(&token, &rsa_key.decoding_key(), &validation);

        assert!(
            result.is_err(),
            "Decoding with wrong algorithm validation should fail"
        );
        match result.unwrap_err().kind() {
            ErrorKind::InvalidAlgorithm => {} // Expected
            other => panic!("Expected InvalidAlgorithm error, got: {:?}", other),
        }
    }
}

#[test]
fn test_expired_token_fails() {
    #[cfg(feature = "rsa")]
    {
        use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

        let fx = fx();
        let keypair = fx.rsa("expired-test", RsaSpec::rs256());

        // Create a token that's already expired
        let past_time = 1000000000; // 2001-09-09
        let claims = TestClaims::new("user123", past_time, past_time - 1000, "test-issuer");
        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true; // Ensure expiration is validated

        let result = decode::<TestClaims>(&token, &keypair.decoding_key(), &validation);
        assert!(result.is_err(), "Expired token should fail validation");
        match result.unwrap_err().kind() {
            ErrorKind::ExpiredSignature => {} // Expected
            other => panic!("Expected ExpiredSignature error, got: {:?}", other),
        }
    }
}

#[test]
fn test_malformed_token_fails() {
    #[cfg(feature = "hmac")]
    {
        use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

        let fx = fx();
        let secret = fx.hmac("malformed-test", HmacSpec::hs256());

        let malformed_tokens = [
            "not.a.jwt",
            "invalid.header.payload",
            "header.invalidsignature",
            "too.many.parts.in.this.token.signature",
            "",
            "justonelongstring",
        ];

        let validation = Validation::new(Algorithm::HS256);

        for malformed_token in malformed_tokens {
            let result = decode::<TestClaims>(malformed_token, &secret.decoding_key(), &validation);
            assert!(
                result.is_err(),
                "Malformed token '{}' should fail",
                malformed_token
            );
        }
    }
}
