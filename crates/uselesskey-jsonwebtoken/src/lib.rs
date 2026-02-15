#![forbid(unsafe_code)]

//! Integration between uselesskey test fixtures and the `jsonwebtoken` crate.
//!
//! This crate provides extension traits that add `.encoding_key()` and `.decoding_key()`
//! methods to uselesskey keypair types, making it easy to sign and verify JWTs in tests.
//!
//! # Features
//!
//! Enable the key types you need:
//!
//! - `rsa` - RSA keypairs (RS256, RS384, RS512)
//! - `ecdsa` - ECDSA keypairs (ES256, ES384)
//! - `ed25519` - Ed25519 keypairs (EdDSA)
//! - `hmac` - HMAC secrets (HS256, HS384, HS512)
//! - `all` - All of the above
//!
//! # Example: Sign and verify a JWT with RSA
//!
#![cfg_attr(feature = "rsa", doc = "```")]
#![cfg_attr(not(feature = "rsa"), doc = "```ignore")]
//! use uselesskey_core::Factory;
//! use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
//! use uselesskey_jsonwebtoken::JwtKeyExt;
//! use jsonwebtoken::{encode, decode, Header, Algorithm, Validation};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Debug, Serialize, Deserialize)]
//! struct Claims {
//!     sub: String,
//!     exp: usize,
//! }
//!
//! let fx = Factory::random();
//! let keypair = fx.rsa("my-issuer", RsaSpec::rs256());
//!
//! // Sign a JWT
//! let claims = Claims { sub: "user123".to_string(), exp: 2_000_000_000 };
//! let header = Header::new(Algorithm::RS256);
//! let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();
//!
//! // Verify the JWT
//! let validation = Validation::new(Algorithm::RS256);
//! let decoded = decode::<Claims>(&token, &keypair.decoding_key(), &validation).unwrap();
//! assert_eq!(decoded.claims.sub, "user123");
//! ```
//!
//! # Example: Sign and verify with ECDSA
//!
#![cfg_attr(feature = "ecdsa", doc = "```")]
#![cfg_attr(not(feature = "ecdsa"), doc = "```ignore")]
//! use uselesskey_core::Factory;
//! use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
//! use uselesskey_jsonwebtoken::JwtKeyExt;
//! use jsonwebtoken::{encode, decode, Header, Algorithm, Validation};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Debug, Serialize, Deserialize)]
//! struct Claims {
//!     sub: String,
//!     exp: usize,
//! }
//!
//! let fx = Factory::random();
//! let keypair = fx.ecdsa("my-issuer", EcdsaSpec::es256());
//!
//! let claims = Claims { sub: "user123".to_string(), exp: 2_000_000_000 };
//! let header = Header::new(Algorithm::ES256);
//! let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();
//!
//! let validation = Validation::new(Algorithm::ES256);
//! let decoded = decode::<Claims>(&token, &keypair.decoding_key(), &validation).unwrap();
//! assert_eq!(decoded.claims.sub, "user123");
//! ```
//!
//! # Example: Sign and verify with Ed25519
//!
#![cfg_attr(feature = "ed25519", doc = "```")]
#![cfg_attr(not(feature = "ed25519"), doc = "```ignore")]
//! use uselesskey_core::Factory;
//! use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
//! use uselesskey_jsonwebtoken::JwtKeyExt;
//! use jsonwebtoken::{encode, decode, Header, Algorithm, Validation};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Debug, Serialize, Deserialize)]
//! struct Claims {
//!     sub: String,
//!     exp: usize,
//! }
//!
//! let fx = Factory::random();
//! let keypair = fx.ed25519("my-issuer", Ed25519Spec::new());
//!
//! let claims = Claims { sub: "user123".to_string(), exp: 2_000_000_000 };
//! let header = Header::new(Algorithm::EdDSA);
//! let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();
//!
//! let validation = Validation::new(Algorithm::EdDSA);
//! let decoded = decode::<Claims>(&token, &keypair.decoding_key(), &validation).unwrap();
//! assert_eq!(decoded.claims.sub, "user123");
//! ```
//!
//! # Example: Sign and verify with HMAC
//!
#![cfg_attr(feature = "hmac", doc = "```")]
#![cfg_attr(not(feature = "hmac"), doc = "```ignore")]
//! use uselesskey_core::Factory;
//! use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
//! use uselesskey_jsonwebtoken::JwtKeyExt;
//! use jsonwebtoken::{encode, decode, Header, Algorithm, Validation};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Debug, Serialize, Deserialize)]
//! struct Claims {
//!     sub: String,
//!     exp: usize,
//! }
//!
//! let fx = Factory::random();
//! let secret = fx.hmac("my-secret", HmacSpec::hs256());
//!
//! let claims = Claims { sub: "user123".to_string(), exp: 2_000_000_000 };
//! let header = Header::new(Algorithm::HS256);
//! let token = encode(&header, &claims, &secret.encoding_key()).unwrap();
//!
//! let validation = Validation::new(Algorithm::HS256);
//! let decoded = decode::<Claims>(&token, &secret.decoding_key(), &validation).unwrap();
//! assert_eq!(decoded.claims.sub, "user123");
//! ```

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

#[cfg(feature = "rsa")]
impl JwtKeyExt for uselesskey_rsa::RsaKeyPair {
    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_rsa_pem(self.private_key_pkcs8_pem().as_bytes())
            .expect("failed to create EncodingKey from RSA PEM")
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_rsa_pem(self.public_key_spki_pem().as_bytes())
            .expect("failed to create DecodingKey from RSA PEM")
    }
}

#[cfg(feature = "ecdsa")]
impl JwtKeyExt for uselesskey_ecdsa::EcdsaKeyPair {
    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_ec_pem(self.private_key_pkcs8_pem().as_bytes())
            .expect("failed to create EncodingKey from EC PEM")
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_ec_pem(self.public_key_spki_pem().as_bytes())
            .expect("failed to create DecodingKey from EC PEM")
    }
}

#[cfg(feature = "ed25519")]
impl JwtKeyExt for uselesskey_ed25519::Ed25519KeyPair {
    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_ed_pem(self.private_key_pkcs8_pem().as_bytes())
            .expect("failed to create EncodingKey from Ed25519 PEM")
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_ed_pem(self.public_key_spki_pem().as_bytes())
            .expect("failed to create DecodingKey from Ed25519 PEM")
    }
}

#[cfg(feature = "hmac")]
impl JwtKeyExt for uselesskey_hmac::HmacSecret {
    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_secret(self.secret_bytes())
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_secret(self.secret_bytes())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "rsa")]
    mod rsa_tests {
        use crate::JwtKeyExt;
        use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
        use serde::{Deserialize, Serialize};
        use uselesskey_core::Factory;
        use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestClaims {
            sub: String,
            exp: usize,
        }

        #[test]
        fn test_rsa_sign_and_verify() {
            let fx = Factory::random();
            let keypair = fx.rsa("test-issuer", RsaSpec::rs256());

            let claims = TestClaims {
                sub: "user123".to_string(),
                exp: 2_000_000_000,
            };

            let header = Header::new(Algorithm::RS256);
            let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

            let validation = Validation::new(Algorithm::RS256);
            let decoded =
                decode::<TestClaims>(&token, &keypair.decoding_key(), &validation).unwrap();

            assert_eq!(decoded.claims, claims);
        }

        #[test]
        fn test_rsa_deterministic_keys_work() {
            use uselesskey_core::Seed;

            let seed = Seed::from_env_value("test-seed").unwrap();
            let fx = Factory::deterministic(seed);
            let keypair = fx.rsa("deterministic-issuer", RsaSpec::rs256());

            let claims = TestClaims {
                sub: "det-user".to_string(),
                exp: 2_000_000_000,
            };

            let header = Header::new(Algorithm::RS256);
            let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

            let validation = Validation::new(Algorithm::RS256);
            let decoded =
                decode::<TestClaims>(&token, &keypair.decoding_key(), &validation).unwrap();

            assert_eq!(decoded.claims, claims);
        }
    }

    #[cfg(feature = "ecdsa")]
    mod ecdsa_tests {
        use crate::JwtKeyExt;
        use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
        use serde::{Deserialize, Serialize};
        use uselesskey_core::Factory;
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestClaims {
            sub: String,
            exp: usize,
        }

        #[test]
        fn test_ecdsa_es256_sign_and_verify() {
            let fx = Factory::random();
            let keypair = fx.ecdsa("test-issuer", EcdsaSpec::es256());

            let claims = TestClaims {
                sub: "user123".to_string(),
                exp: 2_000_000_000,
            };

            let header = Header::new(Algorithm::ES256);
            let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

            let validation = Validation::new(Algorithm::ES256);
            let decoded =
                decode::<TestClaims>(&token, &keypair.decoding_key(), &validation).unwrap();

            assert_eq!(decoded.claims, claims);
        }

        #[test]
        fn test_ecdsa_es384_sign_and_verify() {
            let fx = Factory::random();
            let keypair = fx.ecdsa("test-issuer", EcdsaSpec::es384());

            let claims = TestClaims {
                sub: "user123".to_string(),
                exp: 2_000_000_000,
            };

            let header = Header::new(Algorithm::ES384);
            let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

            let validation = Validation::new(Algorithm::ES384);
            let decoded =
                decode::<TestClaims>(&token, &keypair.decoding_key(), &validation).unwrap();

            assert_eq!(decoded.claims, claims);
        }
    }

    #[cfg(feature = "ed25519")]
    mod ed25519_tests {
        use crate::JwtKeyExt;
        use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
        use serde::{Deserialize, Serialize};
        use uselesskey_core::Factory;
        use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestClaims {
            sub: String,
            exp: usize,
        }

        #[test]
        fn test_ed25519_sign_and_verify() {
            let fx = Factory::random();
            let keypair = fx.ed25519("test-issuer", Ed25519Spec::new());

            let claims = TestClaims {
                sub: "user123".to_string(),
                exp: 2_000_000_000,
            };

            let header = Header::new(Algorithm::EdDSA);
            let token = encode(&header, &claims, &keypair.encoding_key()).unwrap();

            let validation = Validation::new(Algorithm::EdDSA);
            let decoded =
                decode::<TestClaims>(&token, &keypair.decoding_key(), &validation).unwrap();

            assert_eq!(decoded.claims, claims);
        }
    }

    #[cfg(feature = "ecdsa")]
    mod cross_key_tests {
        use crate::JwtKeyExt;
        use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
        use serde::{Deserialize, Serialize};
        use uselesskey_core::Factory;
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestClaims {
            sub: String,
            exp: usize,
        }

        #[test]
        fn test_cross_key_decode_fails() {
            let fx = Factory::random();
            let key_a = fx.ecdsa("issuer-a", EcdsaSpec::es256());
            let key_b = fx.ecdsa("issuer-b", EcdsaSpec::es256());

            let claims = TestClaims {
                sub: "user".to_string(),
                exp: 2_000_000_000,
            };

            let token = encode(
                &Header::new(Algorithm::ES256),
                &claims,
                &key_a.encoding_key(),
            )
            .unwrap();

            let result = decode::<TestClaims>(
                &token,
                &key_b.decoding_key(),
                &Validation::new(Algorithm::ES256),
            );
            assert!(result.is_err(), "decoding with wrong key should fail");
        }
    }

    #[cfg(feature = "hmac")]
    mod hmac_tests {
        use crate::JwtKeyExt;
        use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
        use serde::{Deserialize, Serialize};
        use uselesskey_core::Factory;
        use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestClaims {
            sub: String,
            exp: usize,
        }

        #[test]
        fn test_hmac_hs256_sign_and_verify() {
            let fx = Factory::random();
            let secret = fx.hmac("test-secret", HmacSpec::hs256());

            let claims = TestClaims {
                sub: "user123".to_string(),
                exp: 2_000_000_000,
            };

            let header = Header::new(Algorithm::HS256);
            let token = encode(&header, &claims, &secret.encoding_key()).unwrap();

            let validation = Validation::new(Algorithm::HS256);
            let decoded =
                decode::<TestClaims>(&token, &secret.decoding_key(), &validation).unwrap();

            assert_eq!(decoded.claims, claims);
        }

        #[test]
        fn test_hmac_hs384_sign_and_verify() {
            let fx = Factory::random();
            let secret = fx.hmac("test-secret", HmacSpec::hs384());

            let claims = TestClaims {
                sub: "user123".to_string(),
                exp: 2_000_000_000,
            };

            let header = Header::new(Algorithm::HS384);
            let token = encode(&header, &claims, &secret.encoding_key()).unwrap();

            let validation = Validation::new(Algorithm::HS384);
            let decoded =
                decode::<TestClaims>(&token, &secret.decoding_key(), &validation).unwrap();

            assert_eq!(decoded.claims, claims);
        }

        #[test]
        fn test_hmac_hs512_sign_and_verify() {
            let fx = Factory::random();
            let secret = fx.hmac("test-secret", HmacSpec::hs512());

            let claims = TestClaims {
                sub: "user123".to_string(),
                exp: 2_000_000_000,
            };

            let header = Header::new(Algorithm::HS512);
            let token = encode(&header, &claims, &secret.encoding_key()).unwrap();

            let validation = Validation::new(Algorithm::HS512);
            let decoded =
                decode::<TestClaims>(&token, &secret.decoding_key(), &validation).unwrap();

            assert_eq!(decoded.claims, claims);
        }
    }
}
