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

#[doc(hidden)]
pub mod srp;

pub use srp::JwtKeyExt;
