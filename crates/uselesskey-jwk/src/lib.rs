#![forbid(unsafe_code)]

//! Compatibility facade for typed JWK/JWKS helpers.
//!
//! The canonical implementation lives in `uselesskey-core-jwk`.
//! This crate preserves the stable public crate name used by fixture crates
//! and external consumers.
//!
//! # Examples
//!
//! Build a JWKS from individual JWK values:
//!
//! ```
//! use uselesskey_jwk::{JwksBuilder, RsaPublicJwk, PublicJwk};
//!
//! let jwk = PublicJwk::Rsa(RsaPublicJwk {
//!     kty: "RSA",
//!     use_: "sig",
//!     alg: "RS256",
//!     kid: "key-1".to_string(),
//!     n: "modulus".to_string(),
//!     e: "AQAB".to_string(),
//! });
//!
//! let jwks = JwksBuilder::new().add_public(jwk).build();
//! assert_eq!(jwks.keys.len(), 1);
//! assert_eq!(jwks.keys[0].kid(), "key-1");
//! ```
//!
//! Serialize a JWK to JSON:
//!
//! ```
//! use uselesskey_jwk::RsaPublicJwk;
//!
//! let jwk = RsaPublicJwk {
//!     kty: "RSA",
//!     use_: "sig",
//!     alg: "RS256",
//!     kid: "key-1".to_string(),
//!     n: "modulus".to_string(),
//!     e: "AQAB".to_string(),
//! };
//! assert_eq!(jwk.kid(), "key-1");
//! ```

pub use uselesskey_core_jwk::*;
pub use uselesskey_core_jwk_builder::JwksBuilder;
