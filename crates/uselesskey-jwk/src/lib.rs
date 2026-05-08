#![forbid(unsafe_code)]

//! Typed JWK/JWKS helpers for uselesskey fixture crates.
//!
//! This crate is the canonical public owner for JWK and JWKS shape types,
//! deterministic JWKS ordering, key identifiers, and shape-realistic negative
//! JWK fixtures.
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

#[doc(hidden)]
pub mod srp;

#[cfg(feature = "json")]
pub use srp::builder::JwksBuilder;
#[cfg(feature = "json")]
pub use srp::shape::{
    AnyJwk, EcPrivateJwk, EcPublicJwk, Jwks, NegativeJwk, NegativeJwks, OctJwk, OkpPrivateJwk,
    OkpPublicJwk, PrivateJwk, PublicJwk, RsaPrivateJwk, RsaPublicJwk,
};
