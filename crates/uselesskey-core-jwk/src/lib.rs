#![forbid(unsafe_code)]

//! Re-export of JWK model types and helpers.
//!
//! This crate is a thin compatibility façade over
//! `uselesskey-core-jwk-shape` for API stability.
//!
//! # Examples
//!
//! Build an Ed25519 public JWK:
//!
//! ```
//! use uselesskey_core_jwk::{OkpPublicJwk, PublicJwk};
//!
//! let jwk = OkpPublicJwk {
//!     kty: "OKP",
//!     use_: "sig",
//!     alg: "EdDSA",
//!     crv: "Ed25519",
//!     kid: "my-key-1".into(),
//!     x: "dGVzdC1wdWJsaWMta2V5".into(),
//! };
//! let public = PublicJwk::Okp(jwk);
//! assert_eq!(public.to_value()["kty"], "OKP");
//! ```
//!
//! Assemble a JWKS with deterministic ordering via [`JwksBuilder`]:
//!
//! ```
//! use uselesskey_core_jwk::{JwksBuilder, RsaPublicJwk, PublicJwk};
//!
//! let jwks = JwksBuilder::new()
//!     .add_public(PublicJwk::Rsa(RsaPublicJwk {
//!         kty: "RSA", use_: "sig", alg: "RS256",
//!         kid: "b-key".into(), n: "modulus".into(), e: "AQAB".into(),
//!     }))
//!     .add_public(PublicJwk::Rsa(RsaPublicJwk {
//!         kty: "RSA", use_: "sig", alg: "RS256",
//!         kid: "a-key".into(), n: "modulus".into(), e: "AQAB".into(),
//!     }))
//!     .build();
//!
//! // Keys are sorted by kid
//! assert_eq!(jwks.keys[0].kid(), "a-key");
//! assert_eq!(jwks.keys[1].kid(), "b-key");
//! ```

pub use uselesskey_core_jwk_builder::JwksBuilder;
pub use uselesskey_core_jwk_shape::*;
