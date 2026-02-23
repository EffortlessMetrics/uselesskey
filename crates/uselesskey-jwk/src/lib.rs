#![forbid(unsafe_code)]

//! Compatibility facade for typed JWK/JWKS helpers.
//!
//! The canonical implementation lives in `uselesskey-core-jwk`.
//! This crate preserves the stable public crate name used by fixture crates
//! and external consumers.

pub use uselesskey_core_jwk::*;
