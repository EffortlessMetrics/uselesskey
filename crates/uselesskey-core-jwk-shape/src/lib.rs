#![forbid(unsafe_code)]

//! Compatibility façade for typed JWK and JWKS models.
//!
//! This crate intentionally keeps the existing public path stable while delegating
//! shape types and JSON helpers to [`uselesskey_core_jwk_types`].

pub use uselesskey_core_jwk_types::*;
