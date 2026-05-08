#![forbid(unsafe_code)]

//! Deprecated compatibility shim for JWKS builder helpers.
//!
//! Prefer `uselesskey-jwk`; the canonical implementation now lives there.

pub use uselesskey_jwk::JwksBuilder;
