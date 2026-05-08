#![forbid(unsafe_code)]

//! Deprecated compatibility shim.
//!
//! Prefer `uselesskey-token` for supported token fixture APIs.

pub use uselesskey_token::srp::base62::random_base62;
pub use uselesskey_token::srp::shape::*;
