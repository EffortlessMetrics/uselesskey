#![forbid(unsafe_code)]

//! Compatibility façade for token shape primitives.
//!
//! This crate intentionally keeps the existing public path stable while delegating
//! all token-generation behavior to [`uselesskey_core_token_shape`].

pub use uselesskey_core_token_shape::*;

pub use uselesskey_core_token_spec::TokenSpec;
