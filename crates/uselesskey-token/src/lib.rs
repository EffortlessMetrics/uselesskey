#![forbid(unsafe_code)]

//! Token fixtures built on `uselesskey-core`.
//!
//! This crate generates realistic test-token shapes without committing
//! secret-looking blobs to version control.
//!
//! Supported token kinds:
//! - API key style tokens
//! - Opaque bearer tokens
//! - OAuth-style JWT access tokens
//!
//! # Examples
//!
//! ```
//! use uselesskey_core::Factory;
//! use uselesskey_token::{TokenFactoryExt, TokenSpec};
//!
//! let fx = Factory::random();
//! let tok = fx.token("api-key", TokenSpec::api_key());
//! let value = tok.value();
//! assert!(!value.is_empty());
//! ```

mod token;

pub use token::{DOMAIN_TOKEN_FIXTURE, TokenFactoryExt, TokenFixture};
pub use uselesskey_core_token_spec::TokenSpec;
