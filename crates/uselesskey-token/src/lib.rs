#![forbid(unsafe_code)]

//! Token fixtures built on `uselesskey-core`.
//!
//! This crate generates realistic test-token shapes without committing
//! secret-looking blobs to version control.
//!
//! Most users should depend on the [`uselesskey`](https://crates.io/crates/uselesskey)
//! facade crate, which re-exports this crate's types behind the `token` feature flag.
//!
//! Supported token kinds:
//! - API key style tokens (`uk_test_<base62>`)
//! - Opaque bearer tokens (base64url)
//! - OAuth-style JWT access tokens (`header.payload.signature`)
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
//!
//! # Deterministic Mode
//!
//! Use deterministic mode for reproducible test fixtures:
//!
//! ```
//! use uselesskey_core::{Factory, Seed};
//! use uselesskey_token::{TokenFactoryExt, TokenSpec};
//!
//! let seed = Seed::from_env_value("test-seed").unwrap();
//! let fx = Factory::deterministic(seed);
//!
//! // Same seed + label + spec = same token
//! let t1 = fx.token("billing", TokenSpec::api_key());
//! let t2 = fx.token("billing", TokenSpec::api_key());
//! assert_eq!(t1.value(), t2.value());
//!
//! // Different labels produce different tokens
//! let t3 = fx.token("other", TokenSpec::api_key());
//! assert_ne!(t1.value(), t3.value());
//! ```

mod spec;
mod token;

pub use spec::TokenSpec;
pub use token::{DOMAIN_TOKEN_FIXTURE, TokenFactoryExt, TokenFixture};
