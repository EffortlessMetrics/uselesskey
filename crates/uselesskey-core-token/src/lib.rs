#![forbid(unsafe_code)]

//! Compatibility façade for token shape primitives.
//!
//! This crate intentionally keeps the existing public path stable while delegating
//! all token-generation behavior to [`uselesskey_core_token_shape`].
//!
//! # Examples
//!
//! ```
//! use rand_chacha::ChaCha20Rng;
//! use rand_chacha::rand_core::SeedableRng;
//! use uselesskey_core_token::{generate_token, TokenKind};
//!
//! let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
//! let api_key = generate_token("my-service", TokenKind::ApiKey, &mut rng);
//! assert!(api_key.starts_with("uk_test_"));
//! ```
//!
//! # This is a test utility
//!
//! This crate is part of the [uselesskey](https://crates.io/crates/uselesskey)
//! test-fixture ecosystem. It is **not** intended for production use.

pub use uselesskey_core_token_shape::*;
