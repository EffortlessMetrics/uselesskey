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

mod spec;
mod token;

pub use spec::TokenSpec;
pub use token::{DOMAIN_TOKEN_FIXTURE, TokenFactoryExt, TokenFixture};
