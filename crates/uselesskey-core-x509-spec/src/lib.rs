#![forbid(unsafe_code)]

//! X.509 fixture spec models and stable encoding helpers.
//!
//! This crate centralizes reusable X.509 fixture modeling:
//! - self-signed/chain spec types (`X509Spec`, `ChainSpec`)
//! - key-usage and not-before offset policy enums
//! - stable byte encodings used as deterministic derivation inputs

mod chain_spec;
mod spec;

pub use chain_spec::ChainSpec;
pub use spec::{KeyUsage, NotBeforeOffset, X509Spec};
