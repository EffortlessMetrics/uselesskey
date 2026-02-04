#![forbid(unsafe_code)]

//! Core building blocks for `uselesskey`.
//!
//! Most users should depend on the `uselesskey` facade crate instead.
//!
//! This crate provides:
//! - deterministic, order-independent artifact derivation
//! - a concurrency-friendly cache
//! - tempfile sinks
//! - generic "negative fixture" helpers (corrupt PEM, truncate DER)
//!
//! # Architecture
//!
//! The core concept is the [`Factory`], which manages artifact generation and caching.
//! It operates in two modes:
//!
//! - **Random mode**: Artifacts are generated with OS randomness, cached per-process.
//! - **Deterministic mode**: Artifacts are derived from a master seed using BLAKE3,
//!   ensuring the same `(domain, label, spec, variant)` always produces the same artifact.
//!
//! # Extension Pattern
//!
//! Key types (RSA, ECDSA, etc.) are added via extension traits that add methods to `Factory`.
//! See `uselesskey-rsa` for an example implementation.
//!
//! ```
//! use uselesskey_core::Factory;
//!
//! let fx = Factory::random();
//! // Extension crates add methods like: fx.rsa("label", spec)
//! ```

mod derive;
mod error;
mod factory;
mod id;
pub mod negative;
pub mod sink;

pub use crate::error::Error;
pub use crate::factory::{Factory, Mode};
pub use crate::id::{ArtifactDomain, ArtifactId, DerivationVersion, Seed};
