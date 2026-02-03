#![forbid(unsafe_code)]

//! Core building blocks for `uselesskey`.
//!
//! Most users should depend on the `uselesskey` facade crate instead.
//!
//! This crate provides:
//! - deterministic, order-independent artifact derivation
//! - a concurrency-friendly cache
//! - tempfile sinks
//! - generic “negative fixture” helpers (corrupt PEM, truncate DER)

mod derive;
mod error;
mod factory;
mod id;
pub mod negative;
pub mod sink;

pub use crate::error::Error;
pub use crate::factory::{Factory, Mode};
pub use crate::id::{ArtifactDomain, ArtifactId, DerivationVersion, Seed};
