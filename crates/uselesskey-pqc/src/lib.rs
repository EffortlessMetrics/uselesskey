#![forbid(unsafe_code)]

//! Experimental PQC fixtures for parser, buffer, and TLS-prep testing.
//!
//! This crate is intentionally **opaque-first** and is not a production PQC API.
//! The goal is to provide deterministic high-size fixtures and malformed variants
//! without committing secret-shaped blobs to version control.
//!
//! The API exposes [`PqcSpec`] + [`PqcFixture`] and supports two fixture modes:
//! - [`PqcFixtureMode::Opaque`] (implemented)
//! - [`PqcFixtureMode::Real`] (reserved; currently returns an error)

mod fixture;
mod spec;

pub use fixture::{
    DOMAIN_PQC_FIXTURE, PqcError, PqcFactoryExt, PqcFixture, PqcNegativeFixture, PrivateMaterial,
};
pub use spec::{PqcAlgorithm, PqcFixtureMode, PqcSecurityLevel, PqcSpec};
