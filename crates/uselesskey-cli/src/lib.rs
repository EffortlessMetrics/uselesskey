#![forbid(unsafe_code)]

//! Bundle manifest and export helpers for uselesskey fixture handoff.
//!
//! This crate is designed for one-shot generation workflows that produce
//! files/manifests intended for ingestion by external secret tooling.

pub mod export;
pub mod manifest;

pub use export::{ExportError, SecretEntry};
pub use manifest::{
    ArtifactType, BundleManifest, Fingerprint, KeyRef, OutputPath, SourceMetadata,
};
