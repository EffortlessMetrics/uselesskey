//! Deprecated compatibility shim for tempfile-backed artifact sinks.
//!
//! Prefer `uselesskey-core`; raw sink mechanics are now owned by
//! `uselesskey_core::srp::sink`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use uselesskey_core::srp::sink::TempArtifact;
