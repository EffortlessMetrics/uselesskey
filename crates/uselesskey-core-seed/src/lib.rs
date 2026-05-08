//! Deprecated compatibility shim for seed parsing and redaction.
//!
//! Prefer `uselesskey-core`; seed primitives are now owned by
//! `uselesskey_core::srp::seed`.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

pub use uselesskey_core::srp::seed::Seed;
