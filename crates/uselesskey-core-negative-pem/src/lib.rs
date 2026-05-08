//! Deprecated compatibility shim for PEM negative fixture helpers.
//!
//! Prefer `uselesskey-core`; PEM corruption helpers are now owned by
//! `uselesskey_core::srp::negative::pem`.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

pub use uselesskey_core::srp::negative::pem::{CorruptPem, corrupt_pem, corrupt_pem_deterministic};
