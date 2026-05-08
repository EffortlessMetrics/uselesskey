//! Deprecated compatibility shim for DER negative fixture helpers.
//!
//! Prefer `uselesskey-core`; DER corruption helpers are now owned by
//! `uselesskey_core::srp::negative::der`.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

pub use uselesskey_core::srp::negative::der::{corrupt_der_deterministic, flip_byte, truncate_der};
