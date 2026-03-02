#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Compatibility façade for negative fixture primitives.
//!
//! This crate keeps existing `uselesskey_core_negative` paths stable while
//! delegating to focused microcrates:
//! - [`uselesskey_core_negative_der`] for DER corruption helpers.
//! - [`uselesskey_core_negative_pem`] for PEM corruption helpers.

pub use uselesskey_core_negative_der::{corrupt_der_deterministic, flip_byte, truncate_der};
pub use uselesskey_core_negative_pem::{CorruptPem, corrupt_pem, corrupt_pem_deterministic};
