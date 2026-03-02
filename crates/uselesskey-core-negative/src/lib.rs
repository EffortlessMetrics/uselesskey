#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Compatibility façade for negative fixture primitives.
//!
//! This crate keeps existing `uselesskey_core_negative` paths stable while
//! delegating to focused microcrates:
//! - [`uselesskey_core_negative_der`] for DER corruption helpers.
//! - [`uselesskey_core_negative_pem`] for PEM corruption helpers.
//!
//! # Examples
//!
//! Corrupt a PEM string with a specific strategy:
//!
//! ```
//! use uselesskey_core_negative::{corrupt_pem, CorruptPem};
//!
//! let pem = "-----BEGIN PUBLIC KEY-----\nABC=\n-----END PUBLIC KEY-----\n";
//! let bad = corrupt_pem(pem, CorruptPem::BadHeader);
//! assert!(bad.starts_with("-----BEGIN CORRUPTED KEY-----"));
//! ```
//!
//! Deterministic DER corruption from a variant string:
//!
//! ```
//! use uselesskey_core_negative::corrupt_der_deterministic;
//!
//! let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20];
//! let a = corrupt_der_deterministic(&der, "corrupt:test-v1");
//! let b = corrupt_der_deterministic(&der, "corrupt:test-v1");
//! assert_eq!(a, b); // same variant ⇒ same corruption
//! ```

pub use uselesskey_core_negative_der::{corrupt_der_deterministic, flip_byte, truncate_der};
pub use uselesskey_core_negative_pem::{CorruptPem, corrupt_pem, corrupt_pem_deterministic};
