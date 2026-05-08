//! Deprecated compatibility shim for deterministic hashing helpers.
//!
//! Prefer `uselesskey-core`; hashing mechanics are now owned by
//! `uselesskey_core::srp::hash`.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

pub use uselesskey_core::srp::hash::{Hash, Hasher, hash32, write_len_prefixed};
