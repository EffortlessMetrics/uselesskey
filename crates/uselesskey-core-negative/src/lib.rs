//! Deprecated compatibility shim for negative fixture primitives.
//!
//! Prefer `uselesskey-core`; generic negative helpers are now owned by
//! `uselesskey_core::srp::negative`.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

pub use uselesskey_core::srp::negative::{
    CorruptPem, corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic, flip_byte,
    truncate_der,
};
