//! Deprecated compatibility shim for factory orchestration.
//!
//! Prefer `uselesskey-core`; factory mechanics are now owned by
//! `uselesskey_core::srp::factory`.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

pub use uselesskey_core::srp::factory::{Factory, Mode};
