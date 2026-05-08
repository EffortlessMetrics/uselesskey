//! Deprecated compatibility shim for cache primitives.
//!
//! Prefer `uselesskey-core`; cache mechanics are now owned by
//! `uselesskey_core::srp::cache`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

pub use uselesskey_core::srp::cache::{ArtifactCache, downcast_or_panic};
