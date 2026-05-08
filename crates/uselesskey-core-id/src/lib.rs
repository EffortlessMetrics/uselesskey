//! Deprecated compatibility shim for artifact identity primitives.
//!
//! Prefer `uselesskey-core`; identity mechanics are now owned by
//! `uselesskey_core::srp::identity`.

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

pub use uselesskey_core::srp::identity::{
    ArtifactDomain, ArtifactId, DerivationVersion, Seed, derive_seed, hash32, write_len_prefixed,
};
