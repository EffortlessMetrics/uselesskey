#![forbid(unsafe_code)]

//! Deprecated compatibility shim for stable `kid` ordering helpers.
//!
//! Prefer `uselesskey-jwk`; the canonical implementation now lives there.

pub use uselesskey_jwk::srp::ordering::{HasKid, KidSorted};
