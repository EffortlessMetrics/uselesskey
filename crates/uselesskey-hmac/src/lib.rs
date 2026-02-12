#![forbid(unsafe_code)]

//! HMAC secret fixtures built on `uselesskey-core`.
//!
//! Generates HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512 symmetric secrets
//! for testing. Supports deterministic and random modes.
//!
//! # Usage
//!
//! The main entry point is the [`HmacFactoryExt`] trait, which adds the `.hmac()` method
//! to [`Factory`](uselesskey_core::Factory).

mod secret;
mod spec;

pub use secret::{DOMAIN_HMAC_SECRET, HmacFactoryExt, HmacSecret};
pub use spec::HmacSpec;
