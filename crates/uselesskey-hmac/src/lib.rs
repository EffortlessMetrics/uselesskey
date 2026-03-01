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
//!
//! # Examples
//!
//! ```
//! use uselesskey_core::Factory;
//! use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
//!
//! let fx = Factory::random();
//! let kp = fx.hmac("my-service", HmacSpec::hs256());
//! let secret = kp.secret_bytes();
//! assert_eq!(secret.len(), 32);
//! ```

mod secret;
mod spec;

pub use secret::{DOMAIN_HMAC_SECRET, HmacFactoryExt, HmacSecret};
pub use spec::HmacSpec;
