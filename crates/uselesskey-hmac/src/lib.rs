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
//!
//! # Deterministic Mode
//!
//! Use deterministic mode for reproducible test fixtures:
//!
//! ```
//! use uselesskey_core::{Factory, Seed};
//! use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
//!
//! let seed = Seed::from_env_value("test-seed").unwrap();
//! let fx = Factory::deterministic(seed);
//!
//! // Same seed + label + spec = same secret
//! let s1 = fx.hmac("issuer", HmacSpec::hs384());
//! let s2 = fx.hmac("issuer", HmacSpec::hs384());
//! assert_eq!(s1.secret_bytes(), s2.secret_bytes());
//!
//! // Different labels produce different secrets
//! let s3 = fx.hmac("other", HmacSpec::hs384());
//! assert_ne!(s1.secret_bytes(), s3.secret_bytes());
//! ```
//!
//! # Available Specs
//!
//! | Spec | Algorithm | Secret Length |
//! |------|-----------|--------------|
//! | [`HmacSpec::hs256()`] | HMAC-SHA256 | 32 bytes |
//! | [`HmacSpec::hs384()`] | HMAC-SHA384 | 48 bytes |
//! | [`HmacSpec::hs512()`] | HMAC-SHA512 | 64 bytes |

mod secret;
mod spec;

pub use secret::{DOMAIN_HMAC_SECRET, HmacFactoryExt, HmacSecret};
pub use spec::HmacSpec;
