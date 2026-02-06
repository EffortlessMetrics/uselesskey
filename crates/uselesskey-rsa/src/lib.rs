#![forbid(unsafe_code)]

//! RSA fixtures built on `uselesskey-core`.
//!
//! This crate is used by the `uselesskey` facade crate.
//!
//! # Usage
//!
//! The main entry point is the [`RsaFactoryExt`] trait, which adds the `.rsa()` method
//! to [`Factory`](uselesskey_core::Factory).
//!
//! ```
//! use uselesskey_core::Factory;
//! use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
//!
//! let fx = Factory::random();
//! let keypair = fx.rsa("my-service", RsaSpec::rs256());
//!
//! // Access key material in various formats
//! let private_pem = keypair.private_key_pkcs8_pem();
//! let private_der = keypair.private_key_pkcs8_der();
//! let public_pem = keypair.public_key_spki_pem();
//! let public_der = keypair.public_key_spki_der();
//!
//! assert!(private_pem.contains("BEGIN PRIVATE KEY"));
//! ```
//!
//! # Deterministic Mode
//!
//! Use deterministic mode for reproducible test fixtures:
//!
//! ```
//! use uselesskey_core::{Factory, Seed};
//! use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
//!
//! let seed = Seed::from_env_value("test-seed").unwrap();
//! let fx = Factory::deterministic(seed);
//!
//! // Same seed + label + spec = same key
//! let key1 = fx.rsa("issuer", RsaSpec::rs256());
//! let key2 = fx.rsa("issuer", RsaSpec::rs256());
//! assert_eq!(key1.private_key_pkcs8_pem(), key2.private_key_pkcs8_pem());
//!
//! // Different labels produce different keys
//! let key3 = fx.rsa("other", RsaSpec::rs256());
//! assert_ne!(key1.private_key_pkcs8_pem(), key3.private_key_pkcs8_pem());
//! ```
//!
//! # Negative Fixtures
//!
//! Generate intentionally broken keys for testing error handling:
//!
//! ```
//! use uselesskey_core::Factory;
//! use uselesskey_core::negative::CorruptPem;
//! use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
//!
//! let fx = Factory::random();
//! let keypair = fx.rsa("test", RsaSpec::rs256());
//!
//! // Corrupted PEM
//! let bad_pem = keypair.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
//!
//! // Truncated DER
//! let truncated = keypair.private_key_pkcs8_der_truncated(10);
//!
//! // Mismatched public key (valid but from a different keypair)
//! let wrong_pub = keypair.mismatched_public_key_spki_der();
//! ```

mod keypair;
mod spec;

pub use keypair::{DOMAIN_RSA_KEYPAIR, RsaFactoryExt, RsaKeyPair};
pub use spec::RsaSpec;
