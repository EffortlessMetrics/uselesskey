#![forbid(unsafe_code)]

//! Ed25519 fixtures built on `uselesskey-core`.
//!
//! This crate is used by the `uselesskey` facade crate.
//!
//! # Usage
//!
//! The main entry point is the [`Ed25519FactoryExt`] trait, which adds the `.ed25519()` method
//! to [`Factory`](uselesskey_core::Factory).
//!
//! ```
//! use uselesskey_core::Factory;
//! use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
//!
//! let fx = Factory::random();
//! let keypair = fx.ed25519("my-service", Ed25519Spec::new());
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
//! use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
//!
//! let seed = Seed::from_env_value("test-seed").unwrap();
//! let fx = Factory::deterministic(seed);
//!
//! // Same seed + label + spec = same key
//! let key1 = fx.ed25519("issuer", Ed25519Spec::new());
//! let key2 = fx.ed25519("issuer", Ed25519Spec::new());
//! assert_eq!(key1.private_key_pkcs8_pem(), key2.private_key_pkcs8_pem());
//!
//! // Different labels produce different keys
//! let key3 = fx.ed25519("other", Ed25519Spec::new());
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
//! use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
//!
//! let fx = Factory::random();
//! let keypair = fx.ed25519("test", Ed25519Spec::new());
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

pub use keypair::{DOMAIN_ED25519_KEYPAIR, Ed25519FactoryExt, Ed25519KeyPair};
pub use spec::Ed25519Spec;
