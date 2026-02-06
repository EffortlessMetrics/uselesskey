#![forbid(unsafe_code)]

//! ECDSA fixtures built on `uselesskey-core`.
//!
//! This crate is used by the `uselesskey` facade crate.
//!
//! # Usage
//!
//! The main entry point is the [`EcdsaFactoryExt`] trait, which adds the `.ecdsa()` method
//! to [`Factory`](uselesskey_core::Factory).
//!
//! ```
//! use uselesskey_core::Factory;
//! use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
//!
//! let fx = Factory::random();
//! let keypair = fx.ecdsa("my-service", EcdsaSpec::es256());
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
//! use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
//!
//! let seed = Seed::from_env_value("test-seed").unwrap();
//! let fx = Factory::deterministic(seed);
//!
//! // Same seed + label + spec = same key
//! let key1 = fx.ecdsa("issuer", EcdsaSpec::es256());
//! let key2 = fx.ecdsa("issuer", EcdsaSpec::es256());
//! assert_eq!(key1.private_key_pkcs8_pem(), key2.private_key_pkcs8_pem());
//!
//! // Different labels produce different keys
//! let key3 = fx.ecdsa("other", EcdsaSpec::es256());
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
//! use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
//!
//! let fx = Factory::random();
//! let keypair = fx.ecdsa("test", EcdsaSpec::es256());
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
//!
//! # Available Specs
//!
//! | Spec | Curve | JWT Algorithm |
//! |------|-------|---------------|
//! | [`EcdsaSpec::es256()`] | P-256 (secp256r1) | ES256 |
//! | [`EcdsaSpec::es384()`] | P-384 (secp384r1) | ES384 |

mod keypair;
mod spec;

pub use keypair::{DOMAIN_ECDSA_KEYPAIR, EcdsaFactoryExt, EcdsaKeyPair};
pub use spec::EcdsaSpec;
