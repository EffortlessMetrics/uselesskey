#![forbid(unsafe_code)]

//! X.509 certificate fixtures built on `uselesskey-core`.
//!
//! This crate provides self-signed certificate generation for testing TLS and
//! X.509-related functionality without committing certificate files to version control.
//!
//! # Quick Start
//!
//! ```
//! use uselesskey_core::Factory;
//! use uselesskey_x509::{X509FactoryExt, X509Spec};
//!
//! let factory = Factory::random();
//! let spec = X509Spec::self_signed("test.example.com");
//! let cert = factory.x509_self_signed("my-service", spec);
//!
//! // Access certificate in various formats
//! let cert_pem = cert.cert_pem();
//! let key_pem = cert.private_key_pkcs8_pem();
//!
//! assert!(cert_pem.contains("-----BEGIN CERTIFICATE-----"));
//! assert!(key_pem.contains("-----BEGIN PRIVATE KEY-----"));
//! ```
//!
//! # Negative Fixtures
//!
//! Generate intentionally invalid certificates for testing error handling:
//!
//! ```
//! use uselesskey_core::Factory;
//! use uselesskey_x509::{X509FactoryExt, X509Spec};
//!
//! let factory = Factory::random();
//! let spec = X509Spec::self_signed("test.example.com");
//! let cert = factory.x509_self_signed("test", spec);
//!
//! // Get an expired certificate
//! let expired = cert.expired();
//!
//! // Get a not-yet-valid certificate
//! let not_valid = cert.not_yet_valid();
//!
//! // Corrupt the PEM encoding
//! use uselesskey_core::negative::CorruptPem;
//! let bad_pem = cert.corrupt_cert_pem(CorruptPem::BadHeader);
//! ```

mod cert;
pub mod negative;
mod spec;

pub use cert::{DOMAIN_X509_CERT, X509Cert, X509FactoryExt};
pub use negative::X509Negative;
pub use spec::{KeyUsage, NotBeforeOffset, X509Spec};
