#![forbid(unsafe_code)]

//! X.509 certificate fixtures built on `uselesskey-core`.
//!
//! This crate provides self-signed certificate generation and certificate chain
//! generation for testing TLS and X.509-related functionality without committing
//! certificate files to version control.
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
//! # Certificate Chains
//!
//! Generate a three-level chain (root CA → intermediate CA → leaf):
//!
//! ```
//! use uselesskey_core::Factory;
//! use uselesskey_x509::{X509FactoryExt, ChainSpec};
//!
//! let factory = Factory::random();
//! let spec = ChainSpec::new("test.example.com");
//! let chain = factory.x509_chain("my-service", spec);
//!
//! // Standard TLS chain (leaf + intermediate)
//! let chain_pem = chain.chain_pem();
//! assert_eq!(chain_pem.matches("-----BEGIN CERTIFICATE-----").count(), 2);
//!
//! // Individual certs
//! let leaf_pem = chain.leaf_cert_pem();
//! let root_pem = chain.root_cert_pem();
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
mod chain;
mod chain_negative;
mod chain_spec;
pub mod negative;
mod spec;
mod util;

pub use cert::{DOMAIN_X509_CERT, X509Cert, X509FactoryExt};
pub use chain::{DOMAIN_X509_CHAIN, X509Chain};
pub use chain_negative::ChainNegative;
pub use chain_spec::ChainSpec;
pub use negative::X509Negative;
pub use spec::{KeyUsage, NotBeforeOffset, X509Spec};
