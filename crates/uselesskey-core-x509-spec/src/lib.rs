#![forbid(unsafe_code)]

//! X.509 fixture spec models and stable encoding helpers.
//!
//! This crate centralizes reusable X.509 fixture modeling:
//! - self-signed/chain spec types (`X509Spec`, `ChainSpec`)
//! - key-usage and not-before offset policy enums
//! - stable byte encodings used as deterministic derivation inputs
//!
//! # Examples
//!
//! Create a self-signed leaf spec with SANs via the builder API:
//!
//! ```
//! use uselesskey_core_x509_spec::{X509Spec, NotBeforeOffset};
//!
//! let spec = X509Spec::self_signed("myapp.example.com")
//!     .with_validity_days(90)
//!     .with_sans(vec!["myapp.example.com".into(), "api.example.com".into()])
//!     .with_rsa_bits(4096);
//!
//! assert_eq!(spec.subject_cn, "myapp.example.com");
//! assert_eq!(spec.validity_days, 90);
//! assert!(!spec.is_ca);
//!
//! // stable_bytes is used for deterministic derivation — same spec always
//! // produces the same bytes.
//! assert_eq!(spec.stable_bytes(), spec.stable_bytes());
//! ```
//!
//! Create a CA certificate spec:
//!
//! ```
//! use uselesskey_core_x509_spec::X509Spec;
//!
//! let ca = X509Spec::self_signed_ca("My Test CA");
//! assert!(ca.is_ca);
//! assert!(ca.key_usage.key_cert_sign);
//! ```

mod chain_spec;
mod revocation_spec;
mod spec;

pub use chain_spec::ChainSpec;
pub use revocation_spec::{
    CertStatus, CrlIssuerKind, CrlReasonCode, CrlSpec, NoncePolicy, OcspResponderKind, OcspSpec,
};
pub use spec::{KeyUsage, NotBeforeOffset, X509Spec};
