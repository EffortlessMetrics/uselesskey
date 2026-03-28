#![forbid(unsafe_code)]

//! Deterministic X.509 fixture policy helpers.
//!
//! This crate centralizes reusable policy used by X.509 fixture producers:
//! - X.509 negative-policy types used by fixture generators
//! - re-exports of X.509 spec models from `uselesskey-core-x509-spec`
//! - re-exports of deterministic derivation helpers from
//!   `uselesskey-core-x509-derive`
//!
//! # Examples
//!
//! Create an expired certificate spec using [`X509Negative`]:
//!
//! ```
//! use uselesskey_core_x509::{X509Negative, X509Spec, NotBeforeOffset};
//!
//! let base = X509Spec::self_signed("example.com");
//! let expired = X509Negative::Expired.apply_to_spec(&base);
//!
//! assert_eq!(expired.not_before_offset, NotBeforeOffset::DaysAgo(395));
//! assert_eq!(expired.validity_days, 365);
//! ```
//!
//! Build a chain spec and apply a hostname-mismatch negative:
//!
//! ```
//! use uselesskey_core_x509::{ChainNegative, ChainSpec};
//!
//! let base = ChainSpec::new("api.example.com");
//! let neg = ChainNegative::HostnameMismatch {
//!     wrong_hostname: "evil.example.com".to_string(),
//! };
//! let modified = neg.apply_to_spec(&base);
//! assert_eq!(modified.leaf_cn, "evil.example.com");
//! ```

mod negative;

pub use negative::{ChainNegative, X509Negative};
pub use uselesskey_core_x509_derive::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, SERIAL_NUMBER_BYTES, deterministic_base_time,
    deterministic_base_time_from_parts, deterministic_serial_number, write_len_prefixed,
};
pub use uselesskey_core_x509_spec::{
    ChainSpec, CrlIssuerKind, CrlReasonCode, CrlSpec, KeyUsage, NotBeforeOffset, OcspCertStatus,
    OcspNoncePolicy, OcspResponderKind, OcspSpec, X509Spec,
};
