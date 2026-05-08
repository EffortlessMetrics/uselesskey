#![forbid(unsafe_code)]

//! Deprecated compatibility shim for X.509 spec models.
//!
//! Prefer `uselesskey-x509`; the canonical implementation now lives there.

pub use uselesskey_x509::srp::spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};
