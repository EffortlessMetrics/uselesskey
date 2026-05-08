#![forbid(unsafe_code)]

//! Deprecated compatibility shim for X.509 policy helpers.
//!
//! Prefer `uselesskey-x509`; the canonical implementation now lives there.

pub use uselesskey_x509::srp::policy::*;
