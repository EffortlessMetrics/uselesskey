#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Deprecated compatibility shim for X.509 negative-fixture policy helpers.
//!
//! Prefer `uselesskey-x509`; the canonical implementation now lives there.

pub use uselesskey_x509::srp::chain_negative::ChainNegative;
pub use uselesskey_x509::srp::negative::X509Negative;
