#![forbid(unsafe_code)]

//! Deprecated compatibility shim.
//!
//! Prefer `uselesskey-hmac` for the supported `HmacSpec` model.

pub use uselesskey_hmac::srp::spec::*;
