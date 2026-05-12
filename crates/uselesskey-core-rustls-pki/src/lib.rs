//! Deprecated compatibility shim.
//!
//! The canonical rustls PKI extension traits now live in `uselesskey-rustls`
//! (see `uselesskey_rustls::srp::pki`). This crate re-exports them so v0.7.x
//! consumers who pinned `uselesskey-core-rustls-pki` keep compiling; prefer
//! `uselesskey-rustls` directly in new code.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "x509")]
pub use uselesskey_rustls::srp::pki::RustlsChainExt;
pub use uselesskey_rustls::srp::pki::{RustlsCertExt, RustlsPrivateKeyExt};
