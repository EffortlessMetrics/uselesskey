#![forbid(unsafe_code)]

//! Integration between uselesskey test fixtures and rustls.
//!
//! `uselesskey-rustls` now focuses on config-building helpers and re-exports
//! DER conversion traits from [`uselesskey_rustls_der`].

#[cfg(any(feature = "server-config", feature = "client-config"))]
mod config;

#[cfg(test)]
mod testutil;

pub use uselesskey_rustls_der::{RustlsCertExt, RustlsChainExt, RustlsPrivateKeyExt};

#[cfg(feature = "server-config")]
pub use config::RustlsServerConfigExt;

#[cfg(feature = "client-config")]
pub use config::RustlsClientConfigExt;

#[cfg(all(feature = "server-config", feature = "client-config"))]
pub use config::RustlsMtlsExt;
