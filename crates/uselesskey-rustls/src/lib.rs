#![forbid(unsafe_code)]

//! Integration between uselesskey test fixtures and `rustls-pki-types`.
//!
//! This crate re-exports extension traits from `uselesskey-core-rustls-pki`
//! that convert uselesskey fixtures into `rustls-pki-types` types
//! (`PrivateKeyDer`, `CertificateDer`).
//!
//! With the `server-config` and `client-config` features, it also provides
//! convenience builders for `rustls::ServerConfig` and `rustls::ClientConfig`,
//! including mutual TLS (mTLS) support.

#[cfg(any(feature = "server-config", feature = "client-config"))]
mod config;

#[cfg(test)]
mod testutil;

#[cfg(feature = "x509")]
pub use uselesskey_core_rustls_pki::RustlsChainExt;
pub use uselesskey_core_rustls_pki::{RustlsCertExt, RustlsPrivateKeyExt};

#[cfg(feature = "server-config")]
pub use config::RustlsServerConfigExt;

#[cfg(feature = "client-config")]
pub use config::RustlsClientConfigExt;

#[cfg(all(feature = "server-config", feature = "client-config"))]
pub use config::RustlsMtlsExt;
