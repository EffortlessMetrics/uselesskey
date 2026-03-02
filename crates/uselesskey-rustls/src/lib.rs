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
//!
//! # Convert a private key to rustls format
//!
//! ```
//! use uselesskey_core::Factory;
//! use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
//! use uselesskey_rustls::RustlsPrivateKeyExt;
//!
//! let fx = Factory::random();
//! let rsa = fx.rsa("server", RsaSpec::rs256());
//! let key = rsa.private_key_der_rustls();
//! assert_eq!(key.secret_der(), rsa.private_key_pkcs8_der());
//! ```
//!
//! # Build TLS configs (requires `tls-config` + a crypto provider feature)
//!
//! ```no_run
//! use uselesskey_core::Factory;
//! use uselesskey_x509::{X509FactoryExt, ChainSpec};
//! use uselesskey_rustls::{RustlsServerConfigExt, RustlsClientConfigExt};
//!
//! let fx = Factory::random();
//! let chain = fx.x509_chain("svc", ChainSpec::new("test.example.com"));
//!
//! let server_cfg = chain.server_config_rustls();
//! let client_cfg = chain.client_config_rustls();
//! ```

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
