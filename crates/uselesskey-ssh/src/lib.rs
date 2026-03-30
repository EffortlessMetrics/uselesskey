#![forbid(unsafe_code)]

//! OpenSSH fixtures built on `uselesskey-core`.
//!
//! This crate provides deterministic, cache-backed OpenSSH key and certificate
//! fixtures for infrastructure and deployment tests.

mod cert;
mod key;
mod spec;

pub use cert::{DOMAIN_SSH_CERT, SshCertFactoryExt, SshCertFixture};
pub use key::{DOMAIN_SSH_KEYPAIR, SshFactoryExt, SshKeyPair};
pub use spec::{SshCertSpec, SshCertType, SshSpec, SshValidity};
