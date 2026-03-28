#![forbid(unsafe_code)]

//! OpenSSH fixtures built on top of `uselesskey-core`.

mod cert;
mod key;
mod spec;

pub use cert::{CertType, SshCertFixture, SshCertSpec, SshValidity};
pub use key::{DOMAIN_SSH_CERT, DOMAIN_SSH_KEYPAIR, SshFactoryExt, SshKeyFixture};
pub use spec::{SshAlgorithm, SshSpec};
