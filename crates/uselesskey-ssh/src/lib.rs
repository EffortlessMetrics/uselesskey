#![forbid(unsafe_code)]

//! OpenSSH key and certificate fixtures for infra/deployment tests.

mod cert;
mod key;
mod spec;

pub use cert::{DOMAIN_SSH_CERT, SshCertFixture};
pub use key::{DOMAIN_SSH_KEY, SshFactoryExt, SshKeyFixture};
pub use spec::{SshCertSpec, SshCertType, SshCertValidity, SshSpec};
