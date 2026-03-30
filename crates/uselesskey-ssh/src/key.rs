use std::fmt;
use std::sync::Arc;

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use uselesskey_core::Factory;

use crate::SshSpec;

/// Cache domain for SSH key fixtures.
pub const DOMAIN_SSH_KEYPAIR: &str = "uselesskey:ssh:keypair";

#[derive(Clone)]
pub struct SshKeyPair {
    label: String,
    spec: SshSpec,
    inner: Arc<Inner>,
}

struct Inner {
    private_key_openssh: String,
    public_key_openssh: String,
}

impl fmt::Debug for SshKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshKeyPair")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

pub trait SshFactoryExt {
    fn ssh_key(&self, label: impl AsRef<str>, spec: SshSpec) -> SshKeyPair;
}

impl SshFactoryExt for Factory {
    fn ssh_key(&self, label: impl AsRef<str>, spec: SshSpec) -> SshKeyPair {
        SshKeyPair::new(self, label.as_ref(), spec)
    }
}

impl SshKeyPair {
    fn new(factory: &Factory, label: &str, spec: SshSpec) -> Self {
        let spec_bytes = spec.stable_bytes();
        let inner = factory.get_or_init(DOMAIN_SSH_KEYPAIR, label, &spec_bytes, "good", |seed| {
            let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
            let private_key = PrivateKey::random(&mut rng, to_algorithm(spec))
                .expect("SSH private key generation failed");
            let public_key = private_key.public_key();

            Inner {
                private_key_openssh: private_key
                    .to_openssh(LineEnding::LF)
                    .expect("OpenSSH private key encoding failed")
                    .to_string(),
                public_key_openssh: public_key
                    .to_openssh()
                    .expect("OpenSSH public key encoding failed"),
            }
        });

        Self {
            label: label.to_string(),
            spec,
            inner,
        }
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn spec(&self) -> SshSpec {
        self.spec
    }

    /// OpenSSH private key text (`-----BEGIN OPENSSH PRIVATE KEY-----`).
    pub fn private_key_openssh(&self) -> &str {
        &self.inner.private_key_openssh
    }

    /// Public key line suitable for `authorized_keys`.
    pub fn authorized_key_line(&self) -> &str {
        &self.inner.public_key_openssh
    }
}

fn to_algorithm(spec: SshSpec) -> Algorithm {
    match spec {
        SshSpec::Ed25519 => Algorithm::Ed25519,
        SshSpec::Rsa => Algorithm::Rsa { hash: None },
    }
}

#[cfg(test)]
mod tests {
    use ssh_key::{PrivateKey, PublicKey};
    use uselesskey_core::Seed;

    use super::*;

    #[test]
    fn deterministic_authorized_key_lines() {
        let fx = Factory::deterministic(Seed::from_env_value("ssh-det-lines").unwrap());
        let a = fx.ssh_key("deploy", SshSpec::ed25519());
        let b = fx.ssh_key("deploy", SshSpec::ed25519());
        assert_eq!(a.authorized_key_line(), b.authorized_key_line());
    }

    #[test]
    fn round_trip_parse_private_and_public() {
        let fx = Factory::random();
        let k = fx.ssh_key("infra", SshSpec::rsa());

        let parsed_private = PrivateKey::from_openssh(k.private_key_openssh()).unwrap();
        let parsed_public = PublicKey::from_openssh(k.authorized_key_line()).unwrap();

        assert_eq!(parsed_private.public_key(), &parsed_public);
    }
}
