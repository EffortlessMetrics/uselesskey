use std::fmt;
use std::sync::Arc;

use rand_chacha10::ChaCha20Rng;
use rand_core10::SeedableRng;
use ssh_key::LineEnding;
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use uselesskey_core::Factory;

use crate::SshSpec;

/// Cache domain for SSH key fixtures.
pub const DOMAIN_SSH_KEY: &str = "uselesskey:ssh:key";

#[derive(Clone)]
pub struct SshKeyFixture {
    label: String,
    spec: SshSpec,
    inner: Arc<Inner>,
}

struct Inner {
    private_key: PrivateKey,
    private_key_openssh: String,
    authorized_keys_line: String,
    public_key_openssh: String,
}

impl fmt::Debug for SshKeyFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshKeyFixture")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

pub trait SshFactoryExt {
    fn ssh_key(&self, label: impl AsRef<str>, spec: SshSpec) -> SshKeyFixture;
    fn ssh_cert(&self, label: impl AsRef<str>, spec: crate::SshCertSpec) -> crate::SshCertFixture;
}

impl SshFactoryExt for Factory {
    fn ssh_key(&self, label: impl AsRef<str>, spec: SshSpec) -> SshKeyFixture {
        SshKeyFixture::new(self, label.as_ref(), spec)
    }

    fn ssh_cert(&self, label: impl AsRef<str>, spec: crate::SshCertSpec) -> crate::SshCertFixture {
        crate::SshCertFixture::new(self, label.as_ref(), spec)
    }
}

impl SshKeyFixture {
    pub(crate) fn new(factory: &Factory, label: &str, spec: SshSpec) -> Self {
        let spec_bytes = spec.stable_bytes();

        let inner = factory.get_or_init(DOMAIN_SSH_KEY, label, &spec_bytes, "good", |seed| {
            let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
            let algorithm = match spec {
                SshSpec::Ed25519 => Algorithm::Ed25519,
                SshSpec::Rsa => Algorithm::Rsa { hash: None },
            };

            let mut private_key =
                PrivateKey::random(&mut rng, algorithm).expect("failed to generate OpenSSH key");

            private_key.set_comment(format!("{label}@uselesskey.test"));
            let private_key_openssh = private_key
                .to_openssh(LineEnding::LF)
                .expect("failed to encode OpenSSH private key")
                .to_string();

            let mut public_key = private_key.public_key().clone();
            public_key.set_comment(format!("{label}@uselesskey.test"));
            let public_key_openssh = public_key
                .to_openssh()
                .expect("failed to encode OpenSSH public key");

            let authorized_keys_line = public_key_openssh.clone();

            Inner {
                private_key,
                private_key_openssh,
                authorized_keys_line,
                public_key_openssh,
            }
        });

        Self {
            label: label.to_owned(),
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

    pub fn private_key_openssh(&self) -> &str {
        &self.inner.private_key_openssh
    }

    pub fn public_key_openssh(&self) -> &str {
        &self.inner.public_key_openssh
    }

    pub fn authorized_keys_line(&self) -> &str {
        &self.inner.authorized_keys_line
    }

    pub fn public_key(&self) -> &PublicKey {
        self.inner.private_key.public_key()
    }

    pub(crate) fn private_key(&self) -> &PrivateKey {
        &self.inner.private_key
    }
}
