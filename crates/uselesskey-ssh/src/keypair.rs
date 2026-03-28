use std::fmt;
use std::sync::Arc;

use rand_chacha10::ChaCha20Rng;
use rand_core10::SeedableRng;
use ssh_key::{LineEnding, PrivateKey, PublicKey};
use uselesskey_core::sink::TempArtifact;
use uselesskey_core::{Error, Factory};

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
    private_key: PrivateKey,
    private_openssh: String,
    public_openssh: String,
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

    fn ssh_cert(
        &self,
        label: impl AsRef<str>,
        spec: crate::SshCertSpec,
    ) -> crate::SshCertificate;

    fn ssh_cert_with_options(
        &self,
        label: impl AsRef<str>,
        spec: crate::SshCertSpecWithOptions,
    ) -> crate::SshCertificate;
}

impl SshFactoryExt for Factory {
    fn ssh_key(&self, label: impl AsRef<str>, spec: SshSpec) -> SshKeyPair {
        SshKeyPair::new(self, label.as_ref(), spec)
    }

    fn ssh_cert(
        &self,
        label: impl AsRef<str>,
        spec: crate::SshCertSpec,
    ) -> crate::SshCertificate {
        crate::SshCertificate::new(self, label.as_ref(), spec.into())
    }

    fn ssh_cert_with_options(
        &self,
        label: impl AsRef<str>,
        spec: crate::SshCertSpecWithOptions,
    ) -> crate::SshCertificate {
        crate::SshCertificate::new(self, label.as_ref(), spec)
    }
}

impl SshKeyPair {
    fn new(factory: &Factory, label: &str, spec: SshSpec) -> Self {
        let spec_bytes = spec.stable_bytes();
        let inner = factory.get_or_init(DOMAIN_SSH_KEYPAIR, label, &spec_bytes, "good", |seed| {
            let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
            let mut private_key =
                PrivateKey::random(&mut rng, spec.into()).expect("failed to generate SSH keypair");
            private_key.set_comment(comment_for_label(label));

            let private_openssh = private_key
                .to_openssh(LineEnding::LF)
                .expect("failed to encode OpenSSH private key")
                .to_string();
            let public_openssh = private_key
                .public_key()
                .to_openssh()
                .expect("failed to encode OpenSSH public key");

            Inner {
                private_key,
                private_openssh,
                public_openssh,
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

    pub fn private_key_openssh(&self) -> &str {
        &self.inner.private_openssh
    }

    pub fn authorized_key_line(&self) -> &str {
        &self.inner.public_openssh
    }

    pub fn public_key(&self) -> &PublicKey {
        self.inner.private_key.public_key()
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.inner.private_key
    }

    pub fn write_private_key_openssh(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".ssh", self.private_key_openssh())
    }

    pub fn write_authorized_key(&self) -> Result<TempArtifact, Error> {
        let line = format!("{}\n", self.authorized_key_line());
        TempArtifact::new_string("uselesskey-", ".pub", &line)
    }
}

fn comment_for_label(label: &str) -> String {
    if label.trim().is_empty() {
        "fixture@uselesskey.test".to_string()
    } else {
        format!("{label}@uselesskey.test")
    }
}
