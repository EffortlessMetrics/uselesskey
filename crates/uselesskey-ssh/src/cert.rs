use std::fmt;
use std::sync::Arc;

use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};
use ssh_key::certificate::Builder;
use ssh_key::{Certificate, PrivateKey};
use uselesskey_core::Factory;

use crate::{SshCertSpecWithOptions, SshSpec};

/// Cache domain for SSH certificate fixtures.
pub const DOMAIN_SSH_CERT: &str = "uselesskey:ssh:cert";

#[derive(Clone)]
pub struct SshCertificate {
    label: String,
    spec: SshCertSpecWithOptions,
    inner: Arc<Inner>,
}

struct Inner {
    cert: Certificate,
    cert_openssh: String,
    subject_private_key_openssh: String,
    ca_private_key_openssh: String,
}

impl fmt::Debug for SshCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshCertificate")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

impl SshCertificate {
    pub(crate) fn new(factory: &Factory, label: &str, spec: SshCertSpecWithOptions) -> Self {
        let spec_bytes = spec.stable_bytes();
        let inner = factory.get_or_init(DOMAIN_SSH_CERT, label, &spec_bytes, "good", |seed| {
            let mut rng = ChaCha20Rng::from_seed(*seed.bytes());

            let mut subject_key = PrivateKey::random(&mut rng, SshSpec::Ed25519.into())
                .expect("failed to generate SSH subject key");
            subject_key.set_comment(format!("{label}-subject@uselesskey.test"));

            let mut ca_key = PrivateKey::random(&mut rng, SshSpec::Ed25519.into())
                .expect("failed to generate SSH CA key");
            ca_key.set_comment(format!("{label}-ca@uselesskey.test"));

            let mut nonce = [0u8; 16];
            rng.fill_bytes(&mut nonce);
            let mut builder = Builder::new(
                nonce,
                subject_key.public_key().key_data().clone(),
                spec.spec.validity.valid_after,
                spec.spec.validity.valid_before,
            )
            .expect("failed to initialize SSH certificate builder");

            builder
                .cert_type(spec.spec.cert_type.into())
                .expect("invalid SSH certificate type")
                .key_id(format!("{label}-cert"))
                .expect("invalid SSH certificate key id")
                .comment(format!("{label}@uselesskey.test"))
                .expect("invalid SSH certificate comment");

            if spec.spec.principals.is_empty() {
                builder
                    .all_principals_valid()
                    .expect("failed to mark all principals as valid");
            } else {
                for principal in &spec.spec.principals {
                    builder
                        .valid_principal(principal)
                        .expect("invalid SSH principal");
                }
            }

            for (name, value) in &spec.critical_options {
                builder
                    .critical_option(name, value)
                    .expect("invalid SSH critical option");
            }

            for (name, value) in &spec.extensions {
                builder
                    .extension(name, value)
                    .expect("invalid SSH extension");
            }

            let cert = builder.sign(&ca_key).expect("failed to sign SSH certificate");
            let cert_openssh = cert.to_openssh().expect("failed to encode SSH certificate");
            let subject_private_key_openssh = subject_key
                .to_openssh(ssh_key::LineEnding::LF)
                .expect("failed to encode SSH subject private key")
                .to_string();
            let ca_private_key_openssh = ca_key
                .to_openssh(ssh_key::LineEnding::LF)
                .expect("failed to encode SSH CA private key")
                .to_string();

            Inner {
                cert,
                cert_openssh,
                subject_private_key_openssh,
                ca_private_key_openssh,
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

    pub fn spec(&self) -> &SshCertSpecWithOptions {
        &self.spec
    }

    pub fn cert_openssh(&self) -> &str {
        &self.inner.cert_openssh
    }

    pub fn cert(&self) -> &Certificate {
        &self.inner.cert
    }

    pub fn subject_private_key_openssh(&self) -> &str {
        &self.inner.subject_private_key_openssh
    }

    pub fn ca_private_key_openssh(&self) -> &str {
        &self.inner.ca_private_key_openssh
    }
}
