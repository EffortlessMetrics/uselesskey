use std::fmt;
use std::sync::Arc;

use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};
use ssh_key::Certificate;
use ssh_key::certificate::{Builder, CertType};
use uselesskey_core::Factory;

use crate::{SshCertSpec, SshCertType, SshKeyFixture};

/// Cache domain for SSH certificate fixtures.
pub const DOMAIN_SSH_CERT: &str = "uselesskey:ssh:cert";

#[derive(Clone)]
pub struct SshCertFixture {
    label: String,
    spec: SshCertSpec,
    inner: Arc<Inner>,
}

struct Inner {
    subject_key: SshKeyFixture,
    ca_key: SshKeyFixture,
    certificate: Certificate,
    certificate_openssh: String,
}

impl fmt::Debug for SshCertFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshCertFixture")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

impl SshCertFixture {
    pub(crate) fn new(factory: &Factory, label: &str, spec: SshCertSpec) -> Self {
        let spec_bytes = spec.stable_bytes();

        let inner = factory.get_or_init(DOMAIN_SSH_CERT, label, &spec_bytes, "good", |seed| {
            let subject_key = SshKeyFixture::new(factory, &format!("{label}:subject"), spec.subject_key);
            let ca_key = SshKeyFixture::new(factory, &format!("{label}:ca"), spec.ca_key);

            let mut nonce_rng = ChaCha20Rng::from_seed(*seed.bytes());
            let mut nonce = [0u8; Builder::RECOMMENDED_NONCE_SIZE];
            nonce_rng.fill_bytes(&mut nonce);

            let mut builder = Builder::new(
                nonce.to_vec(),
                subject_key.public_key().key_data().clone(),
                spec.validity.valid_after,
                spec.validity.valid_before,
            )
            .expect("invalid SSH certificate validity");

            builder
                .cert_type(match spec.cert_type {
                    SshCertType::User => CertType::User,
                    SshCertType::Host => CertType::Host,
                })
                .expect("failed to set cert type");

            builder
                .key_id(format!("{label}-cert"))
                .expect("failed to set key id");
            builder.serial(1).expect("failed to set serial");
            builder
                .comment(format!("{label}@uselesskey.test"))
                .expect("failed to set comment");

            if spec.principals.is_empty() {
                builder
                    .all_principals_valid()
                    .expect("failed to set all-principals certificate");
            } else {
                for principal in &spec.principals {
                    builder
                        .valid_principal(principal.clone())
                        .expect("failed to set principal");
                }
            }

            for (name, data) in &spec.critical_options {
                builder
                    .critical_option(name.clone(), data.clone())
                    .expect("failed to set critical option");
            }

            for (name, data) in &spec.extensions {
                builder
                    .extension(name.clone(), data.clone())
                    .expect("failed to set extension");
            }

            let certificate = builder
                .sign(ca_key.private_key())
                .expect("failed to sign SSH certificate");

            let certificate_openssh = certificate
                .to_openssh()
                .expect("failed to encode SSH certificate");

            Inner {
                subject_key,
                ca_key,
                certificate,
                certificate_openssh,
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

    pub fn spec(&self) -> &SshCertSpec {
        &self.spec
    }

    pub fn certificate_openssh(&self) -> &str {
        &self.inner.certificate_openssh
    }

    pub fn certificate(&self) -> &Certificate {
        &self.inner.certificate
    }

    pub fn subject_key(&self) -> &SshKeyFixture {
        &self.inner.subject_key
    }

    pub fn ca_key(&self) -> &SshKeyFixture {
        &self.inner.ca_key
    }
}
