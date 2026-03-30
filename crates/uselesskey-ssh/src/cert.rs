use std::fmt;
use std::sync::Arc;

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use ssh_key::certificate::{Builder, CertType};
use ssh_key::{Algorithm, Certificate, LineEnding, PrivateKey};
use uselesskey_core::Factory;

use crate::{SshCertSpec, SshCertType};

/// Cache domain for SSH certificate fixtures.
pub const DOMAIN_SSH_CERT: &str = "uselesskey:ssh:cert";

#[derive(Clone)]
pub struct SshCertFixture {
    label: String,
    spec: SshCertSpec,
    inner: Arc<Inner>,
}

struct Inner {
    private_key_openssh: String,
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

pub trait SshCertFactoryExt {
    fn ssh_cert(&self, label: impl AsRef<str>, spec: SshCertSpec) -> SshCertFixture;
}

impl SshCertFactoryExt for Factory {
    fn ssh_cert(&self, label: impl AsRef<str>, spec: SshCertSpec) -> SshCertFixture {
        SshCertFixture::new(self, label.as_ref(), spec)
    }
}

impl SshCertFixture {
    fn new(factory: &Factory, label: &str, spec: SshCertSpec) -> Self {
        let spec_bytes = spec.stable_bytes();
        let inner = factory.get_or_init(DOMAIN_SSH_CERT, label, &spec_bytes, "good", |seed| {
            let mut rng = ChaCha20Rng::from_seed(*seed.bytes());

            let ca_private =
                PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("SSH CA keygen failed");
            let subject_private =
                PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("SSH keygen failed");

            let mut builder = Builder::new(
                seed.bytes()[..16].to_vec(),
                subject_private.public_key().key_data().clone(),
                spec.validity.valid_after,
                spec.validity.valid_before,
            )
            .expect("invalid SSH certificate validity window");

            builder.serial(0).expect("unable to set cert serial");
            builder
                .key_id(label.to_owned())
                .expect("unable to set cert key_id");
            builder
                .cert_type(to_cert_type(spec.cert_type))
                .expect("unable to set cert type");

            for principal in &spec.principals {
                builder
                    .valid_principal(principal.clone())
                    .expect("unable to add valid principal");
            }
            if spec.principals.is_empty() {
                builder
                    .all_principals_valid()
                    .expect("unable to mark all principals valid");
            }

            for (name, value) in &spec.critical_options {
                builder
                    .critical_option(name.clone(), value.clone())
                    .expect("unable to add critical option");
            }
            for (name, value) in &spec.extensions {
                builder
                    .extension(name.clone(), value.clone())
                    .expect("unable to add extension");
            }

            let cert = builder.sign(&ca_private).expect("unable to sign SSH cert");

            Inner {
                private_key_openssh: subject_private
                    .to_openssh(LineEnding::LF)
                    .expect("OpenSSH private key encoding failed")
                    .to_string(),
                certificate_openssh: cert.to_openssh().expect("OpenSSH cert encoding failed"),
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

    pub fn spec(&self) -> &SshCertSpec {
        &self.spec
    }

    pub fn private_key_openssh(&self) -> &str {
        &self.inner.private_key_openssh
    }

    pub fn certificate_openssh(&self) -> &str {
        &self.inner.certificate_openssh
    }

    pub fn certificate(&self) -> Certificate {
        Certificate::from_openssh(self.certificate_openssh()).expect("stored SSH cert must parse")
    }
}

fn to_cert_type(cert_type: SshCertType) -> CertType {
    match cert_type {
        SshCertType::User => CertType::User,
        SshCertType::Host => CertType::Host,
    }
}

#[cfg(test)]
mod tests {
    use ssh_key::certificate::CertType;
    use uselesskey_core::Seed;

    use super::*;
    use crate::SshValidity;

    #[test]
    fn cert_principals_and_validity_are_encoded() {
        let fx = Factory::deterministic(Seed::from_env_value("ssh-cert-principals").unwrap());
        let spec = SshCertSpec {
            principals: vec!["deploy".to_string(), "ops".to_string()],
            validity: SshValidity::new(1_700_000_000, 1_700_000_600),
            cert_type: SshCertType::User,
            critical_options: vec![("force-command".to_string(), "/usr/bin/true".to_string())],
            extensions: vec![("permit-pty".to_string(), String::new())],
        };

        let cert = fx.ssh_cert("deploy-cert", spec).certificate();

        assert_eq!(
            cert.valid_principals(),
            ["deploy".to_string(), "ops".to_string()]
        );
        assert_eq!(cert.valid_after(), 1_700_000_000);
        assert_eq!(cert.valid_before(), 1_700_000_600);
        assert_eq!(cert.cert_type(), CertType::User);
        assert_eq!(
            cert.critical_options()
                .get("force-command")
                .map(String::as_str),
            Some("/usr/bin/true")
        );
        assert!(cert.extensions().contains_key("permit-pty"));
    }

    #[test]
    fn cert_round_trip_parse() {
        let fx = Factory::random();
        let cert = fx
            .ssh_cert(
                "host-cert",
                SshCertSpec::host(["host1.internal"], SshValidity::new(10, 20)),
            )
            .certificate();

        let encoded = cert.to_openssh().unwrap();
        let decoded = Certificate::from_openssh(&encoded).unwrap();

        assert_eq!(decoded.valid_principals(), ["host1.internal".to_string()]);
        assert_eq!(decoded.cert_type(), CertType::Host);
    }
}
