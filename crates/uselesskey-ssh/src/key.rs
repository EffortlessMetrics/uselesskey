use std::fmt;
use std::sync::Arc;

use ssh_key::private::PrivateKey;
use ssh_key::{Algorithm, LineEnding};
use uselesskey_core::{Factory, Seed};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use ssh_key::private::KeypairData;

use crate::cert::{CertType, SshCertFixture, SshCertSpec};
use crate::spec::{SshAlgorithm, SshSpec};

pub const DOMAIN_SSH_KEYPAIR: &str = "uselesskey:ssh:keypair";
pub const DOMAIN_SSH_CERT: &str = "uselesskey:ssh:cert";

#[derive(Clone)]
pub struct SshKeyFixture {
    label: String,
    spec: SshSpec,
    inner: Arc<Inner>,
}

#[derive(Clone)]
struct Inner {
    authorized_keys_line: String,
    openssh_private_key: String,
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
    fn ssh_cert(&self, label: impl AsRef<str>, spec: SshCertSpec) -> SshCertFixture;
}

impl SshFactoryExt for Factory {
    fn ssh_key(&self, label: impl AsRef<str>, spec: SshSpec) -> SshKeyFixture {
        let label = label.as_ref();
        let spec_bytes = spec.fingerprint_bytes();
        let inner = self.get_or_init(DOMAIN_SSH_KEYPAIR, label, &spec_bytes, "good", |_| {
            build_key_fixture(self, label, spec)
        });
        SshKeyFixture {
            label: label.to_string(),
            spec,
            inner,
        }
    }

    fn ssh_cert(&self, label: impl AsRef<str>, spec: SshCertSpec) -> SshCertFixture {
        let label = label.as_ref();
        let spec_bytes = spec.fingerprint_bytes();
        self.get_or_init(DOMAIN_SSH_CERT, label, &spec_bytes, "good", |seed| {
            build_cert_fixture(self, label, &spec, seed)
        })
        .as_ref()
        .clone()
    }
}

impl SshKeyFixture {
    pub fn authorized_keys_line(&self) -> &str {
        &self.inner.authorized_keys_line
    }

    pub fn openssh_private_key(&self) -> &str {
        &self.inner.openssh_private_key
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn spec(&self) -> SshSpec {
        self.spec
    }
}

fn build_key_fixture(factory: &Factory, label: &str, spec: SshSpec) -> Inner {
    let seed_bytes = factory
        .get_or_init(DOMAIN_SSH_KEYPAIR, label, &spec.fingerprint_bytes(), "seed", |seed| {
            *seed.bytes()
        });
    let mut rng = ChaCha20Rng::from_seed(*seed_bytes);
    let key = match spec.algorithm() {
        SshAlgorithm::Ed25519 => {
            PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("ssh ed25519 generation")
        }
        SshAlgorithm::Rsa { bits } => {
            let rsa = rsa09::RsaPrivateKey::new(&mut rng, bits).expect("rsa generation");
            let ssh_rsa = ssh_key::private::RsaKeypair::try_from(&rsa).expect("rsa conversion");
            let data = KeypairData::from(ssh_rsa);
            PrivateKey::new(data, label).expect("ssh rsa private key")
        }
    };

    let mut public_line = key.public_key().to_openssh().expect("openssh public line");
    public_line.push_str(&format!(" {label}"));

    let private = key
        .to_openssh(LineEnding::LF)
        .expect("openssh private key encode");

    Inner {
        authorized_keys_line: public_line,
        openssh_private_key: private.to_string(),
    }
}

fn build_cert_fixture(factory: &Factory, label: &str, spec: &SshCertSpec, seed: Seed) -> SshCertFixture {
    let subject = factory.ssh_key(label, SshSpec::ed25519());
    let subject_key =
        PrivateKey::from_openssh(subject.openssh_private_key()).expect("parse subject private key");
    let signer = factory.ssh_key(&format!("{label}:ca"), SshSpec::ed25519());
    let signer_key =
        PrivateKey::from_openssh(signer.openssh_private_key()).expect("parse signer private key");

    let cert_type = match spec.cert_type {
        CertType::User => ssh_key::certificate::CertType::User,
        CertType::Host => ssh_key::certificate::CertType::Host,
    };

    let mut serial_bytes = [0u8; 8];
    seed.fill_bytes(&mut serial_bytes);
    let serial = u64::from_le_bytes(serial_bytes);

    let mut nonce = [0u8; 16];
    seed.fill_bytes(&mut nonce);
    let mut builder = ssh_key::certificate::Builder::new(
        nonce,
        subject_key.public_key().key_data().clone(),
        spec.validity.valid_after,
        spec.validity.valid_before,
    )
    .expect("certificate builder");
    builder.serial(serial).expect("serial");
    builder.cert_type(cert_type).expect("cert type");
    builder.key_id(label).expect("key id");
    for principal in &spec.principals {
        builder
            .valid_principal(principal.clone())
            .expect("valid principal");
    }

    for (k, v) in &spec.critical_options {
        builder
            .critical_option(k.clone(), v.clone())
            .expect("critical option");
    }
    for (k, v) in &spec.extensions {
        builder.extension(k.clone(), v.clone()).expect("extension");
    }

    let cert = builder.sign(&signer_key).expect("sign ssh cert");
    let cert_line = cert.to_openssh().expect("encode ssh cert line");
    SshCertFixture { cert_line }
}
