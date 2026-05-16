//! Self-signed certificate material generation.

use std::sync::Arc;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rcgen::{KeyPair, PKCS_RSA_SHA256};
use rustls_pki_types::PrivatePkcs8KeyDer;
use uselesskey_core::{Factory, Seed};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

use crate::srp::cert_params::self_signed_params;
use crate::srp::spec::X509Spec;

pub(crate) struct SelfSignedMaterial {
    pub(crate) cert_der: Arc<[u8]>,
    pub(crate) cert_pem: String,
    pub(crate) private_key_pkcs8_der: Arc<[u8]>,
    pub(crate) private_key_pkcs8_pem: String,
}

pub(crate) fn generate_self_signed(
    factory: &Factory,
    label: &str,
    spec: &X509Spec,
    seed: &Seed,
) -> SelfSignedMaterial {
    let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
    let rsa_keypair = certificate_keypair(factory, label, spec);
    let pkcs8_der = rsa_keypair.private_key_pkcs8_der();
    let key_pair = rcgen_keypair(pkcs8_der);
    let params = self_signed_params(label, spec, &mut rng);
    let cert = params.self_signed(&key_pair).expect("cert generation");

    SelfSignedMaterial {
        cert_der: Arc::from(cert.der().as_ref()),
        cert_pem: cert.pem(),
        private_key_pkcs8_der: Arc::from(pkcs8_der),
        private_key_pkcs8_pem: rsa_keypair.private_key_pkcs8_pem().to_string(),
    }
}

fn certificate_keypair(
    factory: &Factory,
    label: &str,
    spec: &X509Spec,
) -> uselesskey_rsa::RsaKeyPair {
    let key_label = format!("{}-key", label);
    factory.rsa(&key_label, RsaSpec::new(spec.rsa_bits))
}

fn rcgen_keypair(pkcs8_der: &[u8]) -> KeyPair {
    let pkcs8_key = PrivatePkcs8KeyDer::from(pkcs8_der.to_vec());
    KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_key, &PKCS_RSA_SHA256).expect("key parse")
}
