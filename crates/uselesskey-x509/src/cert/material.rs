use rcgen::{KeyPair, PKCS_RSA_SHA256};
use rustls_pki_types::PrivatePkcs8KeyDer;
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaKeyPair, RsaSpec};

pub(super) struct CertKeyMaterial {
    pub(super) rsa: RsaKeyPair,
    pub(super) kp: Option<KeyPair>,
}

pub(super) fn generate(factory: &Factory, label: &str, rsa_bits: usize) -> CertKeyMaterial {
    let rsa_spec = RsaSpec::new(rsa_bits);
    let rsa = factory.rsa(format!("{}-key", label), rsa_spec);
    let kp = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(rsa.private_key_pkcs8_der().to_vec()),
        &PKCS_RSA_SHA256,
    )
    .ok();
    CertKeyMaterial { rsa, kp }
}
