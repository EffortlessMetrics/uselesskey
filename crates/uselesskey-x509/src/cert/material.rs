use rcgen::{KeyPair, PKCS_RSA_SHA256};
use rustls_pki_types::PrivatePkcs8KeyDer;
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaKeyPair, RsaSpec};

pub(super) struct CertKeyMaterial {
    pub(super) rsa: RsaKeyPair,
    pub(super) key_pair: KeyPair,
}

pub(super) fn generate(factory: &Factory, label: &str, rsa_bits: usize) -> CertKeyMaterial {
    let key_label = format!("{}-key", label);
    let rsa = factory.rsa(&key_label, RsaSpec::new(rsa_bits));

    CertKeyMaterial {
        key_pair: parse_key_pair(&rsa),
        rsa,
    }
}

fn parse_key_pair(key_pair: &RsaKeyPair) -> KeyPair {
    KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(key_pair.private_key_pkcs8_der().to_vec()),
        &PKCS_RSA_SHA256,
    )
    .expect("key parse")
}
