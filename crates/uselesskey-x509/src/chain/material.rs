use rcgen::{KeyPair, PKCS_RSA_SHA256};
use rustls_pki_types::PrivatePkcs8KeyDer;
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaKeyPair, RsaSpec};

pub(super) struct ChainKeyMaterial {
    pub(super) root_rsa: RsaKeyPair,
    pub(super) root_kp: KeyPair,
    pub(super) intermediate_rsa: RsaKeyPair,
    pub(super) intermediate_kp: KeyPair,
    pub(super) leaf_rsa: RsaKeyPair,
    pub(super) leaf_kp: KeyPair,
}

pub(super) fn generate(factory: &Factory, label: &str, rsa_bits: usize) -> ChainKeyMaterial {
    let rsa_spec = RsaSpec::new(rsa_bits);
    let root_rsa = factory.rsa(format!("{}-chain-root", label), rsa_spec);
    let intermediate_rsa = factory.rsa(format!("{}-chain-intermediate", label), rsa_spec);
    let leaf_rsa = factory.rsa(format!("{}-chain-leaf", label), rsa_spec);

    ChainKeyMaterial {
        root_kp: parse_key_pair(&root_rsa, "root"),
        intermediate_kp: parse_key_pair(&intermediate_rsa, "intermediate"),
        leaf_kp: parse_key_pair(&leaf_rsa, "leaf"),
        root_rsa,
        intermediate_rsa,
        leaf_rsa,
    }
}

fn parse_key_pair(key_pair: &RsaKeyPair, role: &str) -> KeyPair {
    KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(key_pair.private_key_pkcs8_der().to_vec()),
        &PKCS_RSA_SHA256,
    )
    .unwrap_or_else(|_| panic!("{role} key parse"))
}
