//! Key generation and rcgen key parsing for X.509 chains.

use rcgen::{KeyPair, PKCS_RSA_SHA256};
use rustls_pki_types::PrivatePkcs8KeyDer;
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaKeyPair, RsaSpec};

pub(crate) struct ChainKeys {
    pub(crate) root_rsa: RsaKeyPair,
    pub(crate) intermediate_rsa: RsaKeyPair,
    pub(crate) leaf_rsa: RsaKeyPair,
    pub(crate) root_key_pair: KeyPair,
    pub(crate) intermediate_key_pair: KeyPair,
    pub(crate) leaf_key_pair: KeyPair,
}

pub(crate) fn generate(factory: &Factory, label: &str, rsa_bits: usize) -> ChainKeys {
    let rsa_spec = RsaSpec::new(rsa_bits);

    let root_rsa = factory.rsa(format!("{label}-chain-root"), rsa_spec);
    let intermediate_rsa = factory.rsa(format!("{label}-chain-intermediate"), rsa_spec);
    let leaf_rsa = factory.rsa(format!("{label}-chain-leaf"), rsa_spec);

    let root_key_pair = parse_pkcs8_key(&root_rsa, "root");
    let intermediate_key_pair = parse_pkcs8_key(&intermediate_rsa, "intermediate");
    let leaf_key_pair = parse_pkcs8_key(&leaf_rsa, "leaf");

    ChainKeys {
        root_rsa,
        intermediate_rsa,
        leaf_rsa,
        root_key_pair,
        intermediate_key_pair,
        leaf_key_pair,
    }
}

fn parse_pkcs8_key(key: &RsaKeyPair, role: &str) -> KeyPair {
    KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(key.private_key_pkcs8_der().to_vec()),
        &PKCS_RSA_SHA256,
    )
    .unwrap_or_else(|_| panic!("{role} key parse"))
}
