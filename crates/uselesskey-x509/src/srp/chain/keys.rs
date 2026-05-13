//! RSA key material and rcgen key-pair conversion for chain generation.

use rcgen::{KeyPair, PKCS_RSA_SHA256};
use rustls_pki_types::PrivatePkcs8KeyDer;
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaKeyPair, RsaSpec};

pub(crate) struct ChainKeys {
    pub(crate) root_rsa: RsaKeyPair,
    pub(crate) intermediate_rsa: RsaKeyPair,
    pub(crate) leaf_rsa: RsaKeyPair,
    pub(crate) root_kp: KeyPair,
    pub(crate) intermediate_kp: KeyPair,
    pub(crate) leaf_kp: KeyPair,
}

impl ChainKeys {
    pub(crate) fn load(factory: &Factory, label: &str, rsa_spec: RsaSpec) -> Self {
        let root_key_label = format!("{}-chain-root", label);
        let intermediate_key_label = format!("{}-chain-intermediate", label);
        let leaf_key_label = format!("{}-chain-leaf", label);

        let root_rsa = factory.rsa(&root_key_label, rsa_spec);
        let intermediate_rsa = factory.rsa(&intermediate_key_label, rsa_spec);
        let leaf_rsa = factory.rsa(&leaf_key_label, rsa_spec);

        let root_kp = key_pair_from_rsa(&root_rsa, "root key parse");
        let intermediate_kp = key_pair_from_rsa(&intermediate_rsa, "intermediate key parse");
        let leaf_kp = key_pair_from_rsa(&leaf_rsa, "leaf key parse");

        Self {
            root_rsa,
            intermediate_rsa,
            leaf_rsa,
            root_kp,
            intermediate_kp,
            leaf_kp,
        }
    }
}

fn key_pair_from_rsa(rsa: &RsaKeyPair, context: &str) -> KeyPair {
    KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(rsa.private_key_pkcs8_der().to_vec()),
        &PKCS_RSA_SHA256,
    )
    .expect(context)
}
