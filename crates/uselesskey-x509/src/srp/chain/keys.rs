//! RSA key material loading for X.509 chains.

use rcgen::{KeyPair, PKCS_RSA_SHA256};
use rustls_pki_types::PrivatePkcs8KeyDer;
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaKeyPair, RsaSpec};

use crate::srp::spec::ChainSpec;

pub(crate) struct ChainKeys {
    pub(crate) root_rsa: RsaKeyPair,
    pub(crate) intermediate_rsa: RsaKeyPair,
    pub(crate) leaf_rsa: RsaKeyPair,
    pub(crate) root_kp: KeyPair,
    pub(crate) intermediate_kp: KeyPair,
    pub(crate) leaf_kp: KeyPair,
}

pub(crate) fn load_chain_keys(factory: &Factory, label: &str, spec: &ChainSpec) -> ChainKeys {
    let rsa_spec = RsaSpec::new(spec.rsa_bits);

    let root_rsa = factory.rsa(format!("{label}-chain-root"), rsa_spec);
    let intermediate_rsa = factory.rsa(format!("{label}-chain-intermediate"), rsa_spec);
    let leaf_rsa = factory.rsa(format!("{label}-chain-leaf"), rsa_spec);

    let root_kp = key_pair_from_rsa(&root_rsa, "root");
    let intermediate_kp = key_pair_from_rsa(&intermediate_rsa, "intermediate");
    let leaf_kp = key_pair_from_rsa(&leaf_rsa, "leaf");

    ChainKeys {
        root_rsa,
        intermediate_rsa,
        leaf_rsa,
        root_kp,
        intermediate_kp,
        leaf_kp,
    }
}

fn key_pair_from_rsa(rsa: &RsaKeyPair, role: &str) -> KeyPair {
    KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(rsa.private_key_pkcs8_der().to_vec()),
        &PKCS_RSA_SHA256,
    )
    .unwrap_or_else(|_| panic!("{role} key parse"))
}
