//! X.509 chain key-material helpers.
//!
//! This module owns the RSA fixture labels used by chain generation and the
//! conversion from reusable `uselesskey-rsa` fixtures into `rcgen` signing keys.

use rcgen::{KeyPair, PKCS_RSA_SHA256};
use rustls_pki_types::PrivatePkcs8KeyDer;
use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaKeyPair, RsaSpec};

/// RSA fixture material and parsed `rcgen` signers for a root/intermediate/leaf chain.
pub(crate) struct ChainKeyMaterial {
    pub(crate) root_rsa: RsaKeyPair,
    pub(crate) root_kp: KeyPair,
    pub(crate) intermediate_rsa: RsaKeyPair,
    pub(crate) intermediate_kp: KeyPair,
    pub(crate) leaf_rsa: RsaKeyPair,
    pub(crate) leaf_kp: KeyPair,
}

/// Generate role-tagged RSA key fixtures and parse them for X.509 signing.
pub(crate) fn load_chain_key_material(
    factory: &Factory,
    label: &str,
    rsa_bits: usize,
) -> ChainKeyMaterial {
    let rsa_spec = RsaSpec::new(rsa_bits);

    let root_rsa = factory.rsa(format!("{label}-chain-root"), rsa_spec);
    let intermediate_rsa = factory.rsa(format!("{label}-chain-intermediate"), rsa_spec);
    let leaf_rsa = factory.rsa(format!("{label}-chain-leaf"), rsa_spec);

    let root_kp = parse_rsa_signing_key(&root_rsa, "root");
    let intermediate_kp = parse_rsa_signing_key(&intermediate_rsa, "intermediate");
    let leaf_kp = parse_rsa_signing_key(&leaf_rsa, "leaf");

    ChainKeyMaterial {
        root_rsa,
        root_kp,
        intermediate_rsa,
        intermediate_kp,
        leaf_rsa,
        leaf_kp,
    }
}

fn parse_rsa_signing_key(rsa: &RsaKeyPair, role: &str) -> KeyPair {
    KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(rsa.private_key_pkcs8_der().to_vec()),
        &PKCS_RSA_SHA256,
    )
    .unwrap_or_else(|_| panic!("{role} key parse"))
}
