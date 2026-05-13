//! SRP components for X.509 certificate chain generation.

use std::sync::Arc;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rcgen::{Certificate, Issuer};
use uselesskey_core::Factory;

use crate::chain::{ChainInner, DOMAIN_X509_CHAIN};
use crate::srp::chain::crl::maybe_revoked_leaf_crl;
use crate::srp::chain::keys::load_chain_keys;
use crate::srp::chain::params::build_chain_params;
use crate::srp::derive::deterministic_base_time_from_parts;
use crate::srp::spec::ChainSpec;

mod crl;
mod keys;
mod params;

pub(crate) fn load_chain_inner(
    factory: &Factory,
    label: &str,
    spec: &ChainSpec,
    variant: &str,
) -> Arc<ChainInner> {
    let spec_bytes = spec.stable_bytes();

    factory.get_or_init(DOMAIN_X509_CHAIN, label, &spec_bytes, variant, |seed| {
        generate_chain_inner(factory, label, spec, variant, seed.bytes())
    })
}

fn generate_chain_inner(
    factory: &Factory,
    label: &str,
    spec: &ChainSpec,
    variant: &str,
    seed: &[u8; 32],
) -> ChainInner {
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let keys = load_chain_keys(factory, label, spec);
    let base_time = chain_base_time(label, spec);
    let params = build_chain_params(spec, base_time, &mut rng);

    let root_cert = params
        .root
        .self_signed(&keys.root_kp)
        .expect("root cert gen");

    let root_issuer = Issuer::from_params(&params.root, &keys.root_kp);
    let intermediate_cert = params
        .intermediate
        .signed_by(&keys.intermediate_kp, &root_issuer)
        .expect("intermediate cert gen");

    let intermediate_issuer = Issuer::from_params(&params.intermediate, &keys.intermediate_kp);
    let leaf_cert = params
        .leaf
        .signed_by(&keys.leaf_kp, &intermediate_issuer)
        .expect("leaf cert gen");

    let crl = maybe_revoked_leaf_crl(
        variant,
        params.leaf_serial,
        base_time,
        &params.intermediate,
        &keys.intermediate_kp,
        &mut rng,
    );

    ChainInner {
        root_cert_der: cert_der(&root_cert),
        root_cert_pem: root_cert.pem(),
        root_key_pkcs8_der: Arc::from(keys.root_rsa.private_key_pkcs8_der()),
        root_key_pkcs8_pem: keys.root_rsa.private_key_pkcs8_pem().to_string(),

        intermediate_cert_der: cert_der(&intermediate_cert),
        intermediate_cert_pem: intermediate_cert.pem(),
        intermediate_key_pkcs8_der: Arc::from(keys.intermediate_rsa.private_key_pkcs8_der()),
        intermediate_key_pkcs8_pem: keys.intermediate_rsa.private_key_pkcs8_pem().to_string(),

        leaf_cert_der: cert_der(&leaf_cert),
        leaf_cert_pem: leaf_cert.pem(),
        leaf_key_pkcs8_der: Arc::from(keys.leaf_rsa.private_key_pkcs8_der()),
        leaf_key_pkcs8_pem: keys.leaf_rsa.private_key_pkcs8_pem().to_string(),

        crl_der: crl.as_ref().map(|crl| crl.der.clone()),
        crl_pem: crl.map(|crl| crl.pem),
    }
}

fn chain_base_time(label: &str, spec: &ChainSpec) -> time::OffsetDateTime {
    let rsa_bits = (spec.rsa_bits as u32).to_be_bytes();
    deterministic_base_time_from_parts(&[
        label.as_bytes(),
        spec.leaf_cn.as_bytes(),
        spec.root_cn.as_bytes(),
        &rsa_bits,
    ])
}

fn cert_der(cert: &Certificate) -> Arc<[u8]> {
    Arc::from(cert.der().as_ref())
}
