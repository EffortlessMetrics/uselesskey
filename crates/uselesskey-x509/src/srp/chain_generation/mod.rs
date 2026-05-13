//! Single-responsibility chain generation orchestration.

mod crl;
mod keys;
mod params;

use std::sync::Arc;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use rcgen::Issuer;
use uselesskey_core::Factory;

use crate::chain::{ChainInner, DOMAIN_X509_CHAIN};
use crate::srp::spec::ChainSpec;

pub(crate) fn load_inner(
    factory: &Factory,
    label: &str,
    spec: &ChainSpec,
    variant: &str,
) -> Arc<ChainInner> {
    let spec_bytes = spec.stable_bytes();

    factory.get_or_init(DOMAIN_X509_CHAIN, label, &spec_bytes, variant, |seed| {
        let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
        let keys = keys::generate(factory, label, spec.rsa_bits);
        let base_time = params::base_time(label, spec);

        let root_params = params::root(spec, base_time, &mut rng);
        let root_cert = root_params
            .self_signed(&keys.root_key_pair)
            .expect("root cert gen");

        let intermediate_params = params::intermediate(spec, base_time, &mut rng);
        let root_issuer = Issuer::from_params(&root_params, &keys.root_key_pair);
        let intermediate_cert = intermediate_params
            .signed_by(&keys.intermediate_key_pair, &root_issuer)
            .expect("intermediate cert gen");

        let (leaf_params, leaf_serial) = params::leaf(spec, base_time, &mut rng);
        let intermediate_issuer =
            Issuer::from_params(&intermediate_params, &keys.intermediate_key_pair);
        let leaf_cert = leaf_params
            .signed_by(&keys.leaf_key_pair, &intermediate_issuer)
            .expect("leaf cert gen");

        let (crl_der, crl_pem) = crl::revoked_leaf(
            variant,
            &mut rng,
            base_time,
            leaf_serial,
            &intermediate_params,
            &keys.intermediate_key_pair,
        );

        ChainInner {
            root_cert_der: Arc::from(root_cert.der().as_ref()),
            root_cert_pem: root_cert.pem(),
            root_key_pkcs8_der: Arc::from(keys.root_rsa.private_key_pkcs8_der()),
            root_key_pkcs8_pem: keys.root_rsa.private_key_pkcs8_pem().to_string(),

            intermediate_cert_der: Arc::from(intermediate_cert.der().as_ref()),
            intermediate_cert_pem: intermediate_cert.pem(),
            intermediate_key_pkcs8_der: Arc::from(keys.intermediate_rsa.private_key_pkcs8_der()),
            intermediate_key_pkcs8_pem: keys.intermediate_rsa.private_key_pkcs8_pem().to_string(),

            leaf_cert_der: Arc::from(leaf_cert.der().as_ref()),
            leaf_cert_pem: leaf_cert.pem(),
            leaf_key_pkcs8_der: Arc::from(keys.leaf_rsa.private_key_pkcs8_der()),
            leaf_key_pkcs8_pem: keys.leaf_rsa.private_key_pkcs8_pem().to_string(),

            crl_der,
            crl_pem,
        }
    })
}
