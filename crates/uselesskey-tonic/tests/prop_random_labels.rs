//! Property tests: random labels and mTLS adapters for tonic fixtures.

use proptest::prelude::*;
use uselesskey_core::{Factory, Seed};
use uselesskey_tonic::{TonicClientTlsExt, TonicIdentityExt, TonicMtlsExt, TonicServerTlsExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

proptest! {
    // RSA keygen is expensive; keep case count low.
    #![proptest_config(ProptestConfig { cases: 5, ..ProptestConfig::default() })]

    /// Random labels produce valid tonic identity from self-signed certs.
    #[test]
    fn random_label_self_signed_identity(
        seed in any::<[u8; 32]>(),
        label in "[a-zA-Z][a-zA-Z0-9_]{0,15}",
    ) {
        let fx = Factory::deterministic(Seed::new(seed));
        let spec = X509Spec::self_signed("prop.example.com");
        let cert = fx.x509_self_signed(&label, spec);

        // Adapter methods must not panic.
        let _ = cert.identity_tonic();
        let _ = cert.server_tls_config_tonic();
        let _ = cert.client_tls_config_tonic("prop.example.com");
    }

    /// Random labels produce valid tonic identity from certificate chains.
    #[test]
    fn random_label_chain_identity(
        seed in any::<[u8; 32]>(),
        label in "[a-zA-Z][a-zA-Z0-9_]{0,15}",
    ) {
        let fx = Factory::deterministic(Seed::new(seed));
        let spec = ChainSpec::new("prop-chain.example.com");
        let chain = fx.x509_chain(&label, spec);

        // Adapter methods must not panic.
        let _ = chain.identity_tonic();
        let _ = chain.server_tls_config_tonic();
        let _ = chain.client_tls_config_tonic("prop-chain.example.com");
    }

    /// mTLS config generation from random seeds never panics.
    #[test]
    fn mtls_config_never_panics(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let chain = fx.x509_chain("prop-mtls", ChainSpec::new("mtls.example.com"));

        let _ = chain.server_tls_config_mtls_tonic();
        let _ = chain.client_tls_config_mtls_tonic("mtls.example.com");
    }

    /// Deterministic mTLS: same seed produces identical underlying PEM.
    #[test]
    fn deterministic_mtls_stability(seed in any::<[u8; 32]>()) {
        let fx1 = Factory::deterministic(Seed::new(seed));
        let fx2 = Factory::deterministic(Seed::new(seed));

        let c1 = fx1.x509_chain("prop-mtls-det", ChainSpec::new("mtls.example.com"));
        let c2 = fx2.x509_chain("prop-mtls-det", ChainSpec::new("mtls.example.com"));

        prop_assert_eq!(c1.chain_pem(), c2.chain_pem());
        prop_assert_eq!(c1.root_cert_pem(), c2.root_cert_pem());
        prop_assert_eq!(
            c1.leaf_private_key_pkcs8_pem(),
            c2.leaf_private_key_pkcs8_pem(),
        );
    }
}
