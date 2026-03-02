//! Property tests: random labels and label independence for X.509 fixtures.

use proptest::prelude::*;
use uselesskey_core::{Factory, Seed};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

proptest! {
    // RSA keygen is expensive; keep case count low.
    #![proptest_config(ProptestConfig { cases: 5, ..ProptestConfig::default() })]

    /// Random labels always produce valid self-signed cert PEM.
    #[test]
    fn random_label_self_signed_format(
        seed in any::<[u8; 32]>(),
        label in "[a-zA-Z][a-zA-Z0-9_]{0,15}",
    ) {
        let fx = Factory::deterministic(Seed::new(seed));
        let spec = X509Spec::self_signed("prop.example.com");
        let cert = fx.x509_self_signed(&label, spec);

        prop_assert!(cert.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
        prop_assert!(cert.private_key_pkcs8_pem().starts_with("-----BEGIN PRIVATE KEY-----"));
        prop_assert!(!cert.cert_der().is_empty());
        prop_assert!(!cert.private_key_pkcs8_der().is_empty());
    }

    /// Different labels produce different self-signed certificates.
    #[test]
    fn self_signed_label_independence(
        seed in any::<[u8; 32]>(),
        label_a in "[a-zA-Z][a-zA-Z0-9]{1,8}",
        label_b in "[a-zA-Z][a-zA-Z0-9]{1,8}",
    ) {
        prop_assume!(label_a != label_b);
        let fx = Factory::deterministic(Seed::new(seed));
        let spec = X509Spec::self_signed("prop.example.com");

        let ca = fx.x509_self_signed(&label_a, spec.clone());
        let cb = fx.x509_self_signed(&label_b, spec);

        prop_assert_ne!(
            ca.cert_der(),
            cb.cert_der(),
            "Different labels should produce different certs"
        );
    }

    /// Random labels always produce valid chain PEM.
    #[test]
    fn random_label_chain_format(
        seed in any::<[u8; 32]>(),
        label in "[a-zA-Z][a-zA-Z0-9_]{0,15}",
    ) {
        let fx = Factory::deterministic(Seed::new(seed));
        let spec = ChainSpec::new("prop-chain.example.com");
        let chain = fx.x509_chain(&label, spec);

        prop_assert!(chain.root_cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
        prop_assert!(chain.leaf_cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
        prop_assert!(chain.leaf_private_key_pkcs8_pem().starts_with("-----BEGIN PRIVATE KEY-----"));
        prop_assert!(!chain.root_cert_der().is_empty());
        prop_assert!(!chain.leaf_cert_der().is_empty());

        let cert_count = chain.chain_pem().matches("-----BEGIN CERTIFICATE-----").count();
        prop_assert_eq!(cert_count, 2);
    }

    /// Different labels produce different certificate chains.
    #[test]
    fn chain_label_independence(
        seed in any::<[u8; 32]>(),
        label_a in "[a-zA-Z][a-zA-Z0-9]{1,8}",
        label_b in "[a-zA-Z][a-zA-Z0-9]{1,8}",
    ) {
        prop_assume!(label_a != label_b);
        let fx = Factory::deterministic(Seed::new(seed));
        let spec = ChainSpec::new("prop-chain.example.com");

        let ca = fx.x509_chain(&label_a, spec.clone());
        let cb = fx.x509_chain(&label_b, spec);

        prop_assert_ne!(
            ca.leaf_cert_der(),
            cb.leaf_cert_der(),
            "Different labels should produce different chains"
        );
    }
}
