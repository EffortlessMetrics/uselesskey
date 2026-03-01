use proptest::prelude::*;
use uselesskey_core::{Factory, Seed};
use uselesskey_tonic::{TonicClientTlsExt, TonicIdentityExt, TonicServerTlsExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

proptest! {
    // RSA keygen is expensive; keep case count low.
    #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

    // =========================================================================
    // Self-signed cert: determinism
    // =========================================================================

    /// Deterministic factories with the same seed produce identical tonic configs.
    #[test]
    fn deterministic_self_signed_is_consistent(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let spec = X509Spec::self_signed("prop.example.com");

        let cert1 = fx.x509_self_signed("prop-ss", spec.clone());
        fx.clear_cache();
        let cert2 = fx.x509_self_signed("prop-ss", spec);

        prop_assert_eq!(cert1.cert_pem(), cert2.cert_pem());
        prop_assert_eq!(
            cert1.private_key_pkcs8_pem(),
            cert2.private_key_pkcs8_pem(),
        );

        // Adapter conversions should not panic.
        let _ = cert1.identity_tonic();
        let _ = cert2.identity_tonic();
    }

    /// Different seeds produce different self-signed certificates.
    #[test]
    fn different_seeds_different_self_signed(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
    ) {
        prop_assume!(seed_a != seed_b);

        let fx_a = Factory::deterministic(Seed::new(seed_a));
        let fx_b = Factory::deterministic(Seed::new(seed_b));
        let spec = X509Spec::self_signed("prop.example.com");

        let cert_a = fx_a.x509_self_signed("prop-ss", spec.clone());
        let cert_b = fx_b.x509_self_signed("prop-ss", spec);

        prop_assert_ne!(
            cert_a.cert_der(),
            cert_b.cert_der(),
            "Different seeds should produce different self-signed certs"
        );
    }

    /// Self-signed cert PEM starts with the expected header, DER is non-empty.
    #[test]
    fn self_signed_output_format_invariants(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let spec = X509Spec::self_signed("prop.example.com");
        let cert = fx.x509_self_signed("prop-fmt", spec);

        prop_assert!(
            cert.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"),
            "Cert PEM should start with BEGIN CERTIFICATE"
        );
        prop_assert!(
            cert.private_key_pkcs8_pem().starts_with("-----BEGIN PRIVATE KEY-----"),
            "Key PEM should start with BEGIN PRIVATE KEY"
        );
        prop_assert!(!cert.cert_der().is_empty(), "Cert DER should be non-empty");
        prop_assert!(
            !cert.private_key_pkcs8_der().is_empty(),
            "Key DER should be non-empty"
        );

        // Tonic adapter methods should succeed.
        let _ = cert.identity_tonic();
        let _ = cert.server_tls_config_tonic();
        let _ = cert.client_tls_config_tonic("prop.example.com");
    }

    // =========================================================================
    // Certificate chain: determinism
    // =========================================================================

    /// Deterministic chains with the same seed produce identical PEM output.
    #[test]
    fn deterministic_chain_is_consistent(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let spec = ChainSpec::new("prop-chain.example.com");

        let chain1 = fx.x509_chain("prop-chain", spec.clone());
        fx.clear_cache();
        let chain2 = fx.x509_chain("prop-chain", spec);

        prop_assert_eq!(chain1.chain_pem(), chain2.chain_pem());
        prop_assert_eq!(chain1.root_cert_pem(), chain2.root_cert_pem());
        prop_assert_eq!(
            chain1.leaf_private_key_pkcs8_pem(),
            chain2.leaf_private_key_pkcs8_pem(),
        );

        // Tonic adapter methods should succeed.
        let _ = chain1.identity_tonic();
        let _ = chain2.identity_tonic();
    }

    /// Different seeds produce different certificate chains.
    #[test]
    fn different_seeds_different_chains(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
    ) {
        prop_assume!(seed_a != seed_b);

        let fx_a = Factory::deterministic(Seed::new(seed_a));
        let fx_b = Factory::deterministic(Seed::new(seed_b));
        let spec = ChainSpec::new("prop-chain.example.com");

        let chain_a = fx_a.x509_chain("prop-chain", spec.clone());
        let chain_b = fx_b.x509_chain("prop-chain", spec);

        prop_assert_ne!(
            chain_a.leaf_cert_der(),
            chain_b.leaf_cert_der(),
            "Different seeds should produce different chains"
        );
    }

    /// Chain PEM outputs have expected format invariants.
    #[test]
    fn chain_output_format_invariants(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let spec = ChainSpec::new("prop-chain.example.com");
        let chain = fx.x509_chain("prop-fmt", spec);

        prop_assert!(
            chain.root_cert_pem().starts_with("-----BEGIN CERTIFICATE-----"),
            "Root cert PEM should start with BEGIN CERTIFICATE"
        );
        prop_assert!(
            chain.leaf_cert_pem().starts_with("-----BEGIN CERTIFICATE-----"),
            "Leaf cert PEM should start with BEGIN CERTIFICATE"
        );
        prop_assert!(
            chain.leaf_private_key_pkcs8_pem().starts_with("-----BEGIN PRIVATE KEY-----"),
            "Leaf key PEM should start with BEGIN PRIVATE KEY"
        );
        prop_assert!(
            !chain.root_cert_der().is_empty(),
            "Root DER should be non-empty"
        );
        prop_assert!(
            !chain.leaf_cert_der().is_empty(),
            "Leaf DER should be non-empty"
        );

        // chain_pem should contain exactly 2 certificates (leaf + intermediate).
        let cert_count = chain.chain_pem().matches("-----BEGIN CERTIFICATE-----").count();
        prop_assert_eq!(cert_count, 2, "chain_pem should contain 2 certificates");

        // Tonic adapter methods should succeed.
        let _ = chain.identity_tonic();
        let _ = chain.server_tls_config_tonic();
        let _ = chain.client_tls_config_tonic("prop-chain.example.com");
    }
}
