//! Extended tests for uselesskey-tonic adapter.
//!
//! Covers:
//! - TLS config construction (server and client)
//! - Certificate chain building and PEM structure
//! - mTLS setup with separate server/client chains
//! - Edge cases: multiple SANs, custom validity, domain name variants

#[cfg(feature = "x509")]
mod tls_config {
    use uselesskey_core::{Factory, Seed};
    use uselesskey_tonic::{TonicClientTlsExt, TonicIdentityExt, TonicServerTlsExt};
    use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

    fn fx() -> Factory {
        let seed = Seed::from_env_value("uselesskey-tonic-extended-test-seed-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    }

    #[test]
    fn server_tls_from_self_signed_builds() {
        let fx = fx();
        let cert = fx.x509_self_signed("ext-srv-ss", X509Spec::self_signed("localhost"));
        let _server = cert.server_tls_config_tonic();
    }

    #[test]
    fn server_tls_from_chain_builds() {
        let fx = fx();
        let chain = fx.x509_chain("ext-srv-chain", ChainSpec::new("srv.example.com"));
        let _server = chain.server_tls_config_tonic();
    }

    #[test]
    fn client_tls_from_self_signed_builds() {
        let fx = fx();
        let cert = fx.x509_self_signed("ext-cli-ss", X509Spec::self_signed("localhost"));
        let _client = cert.client_tls_config_tonic("localhost");
    }

    #[test]
    fn client_tls_from_chain_builds() {
        let fx = fx();
        let chain = fx.x509_chain("ext-cli-chain", ChainSpec::new("cli.example.com"));
        let _client = chain.client_tls_config_tonic("cli.example.com");
    }

    #[test]
    fn client_tls_accepts_string_domain() {
        let fx = fx();
        let chain = fx.x509_chain("ext-cli-str", ChainSpec::new("grpc.example.com"));
        let domain = String::from("grpc.example.com");
        let _client = chain.client_tls_config_tonic(domain);
    }

    #[test]
    fn server_and_client_from_same_chain() {
        let fx = fx();
        let chain = fx.x509_chain("ext-both", ChainSpec::new("both.example.com"));
        let _server = chain.server_tls_config_tonic();
        let _client = chain.client_tls_config_tonic("both.example.com");
    }

    #[test]
    fn random_factory_builds_tls_configs() {
        let fx = Factory::random();
        let chain = fx.x509_chain("ext-random", ChainSpec::new("random.example.com"));
        let _server = chain.server_tls_config_tonic();
        let _client = chain.client_tls_config_tonic("random.example.com");
        let _identity = chain.identity_tonic();
    }
}

// =========================================================================
// Certificate chain building
// =========================================================================

#[cfg(feature = "x509")]
mod chain_building {
    use uselesskey_core::{Factory, Seed};
    use uselesskey_tonic::TonicIdentityExt;
    use uselesskey_x509::{ChainSpec, X509FactoryExt};

    fn fx() -> Factory {
        let seed = Seed::from_env_value("uselesskey-tonic-extended-chain-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    }

    #[test]
    fn chain_pem_has_two_certs() {
        let fx = fx();
        let chain = fx.x509_chain("ext-chain-cnt", ChainSpec::new("chain.example.com"));
        let count = chain
            .chain_pem()
            .matches("-----BEGIN CERTIFICATE-----")
            .count();
        assert_eq!(count, 2, "chain_pem should contain leaf + intermediate");
    }

    #[test]
    fn full_chain_pem_has_three_certs() {
        let fx = fx();
        let chain = fx.x509_chain("ext-full-chain", ChainSpec::new("chain.example.com"));
        let count = chain
            .full_chain_pem()
            .matches("-----BEGIN CERTIFICATE-----")
            .count();
        assert_eq!(
            count, 3,
            "full_chain_pem should contain leaf + intermediate + root"
        );
    }

    #[test]
    fn root_cert_pem_is_single() {
        let fx = fx();
        let chain = fx.x509_chain("ext-root-single", ChainSpec::new("chain.example.com"));
        let count = chain
            .root_cert_pem()
            .matches("-----BEGIN CERTIFICATE-----")
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn leaf_cert_pem_is_single() {
        let fx = fx();
        let chain = fx.x509_chain("ext-leaf-single", ChainSpec::new("chain.example.com"));
        let count = chain
            .leaf_cert_pem()
            .matches("-----BEGIN CERTIFICATE-----")
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn leaf_key_pem_has_correct_header() {
        let fx = fx();
        let chain = fx.x509_chain("ext-key-hdr", ChainSpec::new("chain.example.com"));
        assert!(
            chain
                .leaf_private_key_pkcs8_pem()
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
    }

    #[test]
    fn der_outputs_are_nonempty() {
        let fx = fx();
        let chain = fx.x509_chain("ext-der-ne", ChainSpec::new("chain.example.com"));
        assert!(!chain.root_cert_der().is_empty());
        assert!(!chain.intermediate_cert_der().is_empty());
        assert!(!chain.leaf_cert_der().is_empty());
        assert!(!chain.leaf_private_key_pkcs8_der().is_empty());
    }

    #[test]
    fn identity_from_chain_succeeds() {
        let fx = fx();
        let chain = fx.x509_chain("ext-id-chain", ChainSpec::new("chain.example.com"));
        let _identity = chain.identity_tonic();
    }

    #[test]
    fn chain_with_custom_cn_names() {
        let fx = fx();
        let chain = fx.x509_chain(
            "ext-custom-cn",
            ChainSpec::new("leaf.example.com")
                .with_root_cn("Custom Root CA")
                .with_intermediate_cn("Custom Intermediate CA"),
        );
        let _identity = chain.identity_tonic();
    }

    #[test]
    fn chain_with_multiple_sans() {
        let fx = fx();
        let chain = fx.x509_chain(
            "ext-multi-sans",
            ChainSpec::new("primary.example.com").with_sans(vec![
                "alt1.example.com".into(),
                "alt2.example.com".into(),
                "alt3.example.com".into(),
            ]),
        );
        let _identity = chain.identity_tonic();
    }

    #[test]
    fn chain_with_custom_validity_days() {
        let fx = fx();
        let chain = fx.x509_chain(
            "ext-validity",
            ChainSpec::new("validity.example.com")
                .with_root_validity_days(7300)
                .with_intermediate_validity_days(3650)
                .with_leaf_validity_days(365),
        );
        let _identity = chain.identity_tonic();
    }

    #[test]
    fn different_labels_produce_different_chains() {
        let fx = fx();
        let chain_a = fx.x509_chain("ext-diff-a", ChainSpec::new("a.example.com"));
        let chain_b = fx.x509_chain("ext-diff-b", ChainSpec::new("b.example.com"));
        assert_ne!(chain_a.leaf_cert_der(), chain_b.leaf_cert_der());
    }

    #[test]
    fn different_rsa_sizes_produce_different_chains() {
        let fx = fx();
        let chain_2k = fx.x509_chain(
            "ext-rsa-2k",
            ChainSpec::new("rsa.example.com").with_rsa_bits(2048),
        );
        let chain_4k = fx.x509_chain(
            "ext-rsa-4k",
            ChainSpec::new("rsa.example.com").with_rsa_bits(4096),
        );
        assert_ne!(chain_2k.leaf_cert_der(), chain_4k.leaf_cert_der());
    }
}

// =========================================================================
// mTLS setup tests
// =========================================================================

#[cfg(feature = "x509")]
mod mtls_setup {
    use uselesskey_core::{Factory, Seed};
    use uselesskey_tonic::{TonicClientTlsExt, TonicMtlsExt, TonicServerTlsExt};
    use uselesskey_x509::{ChainSpec, X509FactoryExt};

    fn fx() -> Factory {
        let seed = Seed::from_env_value("uselesskey-tonic-extended-mtls-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    }

    #[test]
    fn mtls_server_from_chain() {
        let fx = fx();
        let chain = fx.x509_chain("ext-mtls-srv", ChainSpec::new("mtls.example.com"));
        let _server = chain.server_tls_config_mtls_tonic();
    }

    #[test]
    fn mtls_client_from_chain() {
        let fx = fx();
        let chain = fx.x509_chain("ext-mtls-cli", ChainSpec::new("mtls.example.com"));
        let _client = chain.client_tls_config_mtls_tonic("mtls.example.com");
    }

    #[test]
    fn mtls_server_and_client_from_same_chain() {
        let fx = fx();
        let chain = fx.x509_chain("ext-mtls-both", ChainSpec::new("mtls.example.com"));
        let _server = chain.server_tls_config_mtls_tonic();
        let _client = chain.client_tls_config_mtls_tonic("mtls.example.com");
    }

    #[test]
    fn mtls_separate_server_and_client_chains() {
        let fx = fx();
        let server_chain = fx.x509_chain("ext-mtls-srv-sep", ChainSpec::new("server.example.com"));
        let client_chain = fx.x509_chain("ext-mtls-cli-sep", ChainSpec::new("client.example.com"));

        let _server = server_chain.server_tls_config_mtls_tonic();
        let _client = client_chain.client_tls_config_mtls_tonic("server.example.com");
    }

    #[test]
    fn mtls_with_4096_bit_keys() {
        let fx = fx();
        let chain = fx.x509_chain(
            "ext-mtls-4096",
            ChainSpec::new("mtls-4096.example.com").with_rsa_bits(4096),
        );
        let _server = chain.server_tls_config_mtls_tonic();
        let _client = chain.client_tls_config_mtls_tonic("mtls-4096.example.com");
    }

    #[test]
    fn mtls_random_factory() {
        let fx = Factory::random();
        let chain = fx.x509_chain("ext-mtls-rand", ChainSpec::new("random.example.com"));
        let _server = chain.server_tls_config_mtls_tonic();
        let _client = chain.client_tls_config_mtls_tonic("random.example.com");
    }

    #[test]
    fn mtls_with_sans() {
        let fx = fx();
        let chain = fx.x509_chain(
            "ext-mtls-sans",
            ChainSpec::new("mtls.example.com")
                .with_sans(vec!["alt.example.com".into(), "other.example.com".into()]),
        );
        let _server = chain.server_tls_config_mtls_tonic();
        let _client = chain.client_tls_config_mtls_tonic("mtls.example.com");
    }

    #[test]
    fn mtls_deterministic_produces_consistent_configs() {
        let seed = Seed::from_env_value("ext-mtls-det").expect("seed");
        let fx = Factory::deterministic(seed);

        let chain_a = fx.x509_chain("ext-mtls-det", ChainSpec::new("det.example.com"));
        fx.clear_cache();
        let chain_b = fx.x509_chain("ext-mtls-det", ChainSpec::new("det.example.com"));

        assert_eq!(chain_a.chain_pem(), chain_b.chain_pem());
        assert_eq!(chain_a.root_cert_pem(), chain_b.root_cert_pem());
        assert_eq!(
            chain_a.leaf_private_key_pkcs8_pem(),
            chain_b.leaf_private_key_pkcs8_pem()
        );

        // Both should build mTLS configs without panicking
        let _srv_a = chain_a.server_tls_config_mtls_tonic();
        let _srv_b = chain_b.server_tls_config_mtls_tonic();
        let _cli_a = chain_a.client_tls_config_mtls_tonic("det.example.com");
        let _cli_b = chain_b.client_tls_config_mtls_tonic("det.example.com");
    }

    #[test]
    fn multiple_mtls_pairs_from_same_factory() {
        let fx = fx();
        for i in 0..3 {
            let chain = fx.x509_chain(
                format!("ext-mtls-multi-{i}"),
                ChainSpec::new(format!("svc{i}.example.com")),
            );
            let _server = chain.server_tls_config_mtls_tonic();
            let _client = chain.client_tls_config_mtls_tonic(format!("svc{i}.example.com"));
        }
    }

    /// Verify that standard (non-mTLS) server TLS and mTLS server TLS both build from the same chain.
    #[test]
    fn standard_and_mtls_server_from_same_chain() {
        let fx = fx();
        let chain = fx.x509_chain("ext-std-mtls", ChainSpec::new("both.example.com"));
        let _standard = chain.server_tls_config_tonic();
        let _mtls = chain.server_tls_config_mtls_tonic();
    }

    /// Verify that standard (non-mTLS) client TLS and mTLS client TLS both build from the same chain.
    #[test]
    fn standard_and_mtls_client_from_same_chain() {
        let fx = fx();
        let chain = fx.x509_chain("ext-std-mtls-cli", ChainSpec::new("both.example.com"));
        let _standard = chain.client_tls_config_tonic("both.example.com");
        let _mtls = chain.client_tls_config_mtls_tonic("both.example.com");
    }
}
