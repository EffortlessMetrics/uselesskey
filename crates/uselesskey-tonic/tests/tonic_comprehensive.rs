//! Comprehensive integration tests for the tonic adapter crate.
//!
//! These tests verify that uselesskey X.509 fixtures integrate correctly with
//! `tonic::transport` TLS types (Identity, Certificate, ServerTlsConfig,
//! ClientTlsConfig) for both one-way TLS and mutual TLS scenarios.

#![cfg(feature = "x509")]

mod testutil;

use uselesskey_core::{Factory, Seed};
use uselesskey_tonic::{TonicClientTlsExt, TonicIdentityExt, TonicMtlsExt, TonicServerTlsExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

use testutil::fx;

// ---------------------------------------------------------------------------
// Self-signed certificate tests
// ---------------------------------------------------------------------------

mod self_signed {
    use super::*;

    #[test]
    fn identity_from_self_signed_cert() {
        let fx = fx();
        let cert = fx.x509_self_signed("tonic-ss-id", X509Spec::self_signed("localhost"));
        // Identity construction should not panic
        let _identity = cert.identity_tonic();
    }

    #[test]
    fn server_tls_config_from_self_signed() {
        let fx = fx();
        let cert = fx.x509_self_signed("tonic-ss-server", X509Spec::self_signed("localhost"));
        let _server = cert.server_tls_config_tonic();
    }

    #[test]
    fn client_tls_config_from_self_signed() {
        let fx = fx();
        let cert = fx.x509_self_signed("tonic-ss-client", X509Spec::self_signed("localhost"));
        let _client = cert.client_tls_config_tonic("localhost");
    }

    #[test]
    fn client_tls_config_with_different_domain() {
        let fx = fx();
        let cert = fx.x509_self_signed("tonic-ss-domain", X509Spec::self_signed("example.com"));
        // Different domain name should still produce a valid config object
        let _client = cert.client_tls_config_tonic("example.com");
    }

    #[test]
    fn self_signed_pem_material_is_valid() {
        let fx = fx();
        let cert = fx.x509_self_signed("tonic-ss-pem", X509Spec::self_signed("localhost"));

        let pem = cert.cert_pem();
        let key = cert.private_key_pkcs8_pem();

        assert!(
            pem.starts_with("-----BEGIN CERTIFICATE-----"),
            "cert PEM should have correct header"
        );
        assert!(
            key.starts_with("-----BEGIN PRIVATE KEY-----"),
            "private key PEM should have correct header"
        );
    }
}

// ---------------------------------------------------------------------------
// Chain certificate tests
// ---------------------------------------------------------------------------

mod chain {
    use super::*;

    #[test]
    fn identity_from_chain() {
        let fx = fx();
        let chain = fx.x509_chain("tonic-chain-id", ChainSpec::new("test.example.com"));
        let _identity = chain.identity_tonic();
    }

    #[test]
    fn server_tls_config_from_chain() {
        let fx = fx();
        let chain = fx.x509_chain("tonic-chain-server", ChainSpec::new("test.example.com"));
        let _server = chain.server_tls_config_tonic();
    }

    #[test]
    fn client_tls_config_from_chain() {
        let fx = fx();
        let chain = fx.x509_chain("tonic-chain-client", ChainSpec::new("test.example.com"));
        let _client = chain.client_tls_config_tonic("test.example.com");
    }

    #[test]
    fn chain_pem_contains_leaf_and_intermediate() {
        let fx = fx();
        let chain = fx.x509_chain("tonic-chain-pem", ChainSpec::new("test.example.com"));

        let chain_pem = chain.chain_pem();
        let root_pem = chain.root_cert_pem();
        let leaf_key = chain.leaf_private_key_pkcs8_pem();

        // chain_pem contains leaf + intermediate (standard TLS order)
        let cert_count = chain_pem.matches("-----BEGIN CERTIFICATE-----").count();
        assert_eq!(
            cert_count, 2,
            "chain PEM should contain leaf + intermediate (2 certs)"
        );

        assert!(
            root_pem.starts_with("-----BEGIN CERTIFICATE-----"),
            "root cert should be valid PEM"
        );
        assert!(
            leaf_key.starts_with("-----BEGIN PRIVATE KEY-----"),
            "leaf private key should be valid PEM"
        );
    }

    #[test]
    fn full_chain_pem_contains_all_three_certs() {
        let fx = fx();
        let chain = fx.x509_chain("tonic-chain-full", ChainSpec::new("test.example.com"));

        let full = chain.full_chain_pem();
        let cert_count = full.matches("-----BEGIN CERTIFICATE-----").count();
        assert_eq!(
            cert_count, 3,
            "full chain PEM should contain leaf + intermediate + root (3 certs)"
        );
    }

    #[test]
    fn chain_with_custom_spec() {
        let fx = fx();
        let spec = ChainSpec::new("custom.example.com")
            .with_root_cn("Test Root CA")
            .with_intermediate_cn("Test Intermediate CA");
        let chain = fx.x509_chain("tonic-chain-custom", spec);

        let _server = chain.server_tls_config_tonic();
        let _client = chain.client_tls_config_tonic("custom.example.com");
    }
}

// ---------------------------------------------------------------------------
// Mutual TLS tests
// ---------------------------------------------------------------------------

mod mtls {
    use super::*;

    #[test]
    fn mtls_server_config_from_chain() {
        let fx = fx();
        let chain = fx.x509_chain("tonic-mtls-server", ChainSpec::new("test.example.com"));
        let _server = chain.server_tls_config_mtls_tonic();
    }

    #[test]
    fn mtls_client_config_from_chain() {
        let fx = fx();
        let chain = fx.x509_chain("tonic-mtls-client", ChainSpec::new("test.example.com"));
        let _client = chain.client_tls_config_mtls_tonic("test.example.com");
    }

    #[test]
    fn mtls_both_configs_from_same_chain() {
        let fx = fx();
        let chain = fx.x509_chain("tonic-mtls-both", ChainSpec::new("test.example.com"));

        let _server = chain.server_tls_config_mtls_tonic();
        let _client = chain.client_tls_config_mtls_tonic("test.example.com");
    }

    #[test]
    fn mtls_configs_from_separate_chains() {
        let fx = fx();
        let server_chain = fx.x509_chain(
            "tonic-mtls-server-sep",
            ChainSpec::new("server.example.com"),
        );
        let client_chain = fx.x509_chain(
            "tonic-mtls-client-sep",
            ChainSpec::new("client.example.com"),
        );

        let _server = server_chain.server_tls_config_mtls_tonic();
        let _client = client_chain.client_tls_config_mtls_tonic("client.example.com");
    }
}

// ---------------------------------------------------------------------------
// Deterministic derivation tests
// ---------------------------------------------------------------------------

mod deterministic {
    use super::*;

    #[test]
    fn self_signed_deterministic_identity_is_stable() {
        let seed = Seed::from_env_value("tonic-det-ss-stable").expect("seed");
        let fx = Factory::deterministic(seed);

        let cert_a = fx.x509_self_signed("tonic-det-ss", X509Spec::self_signed("det.example.com"));
        let pem_a = cert_a.cert_pem().to_owned();
        let key_a = cert_a.private_key_pkcs8_pem().to_owned();

        fx.clear_cache();
        let cert_b = fx.x509_self_signed("tonic-det-ss", X509Spec::self_signed("det.example.com"));

        assert_eq!(pem_a, cert_b.cert_pem(), "cert PEM should be stable");
        assert_eq!(
            key_a,
            cert_b.private_key_pkcs8_pem(),
            "key PEM should be stable"
        );
    }

    #[test]
    fn chain_deterministic_material_is_stable() {
        let seed = Seed::from_env_value("tonic-det-chain-stable").expect("seed");
        let fx = Factory::deterministic(seed);

        let chain_a = fx.x509_chain("tonic-det-chain", ChainSpec::new("det.example.com"));
        let pem_a = chain_a.chain_pem();
        let root_a = chain_a.root_cert_pem().to_owned();
        let key_a = chain_a.leaf_private_key_pkcs8_pem().to_owned();

        fx.clear_cache();
        let chain_b = fx.x509_chain("tonic-det-chain", ChainSpec::new("det.example.com"));

        assert_eq!(pem_a, chain_b.chain_pem(), "chain PEM should be stable");
        assert_eq!(
            root_a,
            chain_b.root_cert_pem(),
            "root cert PEM should be stable"
        );
        assert_eq!(
            key_a,
            chain_b.leaf_private_key_pkcs8_pem(),
            "leaf key PEM should be stable"
        );
    }

    #[test]
    fn different_labels_produce_different_material() {
        let fx = fx();
        let chain_a = fx.x509_chain("tonic-label-a", ChainSpec::new("a.example.com"));
        let chain_b = fx.x509_chain("tonic-label-b", ChainSpec::new("b.example.com"));

        assert_ne!(
            chain_a.root_cert_pem(),
            chain_b.root_cert_pem(),
            "different labels should produce different root certs"
        );
        assert_ne!(
            chain_a.leaf_private_key_pkcs8_pem(),
            chain_b.leaf_private_key_pkcs8_pem(),
            "different labels should produce different leaf keys"
        );
    }
}

// ---------------------------------------------------------------------------
// Negative / edge-case tests
// ---------------------------------------------------------------------------

mod negative {
    use super::*;

    #[test]
    fn expired_chain_still_produces_tls_config() {
        let fx = fx();
        let chain = fx.x509_chain("tonic-neg-expired", ChainSpec::new("test.example.com"));
        let expired = chain.expired_leaf();

        // Config construction succeeds even with expired cert material;
        // actual TLS handshake would reject it later.
        let _server = expired.server_tls_config_tonic();
        let _client = expired.client_tls_config_tonic("test.example.com");
    }

    #[test]
    fn revoked_chain_still_produces_tls_config() {
        let fx = fx();
        let chain = fx.x509_chain("tonic-neg-revoked", ChainSpec::new("test.example.com"));
        let revoked = chain.revoked_leaf();

        let _server = revoked.server_tls_config_tonic();
        let _client = revoked.client_tls_config_tonic("test.example.com");

        // Revoked chain should have CRL data available
        assert!(
            revoked.crl_pem().is_some(),
            "revoked chain should have CRL PEM"
        );
    }

    #[test]
    fn random_factory_produces_valid_configs() {
        let fx = Factory::random();
        let chain = fx.x509_chain("tonic-random", ChainSpec::new("random.example.com"));

        let _server = chain.server_tls_config_tonic();
        let _client = chain.client_tls_config_tonic("random.example.com");
        let _mtls_server = chain.server_tls_config_mtls_tonic();
        let _mtls_client = chain.client_tls_config_mtls_tonic("random.example.com");
    }

    #[test]
    fn empty_domain_string_accepted() {
        let fx = fx();
        let cert = fx.x509_self_signed("tonic-empty-domain", X509Spec::self_signed("localhost"));
        // tonic accepts empty domain; the config is still constructed
        let _client = cert.client_tls_config_tonic("");
    }

    #[test]
    fn unicode_domain_accepted() {
        let fx = fx();
        let cert = fx.x509_self_signed("tonic-unicode", X509Spec::self_signed("例え.jp"));
        let _client = cert.client_tls_config_tonic("例え.jp");
    }
}

// ---------------------------------------------------------------------------
// Cross-fixture isolation tests
// ---------------------------------------------------------------------------

mod isolation {
    use super::*;

    #[test]
    fn separate_chains_have_independent_roots() {
        let fx = fx();
        let chain_x = fx.x509_chain("tonic-iso-x", ChainSpec::new("x.example.com"));
        let chain_y = fx.x509_chain("tonic-iso-y", ChainSpec::new("y.example.com"));

        assert_ne!(
            chain_x.root_cert_pem(),
            chain_y.root_cert_pem(),
            "independent chains must have different root CAs"
        );
    }

    #[test]
    fn chain_root_and_leaf_differ() {
        let fx = fx();
        let chain = fx.x509_chain("tonic-iso-parts", ChainSpec::new("test.example.com"));

        assert_ne!(
            chain.root_cert_pem(),
            chain.leaf_cert_pem(),
            "root and leaf certs must differ"
        );
        assert_ne!(
            chain.root_private_key_pkcs8_pem(),
            chain.leaf_private_key_pkcs8_pem(),
            "root and leaf keys must differ"
        );
    }

    #[test]
    fn self_signed_and_chain_are_independent() {
        let fx = fx();
        let cert = fx.x509_self_signed("tonic-iso-ss", X509Spec::self_signed("test.example.com"));
        let chain = fx.x509_chain("tonic-iso-chain", ChainSpec::new("test.example.com"));

        assert_ne!(
            cert.cert_pem(),
            chain.leaf_cert_pem(),
            "self-signed and chain leaf should be independent"
        );
    }
}
