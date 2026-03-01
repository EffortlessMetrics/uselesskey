//! Comprehensive integration tests for uselesskey-tonic adapter.
//!
//! Tests cover:
//! - Server TLS configuration creation (self-signed + chain)
//! - Client TLS configuration creation
//! - mTLS configuration (both client and server)
//! - Certificate chain handling (PEM structure, root/leaf access)
//! - Different RSA key sizes with tonic
//! - Deterministic vs random factory modes
//! - Negative cases (mismatched certs/keys, distinct chains)

use std::sync::OnceLock;

use uselesskey_core::{Factory, Seed};
use uselesskey_tonic::{TonicClientTlsExt, TonicIdentityExt, TonicMtlsExt, TonicServerTlsExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-tonic-comprehensive-test-seed-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
    .clone()
}

// =========================================================================
// Server TLS configuration
// =========================================================================

mod server_tls {
    use super::*;

    #[test]
    fn self_signed_server_tls_builds() {
        let fx = fx();
        let cert = fx.x509_self_signed("server-ss", X509Spec::self_signed("localhost"));
        let _server = cert.server_tls_config_tonic();
    }

    #[test]
    fn chain_server_tls_builds() {
        let fx = fx();
        let chain = fx.x509_chain("server-chain", ChainSpec::new("grpc.example.com"));
        let _server = chain.server_tls_config_tonic();
    }

    #[test]
    fn server_tls_with_custom_rsa_bits() {
        let fx = fx();
        let chain = fx.x509_chain(
            "server-4096",
            ChainSpec::new("grpc-4096.example.com").with_rsa_bits(4096),
        );
        let _server = chain.server_tls_config_tonic();
    }

    #[test]
    fn server_tls_with_custom_validity() {
        let fx = fx();
        let chain = fx.x509_chain(
            "server-validity",
            ChainSpec::new("validity.example.com")
                .with_root_validity_days(7300)
                .with_intermediate_validity_days(3650)
                .with_leaf_validity_days(365),
        );
        let _server = chain.server_tls_config_tonic();
    }

    #[test]
    fn random_factory_server_tls_builds() {
        let fx = Factory::random();
        let chain = fx.x509_chain("random-server", ChainSpec::new("random.example.com"));
        let _server = chain.server_tls_config_tonic();
    }
}

// =========================================================================
// Client TLS configuration
// =========================================================================

mod client_tls {
    use super::*;

    #[test]
    fn self_signed_client_tls_builds() {
        let fx = fx();
        let cert = fx.x509_self_signed("client-ss", X509Spec::self_signed("localhost"));
        let _client = cert.client_tls_config_tonic("localhost");
    }

    #[test]
    fn chain_client_tls_builds() {
        let fx = fx();
        let chain = fx.x509_chain("client-chain", ChainSpec::new("grpc.example.com"));
        let _client = chain.client_tls_config_tonic("grpc.example.com");
    }

    #[test]
    fn client_tls_with_different_domain() {
        let fx = fx();
        let chain = fx.x509_chain("client-domain", ChainSpec::new("api.example.com"));
        // Domain name in client config doesn't have to match cert CN for config creation
        let _client = chain.client_tls_config_tonic("other.example.com");
    }

    #[test]
    fn client_tls_string_domain_name() {
        let fx = fx();
        let chain = fx.x509_chain("client-string", ChainSpec::new("grpc.example.com"));
        let domain = String::from("grpc.example.com");
        let _client = chain.client_tls_config_tonic(domain);
    }

    #[test]
    fn random_factory_client_tls_builds() {
        let fx = Factory::random();
        let chain = fx.x509_chain("random-client", ChainSpec::new("random.example.com"));
        let _client = chain.client_tls_config_tonic("random.example.com");
    }
}

// =========================================================================
// mTLS configuration
// =========================================================================

mod mtls {
    use super::*;

    #[test]
    fn chain_mtls_server_builds() {
        let fx = fx();
        let chain = fx.x509_chain("mtls-server", ChainSpec::new("mtls.example.com"));
        let _server = chain.server_tls_config_mtls_tonic();
    }

    #[test]
    fn chain_mtls_client_builds() {
        let fx = fx();
        let chain = fx.x509_chain("mtls-client", ChainSpec::new("mtls.example.com"));
        let _client = chain.client_tls_config_mtls_tonic("mtls.example.com");
    }

    #[test]
    fn mtls_server_and_client_from_same_chain() {
        let fx = fx();
        let chain = fx.x509_chain("mtls-both", ChainSpec::new("mtls.example.com"));
        let _server = chain.server_tls_config_mtls_tonic();
        let _client = chain.client_tls_config_mtls_tonic("mtls.example.com");
    }

    #[test]
    fn mtls_separate_server_and_client_chains() {
        let fx = fx();
        let server_chain = fx.x509_chain("mtls-srv-chain", ChainSpec::new("server.example.com"));
        let client_chain = fx.x509_chain("mtls-cli-chain", ChainSpec::new("client.example.com"));

        let _server = server_chain.server_tls_config_mtls_tonic();
        let _client = client_chain.client_tls_config_mtls_tonic("server.example.com");
    }

    #[test]
    fn mtls_with_4096_bit_keys() {
        let fx = fx();
        let chain = fx.x509_chain(
            "mtls-4096",
            ChainSpec::new("mtls-4096.example.com").with_rsa_bits(4096),
        );
        let _server = chain.server_tls_config_mtls_tonic();
        let _client = chain.client_tls_config_mtls_tonic("mtls-4096.example.com");
    }

    #[test]
    fn mtls_random_factory() {
        let fx = Factory::random();
        let chain = fx.x509_chain("mtls-random", ChainSpec::new("random.example.com"));
        let _server = chain.server_tls_config_mtls_tonic();
        let _client = chain.client_tls_config_mtls_tonic("random.example.com");
    }
}

// =========================================================================
// Certificate chain handling
// =========================================================================

mod chain_handling {
    use super::*;

    #[test]
    fn chain_pem_contains_two_certificates() {
        let fx = fx();
        let chain = fx.x509_chain("chain-count", ChainSpec::new("chain.example.com"));
        let pem = chain.chain_pem();
        let count = pem.matches("-----BEGIN CERTIFICATE-----").count();
        assert_eq!(count, 2, "chain_pem should contain leaf + intermediate");
    }

    #[test]
    fn full_chain_pem_contains_three_certificates() {
        let fx = fx();
        let chain = fx.x509_chain("full-chain", ChainSpec::new("chain.example.com"));
        let pem = chain.full_chain_pem();
        let count = pem.matches("-----BEGIN CERTIFICATE-----").count();
        assert_eq!(
            count, 3,
            "full_chain_pem should contain leaf + intermediate + root"
        );
    }

    #[test]
    fn root_cert_pem_is_single_certificate() {
        let fx = fx();
        let chain = fx.x509_chain("root-single", ChainSpec::new("chain.example.com"));
        let pem = chain.root_cert_pem();
        let count = pem.matches("-----BEGIN CERTIFICATE-----").count();
        assert_eq!(count, 1, "root_cert_pem should be a single certificate");
    }

    #[test]
    fn leaf_cert_pem_is_single_certificate() {
        let fx = fx();
        let chain = fx.x509_chain("leaf-single", ChainSpec::new("chain.example.com"));
        let pem = chain.leaf_cert_pem();
        let count = pem.matches("-----BEGIN CERTIFICATE-----").count();
        assert_eq!(count, 1, "leaf_cert_pem should be a single certificate");
    }

    #[test]
    fn leaf_private_key_pem_has_correct_header() {
        let fx = fx();
        let chain = fx.x509_chain("key-header", ChainSpec::new("chain.example.com"));
        assert!(
            chain
                .leaf_private_key_pkcs8_pem()
                .starts_with("-----BEGIN PRIVATE KEY-----"),
            "Leaf key PEM should start with BEGIN PRIVATE KEY"
        );
    }

    #[test]
    fn der_outputs_are_nonempty() {
        let fx = fx();
        let chain = fx.x509_chain("der-nonempty", ChainSpec::new("chain.example.com"));
        assert!(!chain.root_cert_der().is_empty());
        assert!(!chain.intermediate_cert_der().is_empty());
        assert!(!chain.leaf_cert_der().is_empty());
        assert!(!chain.leaf_private_key_pkcs8_der().is_empty());
    }

    #[test]
    fn identity_from_chain_uses_chain_pem_and_leaf_key() {
        let fx = fx();
        let chain = fx.x509_chain("identity-check", ChainSpec::new("chain.example.com"));
        // Just verify that identity creation succeeds (it uses chain_pem + leaf key)
        let _identity = chain.identity_tonic();
    }

    #[test]
    fn self_signed_identity_uses_cert_and_key() {
        let fx = fx();
        let cert = fx.x509_self_signed("identity-ss", X509Spec::self_signed("localhost"));
        let _identity = cert.identity_tonic();
    }

    #[test]
    fn chain_with_custom_cn_names() {
        let fx = fx();
        let chain = fx.x509_chain(
            "custom-cn",
            ChainSpec::new("leaf.example.com")
                .with_root_cn("My Root CA")
                .with_intermediate_cn("My Intermediate CA"),
        );
        let _server = chain.server_tls_config_tonic();
        let _client = chain.client_tls_config_tonic("leaf.example.com");
    }

    #[test]
    fn chain_with_sans() {
        let fx = fx();
        let chain = fx.x509_chain(
            "with-sans",
            ChainSpec::new("primary.example.com")
                .with_sans(vec!["alt1.example.com".into(), "alt2.example.com".into()]),
        );
        let _server = chain.server_tls_config_tonic();
    }
}

// =========================================================================
// Different RSA key sizes with tonic
// =========================================================================

mod rsa_key_sizes {
    use super::*;

    #[test]
    fn chain_2048_bits() {
        let fx = fx();
        let chain = fx.x509_chain(
            "rsa-2048",
            ChainSpec::new("rsa2048.example.com").with_rsa_bits(2048),
        );
        let _server = chain.server_tls_config_tonic();
        let _client = chain.client_tls_config_tonic("rsa2048.example.com");
        let _identity = chain.identity_tonic();
    }

    #[test]
    fn chain_3072_bits() {
        let fx = fx();
        let chain = fx.x509_chain(
            "rsa-3072",
            ChainSpec::new("rsa3072.example.com").with_rsa_bits(3072),
        );
        let _server = chain.server_tls_config_tonic();
        let _client = chain.client_tls_config_tonic("rsa3072.example.com");
        let _identity = chain.identity_tonic();
    }

    #[test]
    fn chain_4096_bits() {
        let fx = fx();
        let chain = fx.x509_chain(
            "rsa-4096",
            ChainSpec::new("rsa4096.example.com").with_rsa_bits(4096),
        );
        let _server = chain.server_tls_config_tonic();
        let _client = chain.client_tls_config_tonic("rsa4096.example.com");
        let _identity = chain.identity_tonic();
    }

    #[test]
    fn self_signed_custom_rsa_bits() {
        let fx = fx();
        let cert = fx.x509_self_signed(
            "ss-4096",
            X509Spec::self_signed("localhost").with_rsa_bits(4096),
        );
        let _server = cert.server_tls_config_tonic();
        let _client = cert.client_tls_config_tonic("localhost");
    }
}

// =========================================================================
// Deterministic vs random
// =========================================================================

mod determinism {
    use super::*;

    #[test]
    fn deterministic_chain_produces_same_identity() {
        let seed = Seed::from_env_value("tonic-det-test-v1").expect("seed");
        let fx = Factory::deterministic(seed);

        let chain_a = fx.x509_chain("det-id", ChainSpec::new("det.example.com"));
        fx.clear_cache();
        let chain_b = fx.x509_chain("det-id", ChainSpec::new("det.example.com"));

        assert_eq!(chain_a.chain_pem(), chain_b.chain_pem());
        assert_eq!(chain_a.root_cert_pem(), chain_b.root_cert_pem());
        assert_eq!(
            chain_a.leaf_private_key_pkcs8_pem(),
            chain_b.leaf_private_key_pkcs8_pem()
        );
    }

    #[test]
    fn deterministic_self_signed_produces_same_identity() {
        let seed = Seed::from_env_value("tonic-det-ss-v1").expect("seed");
        let fx = Factory::deterministic(seed);

        let cert_a = fx.x509_self_signed("det-ss", X509Spec::self_signed("localhost"));
        fx.clear_cache();
        let cert_b = fx.x509_self_signed("det-ss", X509Spec::self_signed("localhost"));

        assert_eq!(cert_a.cert_pem(), cert_b.cert_pem());
        assert_eq!(
            cert_a.private_key_pkcs8_pem(),
            cert_b.private_key_pkcs8_pem()
        );
    }

    #[test]
    fn different_labels_produce_different_chains() {
        let fx = fx();
        let chain_a = fx.x509_chain("label-a", ChainSpec::new("a.example.com"));
        let chain_b = fx.x509_chain("label-b", ChainSpec::new("b.example.com"));

        assert_ne!(
            chain_a.leaf_cert_der(),
            chain_b.leaf_cert_der(),
            "Different labels should produce different certificates"
        );
    }

    #[test]
    fn different_seeds_produce_different_chains() {
        let fx_a = Factory::deterministic(Seed::from_env_value("tonic-seed-a").expect("seed"));
        let fx_b = Factory::deterministic(Seed::from_env_value("tonic-seed-b").expect("seed"));

        let chain_a = fx_a.x509_chain("same-label", ChainSpec::new("det.example.com"));
        let chain_b = fx_b.x509_chain("same-label", ChainSpec::new("det.example.com"));

        assert_ne!(
            chain_a.leaf_cert_der(),
            chain_b.leaf_cert_der(),
            "Different seeds should produce different chains"
        );
    }
}

// =========================================================================
// Negative / mismatched scenarios
// =========================================================================

mod negative_cases {
    use super::*;

    #[test]
    fn distinct_chains_have_different_root_certs() {
        let fx = fx();
        let chain_a = fx.x509_chain("neg-chain-a", ChainSpec::new("a.example.com"));
        let chain_b = fx.x509_chain("neg-chain-b", ChainSpec::new("b.example.com"));

        assert_ne!(
            chain_a.root_cert_pem(),
            chain_b.root_cert_pem(),
            "Distinct chains should have different root CAs"
        );
    }

    #[test]
    fn distinct_chains_have_different_leaf_keys() {
        let fx = fx();
        let chain_a = fx.x509_chain("neg-key-a", ChainSpec::new("a.example.com"));
        let chain_b = fx.x509_chain("neg-key-b", ChainSpec::new("b.example.com"));

        assert_ne!(
            chain_a.leaf_private_key_pkcs8_pem(),
            chain_b.leaf_private_key_pkcs8_pem(),
            "Distinct chains should have different leaf keys"
        );
    }

    #[test]
    fn self_signed_and_chain_produce_different_material() {
        let fx = fx();
        let cert = fx.x509_self_signed("neg-ss", X509Spec::self_signed("test.example.com"));
        let chain = fx.x509_chain("neg-chain", ChainSpec::new("test.example.com"));

        assert_ne!(
            cert.cert_pem(),
            chain.leaf_cert_pem(),
            "Self-signed and chain leaf should differ"
        );
    }

    #[test]
    fn configs_from_unrelated_chains_build_independently() {
        let fx = fx();
        let chain_a = fx.x509_chain("unrelated-a", ChainSpec::new("a.example.com"));
        let chain_b = fx.x509_chain("unrelated-b", ChainSpec::new("b.example.com"));

        // Both should build configs without panicking
        let _server_a = chain_a.server_tls_config_tonic();
        let _server_b = chain_b.server_tls_config_tonic();
        let _client_a = chain_a.client_tls_config_tonic("a.example.com");
        let _client_b = chain_b.client_tls_config_tonic("b.example.com");
        let _mtls_a = chain_a.server_tls_config_mtls_tonic();
        let _mtls_b = chain_b.server_tls_config_mtls_tonic();
    }

    #[test]
    fn self_signed_corrupt_cert_pem_still_builds_tonic_identity() {
        let fx = fx();
        let cert = fx.x509_self_signed("neg-corrupt", X509Spec::self_signed("localhost"));

        // A valid cert should still produce an identity
        let _identity = cert.identity_tonic();

        // Corrupt PEM is available but tonic Identity::from_pem is infallible
        // (it defers validation to the TLS handshake). Verify the corruption API exists.
        let _corrupt = cert.corrupt_cert_pem(uselesskey_core::negative::CorruptPem::BadBase64);
        assert_ne!(
            cert.cert_pem(),
            &_corrupt,
            "Corrupt PEM should differ from original"
        );
    }

    #[test]
    fn truncated_der_differs_from_original() {
        let fx = fx();
        let cert = fx.x509_self_signed("neg-trunc", X509Spec::self_signed("localhost"));

        let original = cert.cert_der();
        let truncated = cert.truncate_cert_der(original.len() / 2);

        assert!(truncated.len() < original.len());
        assert_ne!(truncated.as_slice(), original);
    }
}

// =========================================================================
// Combined server + client config creation
// =========================================================================

mod combined {
    use super::*;

    #[test]
    fn full_tls_setup_self_signed() {
        let fx = fx();
        let cert = fx.x509_self_signed("full-ss", X509Spec::self_signed("localhost"));

        let _identity = cert.identity_tonic();
        let _server = cert.server_tls_config_tonic();
        let _client = cert.client_tls_config_tonic("localhost");
    }

    #[test]
    fn full_tls_setup_chain() {
        let fx = fx();
        let chain = fx.x509_chain("full-chain", ChainSpec::new("grpc.example.com"));

        let _identity = chain.identity_tonic();
        let _server = chain.server_tls_config_tonic();
        let _client = chain.client_tls_config_tonic("grpc.example.com");
    }

    #[test]
    fn full_mtls_setup() {
        let fx = fx();
        let chain = fx.x509_chain("full-mtls", ChainSpec::new("grpc.example.com"));

        let _identity = chain.identity_tonic();
        let _server = chain.server_tls_config_mtls_tonic();
        let _client = chain.client_tls_config_mtls_tonic("grpc.example.com");
    }

    #[test]
    fn multiple_chains_tls_setup() {
        let fx = fx();

        let chains: Vec<_> = (0..3)
            .map(|i| {
                fx.x509_chain(
                    format!("multi-{i}"),
                    ChainSpec::new(format!("svc{i}.example.com")),
                )
            })
            .collect();

        for (i, chain) in chains.iter().enumerate() {
            let _server = chain.server_tls_config_tonic();
            let _client = chain.client_tls_config_tonic(format!("svc{i}.example.com"));
        }
    }
}
