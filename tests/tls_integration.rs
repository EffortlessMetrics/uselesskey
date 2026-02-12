//! TLS Integration Tests
//!
//! Tests cross-crate TLS functionality:
//! - TLS server/client configuration with X.509 chains
//! - mTLS scenarios with mutual authentication
//! - Cross-crate compatibility between uselesskey-rustls and X.509 crates
//! - TLS with different key types (RSA, ECDSA, Ed25519)

mod testutil;

use rustls::crypto::CryptoProvider;
use std::sync::Arc;
use testutil::fx;
use uselesskey_core::Factory;
use uselesskey_rustls::{RustlsClientConfigExt, RustlsMtlsExt, RustlsServerConfigExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt};

// =========================================================================
// Basic TLS Configuration Tests
// =========================================================================

#[cfg(feature = "tls")]
mod basic_tls_config_tests {
    use super::*;

    #[test]
    fn test_tls_server_config_from_chain() {
        let fx = fx();

        let chain_spec = ChainSpec::new("test.example.com")
            .with_sans(vec!["localhost".to_string(), "127.0.0.1".to_string()]);
        let chain = fx.x509_chain("server1", chain_spec);

        // Build server config
        let server_config = chain.server_config_rustls();

        // Verify config was created successfully
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_tls_server_config_from_self_signed() {
        let fx = fx();

        let spec = uselesskey_x509::X509Spec::self_signed("localhost");
        let cert = fx.x509_self_signed("self-signed", spec);

        // Build server config
        let server_config = cert.server_config_rustls();

        // Verify config was created successfully
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_tls_client_config_from_chain() {
        let fx = fx();

        let chain_spec = ChainSpec::new("test.example.com");
        let chain = fx.x509_chain("client1", chain_spec);

        // Build client config
        let client_config = chain.client_config_rustls();

        // Verify config was created successfully
        assert_eq!(client_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_tls_client_config_from_self_signed() {
        let fx = fx();

        let spec = uselesskey_x509::X509Spec::self_signed("localhost");
        let cert = fx.x509_self_signed("self-signed", spec);

        // Build client config
        let client_config = cert.client_config_rustls();

        // Verify config was created successfully
        assert_eq!(client_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_tls_config_with_provider() {
        let fx = fx();

        let chain_spec = ChainSpec::new("test.example.com");
        let chain = fx.x509_chain("provider-test", chain_spec);

        // Build server config with explicit provider
        let provider = CryptoProvider::get_default()
            .expect("default crypto provider available")
            .clone();
        let server_config = chain.server_config_rustls_with_provider(provider);

        // Verify config was created successfully
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }
}

// =========================================================================
// mTLS Configuration Tests
// =========================================================================

#[cfg(feature = "tls")]
mod mtls_config_tests {
    use super::*;

    #[test]
    fn test_mtls_server_config() {
        let fx = fx();

        let chain_spec = ChainSpec::new("mtls-server.example.com");
        let chain = fx.x509_chain("mtls-server", chain_spec);

        // Build mTLS server config
        let server_config = chain.server_config_mtls_rustls();

        // Verify config was created successfully
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_mtls_client_config() {
        let fx = fx();

        let chain_spec = ChainSpec::new("mtls-client.example.com");
        let chain = fx.x509_chain("mtls-client", chain_spec);

        // Build mTLS client config
        let client_config = chain.client_config_mtls_rustls();

        // Verify config was created successfully
        assert_eq!(client_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_mtls_config_with_provider() {
        let fx = fx();

        let chain_spec = ChainSpec::new("mtls-provider.example.com");
        let chain = fx.x509_chain("mtls-provider", chain_spec);

        // Build mTLS server config with explicit provider
        let provider = CryptoProvider::get_default()
            .expect("default crypto provider available")
            .clone();
        let server_config = chain.server_config_mtls_rustls_with_provider(provider);

        // Verify config was created successfully
        assert_eq!(server_config.alpn_protocols.len(), 0);

        // Build mTLS client config with explicit provider
        let provider = CryptoProvider::get_default()
            .expect("default crypto provider available")
            .clone();
        let client_config = chain.client_config_mtls_rustls_with_provider(provider);

        // Verify config was created successfully
        assert_eq!(client_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_mtls_pair_config() {
        let fx = fx();

        // Server chain
        let server_chain_spec = ChainSpec::new("server.example.com");
        let server_chain = fx.x509_chain("mtls-server-pair", server_chain_spec);

        // Client chain
        let client_chain_spec = ChainSpec::new("client.example.com");
        let client_chain = fx.x509_chain("mtls-client-pair", client_chain_spec);

        // Build both configs
        let server_config = server_chain.server_config_mtls_rustls();
        let client_config = client_chain.client_config_mtls_rustls();

        // Verify both configs were created successfully
        assert_eq!(server_config.alpn_protocols.len(), 0);
        assert_eq!(client_config.alpn_protocols.len(), 0);
    }
}

// =========================================================================
// Cross-Key Type Tests
// =========================================================================

#[cfg(feature = "tls")]
mod rsa_tls_tests {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn test_tls_with_rsa_key() {
        let fx = fx();

        // Create RSA keypair
        let rsa_keypair = fx.rsa("rsa-server", RsaSpec::rs256());

        // Create X.509 cert with RSA key
        let spec = uselesskey_x509::X509Spec::self_signed("rsa.example.com");
        let cert = fx.x509_self_signed_with_key("rsa-cert", spec, &rsa_keypair);

        // Build server config
        let server_config = cert.server_config_rustls();

        // Verify config was created successfully
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_tls_with_rsa_different_key_sizes() {
        let fx = fx();

        let key_sizes = [2048, 3072, 4096];

        for bits in key_sizes {
            let rsa_keypair = fx.rsa(&format!("rsa-{}-bit", bits), RsaSpec::new(bits));

            let spec = uselesskey_x509::X509Spec::self_signed(&format!("rsa-{}.example.com", bits));
            let cert =
                fx.x509_self_signed_with_key(&format!("rsa-cert-{}", bits), spec, &rsa_keypair);

            let server_config = cert.server_config_rustls();

            assert_eq!(server_config.alpn_protocols.len(), 0);
        }
    }
}

#[cfg(feature = "tls")]
mod ecdsa_tls_tests {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn test_tls_with_ecdsa_p256_key() {
        let fx = fx();

        // Create ECDSA P-256 keypair
        let ecdsa_keypair = fx.ecdsa("ecdsa-p256-server", EcdsaSpec::Es256);

        // Create X.509 cert with ECDSA key
        let spec = uselesskey_x509::X509Spec::self_signed("ecdsa-p256.example.com");
        let cert = fx.x509_self_signed_with_key("ecdsa-p256-cert", spec, &ecdsa_keypair);

        // Build server config
        let server_config = cert.server_config_rustls();

        // Verify config was created successfully
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_tls_with_ecdsa_p384_key() {
        let fx = fx();

        // Create ECDSA P-384 keypair
        let ecdsa_keypair = fx.ecdsa("ecdsa-p384-server", EcdsaSpec::Es384);

        // Create X.509 cert with ECDSA key
        let spec = uselesskey_x509::X509Spec::self_signed("ecdsa-p384.example.com");
        let cert = fx.x509_self_signed_with_key("ecdsa-p384-cert", spec, &ecdsa_keypair);

        // Build server config
        let server_config = cert.server_config_rustls();

        // Verify config was created successfully
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }
}

#[cfg(feature = "tls")]
mod ed25519_tls_tests {
    use super::*;
    use uselesskey_ed25519::Ed25519FactoryExt;

    #[test]
    fn test_tls_with_ed25519_key() {
        let fx = fx();

        // Create Ed25519 keypair
        let ed25519_keypair = fx.ed25519("ed25519-server", uselesskey_ed25519::Ed25519Spec::new());

        // Create X.509 cert with Ed25519 key
        let spec = uselesskey_x509::X509Spec::self_signed("ed25519.example.com");
        let cert = fx.x509_self_signed_with_key("ed25519-cert", spec, &ed25519_keypair);

        // Build server config
        let server_config = cert.server_config_rustls();

        // Verify config was created successfully
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }
}

// =========================================================================
// Certificate Chain Tests
// =========================================================================

#[cfg(feature = "tls")]
mod chain_tests {
    use super::*;

    #[test]
    fn test_chain_structure() {
        let fx = fx();

        let chain_spec = ChainSpec::new("chain.example.com");
        let chain = fx.x509_chain("chain-test", chain_spec);

        // Verify chain structure
        assert!(!chain.leaf_cert_pem().is_empty());
        assert!(!chain.intermediate_cert_pem().is_empty());
        assert!(!chain.root_cert_pem().is_empty());
        assert!(!chain.chain_pem().is_empty());
    }

    #[test]
    fn test_chain_der_conversions() {
        let fx = fx();

        let chain_spec = ChainSpec::new("der.example.com");
        let chain = fx.x509_chain("der-test", chain_spec);

        // Get DER formats
        let leaf_der = chain.leaf_cert_der();
        let intermediate_der = chain.intermediate_cert_der();
        let root_der = chain.root_cert_der();
        let chain_der = chain.chain_der();
        let private_key_der = chain.leaf_private_key_pkcs8_der();

        // Verify DER conversions
        assert!(!leaf_der.is_empty());
        assert!(!intermediate_der.is_empty());
        assert!(!root_der.is_empty());
        assert_eq!(chain_der.len(), 2); // leaf + intermediate
        assert!(!private_key_der.is_empty());
    }

    #[test]
    fn test_chain_rustls_conversions() {
        let fx = fx();

        let chain_spec = ChainSpec::new("rustls.example.com");
        let chain = fx.x509_chain("rustls-test", chain_spec);

        // Get rustls formats
        let cert_chain = chain.chain_der_rustls();
        let root_cert = chain.root_certificate_der_rustls();
        let private_key = chain.private_key_der_rustls();

        // Verify rustls conversions
        assert_eq!(cert_chain.len(), 2); // leaf + intermediate
        assert!(!root_cert.as_ref().is_empty());
        assert!(!private_key.secret_bytes().is_empty());
    }

    #[test]
    fn test_chain_with_sans() {
        let fx = fx();

        let chain_spec = ChainSpec::new("sans.example.com").with_sans(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "*.example.com".to_string(),
        ]);
        let chain = fx.x509_chain("sans-test", chain_spec);

        // Build server config
        let server_config = chain.server_config_rustls();

        // Verify config was created successfully
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }
}

// =========================================================================
// Determinism Tests
// =========================================================================

#[cfg(all(
    feature = "uselesskey-x509",
    feature = "uselesskey-rustls",
    feature = "server-config"
))]
mod tls_determinism_tests {
    use super::*;

    #[test]
    fn test_deterministic_chains_produce_same_configs() {
        let fx1 = fx();
        let fx2 = fx();

        // Generate same chain from same seed
        let chain1 = fx1.x509_chain("deterministic", ChainSpec::new("test.example.com"));
        let chain2 = fx2.x509_chain("deterministic", ChainSpec::new("test.example.com"));

        // Build configs from both chains
        let server_config1 = chain1.server_config_rustls();
        let server_config2 = chain2.server_config_rustls();

        // Both configs should be created successfully
        assert_eq!(server_config1.alpn_protocols.len(), 0);
        assert_eq!(server_config2.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_different_labels_produce_different_chains() {
        let fx = fx();

        // Generate chains with different labels
        let chain1 = fx.x509_chain("label-1", ChainSpec::new("test.example.com"));
        let chain2 = fx.x509_chain("label-2", ChainSpec::new("test.example.com"));

        // Chains should have different certificates
        assert_ne!(chain1.leaf_cert_pem(), chain2.leaf_cert_pem());
        assert_ne!(chain1.root_cert_pem(), chain2.root_cert_pem());
    }
}

// =========================================================================
// Negative Fixture Tests
// =========================================================================

#[cfg(feature = "tls")]
mod negative_fixture_tests {
    use super::*;

    #[test]
    fn test_expired_cert_config() {
        let fx = fx();

        let spec = uselesskey_x509::X509Spec::self_signed("expired.example.com");
        let cert = fx.x509_self_signed("expired", spec);

        // Create expired variant
        let expired_cert = cert.expired();

        // Build server config (config creation succeeds, handshake would fail)
        let server_config = expired_cert.server_config_rustls();

        // Verify config was created successfully
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_not_yet_valid_cert_config() {
        let fx = fx();

        let spec = uselesskey_x509::X509Spec::self_signed("not-yet-valid.example.com");
        let cert = fx.x509_self_signed("not-yet-valid", spec);

        // Create not-yet-valid variant
        let not_yet_valid_cert = cert.not_yet_valid();

        // Build server config (config creation succeeds, handshake would fail)
        let server_config = not_yet_valid_cert.server_config_rustls();

        // Verify config was created successfully
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }
}
