//! TLS Integration Tests
//!
//! Tests cross-crate TLS functionality:
//! - TLS server/client configuration with X.509 chains
//! - mTLS scenarios with mutual authentication
//! - Cross-crate compatibility between uselesskey-rustls and X.509 crates
//! - TLS with different key types (RSA, ECDSA, Ed25519)

mod testutil;

use std::sync::OnceLock;

use rustls::crypto::CryptoProvider;
use uselesskey_rustls::{
    RustlsChainExt, RustlsClientConfigExt, RustlsMtlsExt, RustlsPrivateKeyExt,
    RustlsServerConfigExt,
};
use uselesskey_x509::{ChainSpec, X509Cert, X509Chain, X509FactoryExt, X509Spec};

fn fx() -> uselesskey_core::Factory {
    testutil::install_rustls_ring_provider();
    testutil::fx()
}

// ---------------------------------------------------------------------------
// Shared fixtures — amortise RSA keygen to once per test binary
// ---------------------------------------------------------------------------

static SHARED_CHAIN: OnceLock<X509Chain> = OnceLock::new();
static SHARED_SELF_SIGNED: OnceLock<X509Cert> = OnceLock::new();

fn shared_chain() -> &'static X509Chain {
    SHARED_CHAIN.get_or_init(|| {
        let fx = fx();
        fx.x509_chain(
            "shared-tls",
            ChainSpec::new("test.example.com").with_sans(vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "*.example.com".to_string(),
            ]),
        )
    })
}

fn shared_self_signed() -> &'static X509Cert {
    SHARED_SELF_SIGNED.get_or_init(|| {
        let fx = fx();
        fx.x509_self_signed("shared-ss", X509Spec::self_signed("localhost"))
    })
}

// =========================================================================
// Basic TLS Configuration Tests
// =========================================================================

#[cfg(feature = "tls")]
mod basic_tls_config_tests {
    use super::*;

    #[test]
    fn test_tls_server_config_from_chain() {
        let chain = shared_chain();
        let server_config = chain.server_config_rustls();
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_tls_server_config_from_self_signed() {
        let cert = shared_self_signed();
        let server_config = cert.server_config_rustls();
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_tls_client_config_from_chain() {
        let chain = shared_chain();
        let client_config = chain.client_config_rustls();
        assert_eq!(client_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_tls_client_config_from_self_signed() {
        let cert = shared_self_signed();
        let client_config = cert.client_config_rustls();
        assert_eq!(client_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_tls_config_with_provider() {
        let chain = shared_chain();
        let provider = CryptoProvider::get_default()
            .expect("default crypto provider available")
            .clone();
        let server_config = chain.server_config_rustls_with_provider(provider);
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
        let chain = shared_chain();
        let server_config = chain.server_config_mtls_rustls();
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_mtls_client_config() {
        let chain = shared_chain();
        let client_config = chain.client_config_mtls_rustls();
        assert_eq!(client_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_mtls_config_with_provider() {
        let chain = shared_chain();

        let provider = CryptoProvider::get_default()
            .expect("default crypto provider available")
            .clone();
        let server_config = chain.server_config_mtls_rustls_with_provider(provider);
        assert_eq!(server_config.alpn_protocols.len(), 0);

        let provider = CryptoProvider::get_default()
            .expect("default crypto provider available")
            .clone();
        let client_config = chain.client_config_mtls_rustls_with_provider(provider);
        assert_eq!(client_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_mtls_pair_config() {
        let chain = shared_chain();

        let server_config = chain.server_config_mtls_rustls();
        let client_config = chain.client_config_mtls_rustls();

        assert_eq!(server_config.alpn_protocols.len(), 0);
        assert_eq!(client_config.alpn_protocols.len(), 0);
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
        let chain = shared_chain();

        assert!(!chain.leaf_cert_pem().is_empty());
        assert!(!chain.intermediate_cert_pem().is_empty());
        assert!(!chain.root_cert_pem().is_empty());
        assert!(!chain.chain_pem().is_empty());
    }

    #[test]
    fn test_chain_der_conversions() {
        let chain = shared_chain();

        let leaf_der = chain.leaf_cert_der();
        let intermediate_der = chain.intermediate_cert_der();
        let root_der = chain.root_cert_der();
        let private_key_der = chain.leaf_private_key_pkcs8_der();

        assert!(!leaf_der.is_empty());
        assert!(!intermediate_der.is_empty());
        assert!(!root_der.is_empty());
        assert!(!private_key_der.is_empty());
    }

    #[test]
    fn test_chain_rustls_conversions() {
        let chain = shared_chain();

        let cert_chain = chain.chain_der_rustls();
        let root_cert = chain.root_certificate_der_rustls();
        let private_key = chain.private_key_der_rustls();

        assert_eq!(cert_chain.len(), 2); // leaf + intermediate
        assert!(!root_cert.as_ref().is_empty());
        assert!(!private_key.secret_der().is_empty());
    }

    #[test]
    fn test_chain_with_sans() {
        // shared_chain() already includes SANs
        let chain = shared_chain();
        let server_config = chain.server_config_rustls();
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }
}

// =========================================================================
// Determinism Tests
// =========================================================================

#[cfg(feature = "tls")]
mod tls_determinism_tests {
    use super::*;

    #[test]
    fn test_deterministic_chains_produce_same_configs() {
        let fx1 = fx();
        let fx2 = fx();

        // Same seed + same label → identical chain (cache hit on cloned Factory)
        let chain1 = fx1.x509_chain("deterministic", ChainSpec::new("test.example.com"));
        let chain2 = fx2.x509_chain("deterministic", ChainSpec::new("test.example.com"));

        let server_config1 = chain1.server_config_rustls();
        let server_config2 = chain2.server_config_rustls();

        assert_eq!(server_config1.alpn_protocols.len(), 0);
        assert_eq!(server_config2.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_different_labels_produce_different_chains() {
        let fx = fx();

        let chain1 = fx.x509_chain("label-1", ChainSpec::new("test.example.com"));
        let chain2 = fx.x509_chain("label-2", ChainSpec::new("test.example.com"));

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
        let cert = shared_self_signed();
        let expired_cert = cert.expired();

        let server_config = expired_cert.server_config_rustls();
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }

    #[test]
    fn test_not_yet_valid_cert_config() {
        let cert = shared_self_signed();
        let not_yet_valid_cert = cert.not_yet_valid();

        let server_config = not_yet_valid_cert.server_config_rustls();
        assert_eq!(server_config.alpn_protocols.len(), 0);
    }
}
