//! Comprehensive integration tests for uselesskey-rustls adapter.
//!
//! Covers: key type conversions, certificate chain handling, TLS handshakes,
//! deterministic behavior, self-signed certs, and multiple SNI scenarios.

#![cfg(all(feature = "tls-config", feature = "x509"))]

use std::sync::{Arc, Once};

use rustls::crypto::CryptoProvider;
use uselesskey_core::{Factory, Seed};
use uselesskey_rustls::{
    RustlsCertExt, RustlsChainExt, RustlsClientConfigExt, RustlsMtlsExt, RustlsPrivateKeyExt,
    RustlsServerConfigExt,
};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

use std::sync::OnceLock;

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-rustls-comprehensive-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
    .clone()
}

fn deterministic_factory(seed_str: &str) -> Factory {
    let seed = Seed::from_env_value(seed_str).expect("test seed");
    Factory::deterministic(seed)
}

static INIT: Once = Once::new();

fn install_provider() {
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn ring_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

const MAX_HANDSHAKE_ITERATIONS: usize = 10;

/// Drive a TLS handshake between server and client. Returns Ok(()) on success.
fn try_handshake(
    server: &mut rustls::ServerConnection,
    client: &mut rustls::ClientConnection,
) -> Result<(), rustls::Error> {
    let mut buf = Vec::new();
    for _iteration in 0..MAX_HANDSHAKE_ITERATIONS {
        let mut progress = false;

        buf.clear();
        if client.wants_write() {
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                server.read_tls(&mut &buf[..]).unwrap();
                server.process_new_packets()?;
                progress = true;
            }
        }

        buf.clear();
        if server.wants_write() {
            server.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                client.read_tls(&mut &buf[..]).unwrap();
                client.process_new_packets()?;
                progress = true;
            }
        }

        if !progress {
            break;
        }
    }
    Ok(())
}

// =========================================================================
// Certificate/key conversion tests
// =========================================================================

mod conversion_tests {
    use super::*;

    #[test]
    fn chain_private_key_is_pkcs8() {
        let fx = fx();
        let chain = fx.x509_chain("conv-chain", ChainSpec::new("test.example.com"));

        let key = chain.private_key_der_rustls();
        assert_eq!(
            key.secret_der(),
            chain.leaf_private_key_pkcs8_der(),
            "private key DER must match source"
        );
    }

    #[test]
    fn chain_has_two_certificates() {
        let fx = fx();
        let chain = fx.x509_chain("conv-chain2", ChainSpec::new("test.example.com"));

        let certs = chain.chain_der_rustls();
        assert_eq!(certs.len(), 2, "chain should have leaf + intermediate");
        assert_eq!(certs[0].as_ref(), chain.leaf_cert_der());
        assert_eq!(certs[1].as_ref(), chain.intermediate_cert_der());
    }

    #[test]
    fn root_cert_matches_source() {
        let fx = fx();
        let chain = fx.x509_chain("conv-root", ChainSpec::new("test.example.com"));

        let root = chain.root_certificate_der_rustls();
        assert_eq!(root.as_ref(), chain.root_cert_der());
    }

    #[test]
    fn self_signed_cert_matches_source() {
        let fx = fx();
        let cert = fx.x509_self_signed("conv-ss", X509Spec::self_signed("test.example.com"));

        let cert_der = cert.certificate_der_rustls();
        assert_eq!(cert_der.as_ref(), cert.cert_der());
    }

    #[test]
    fn self_signed_private_key_matches_source() {
        let fx = fx();
        let cert = fx.x509_self_signed("conv-ss-key", X509Spec::self_signed("test.example.com"));

        let key = cert.private_key_der_rustls();
        assert_eq!(key.secret_der(), cert.private_key_pkcs8_der());
    }
}

// =========================================================================
// Key type conversion tests (RSA, ECDSA, Ed25519)
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_key_tests {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rsa_private_key_der_matches_source() {
        let fx = fx();
        let kp = fx.rsa("rustls-rsa", RsaSpec::rs256());
        let key = kp.private_key_der_rustls();
        assert_eq!(key.secret_der(), kp.private_key_pkcs8_der());
    }

    #[test]
    fn rsa_key_der_is_non_empty() {
        let fx = fx();
        let kp = fx.rsa("rustls-rsa-ne", RsaSpec::rs256());
        let key = kp.private_key_der_rustls();
        assert!(!key.secret_der().is_empty());
    }
}

#[cfg(feature = "ecdsa")]
mod ecdsa_key_tests {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn ecdsa_p256_private_key_der_matches() {
        let fx = fx();
        let kp = fx.ecdsa("rustls-ec256", EcdsaSpec::es256());
        let key = kp.private_key_der_rustls();
        assert_eq!(key.secret_der(), kp.private_key_pkcs8_der());
    }

    #[test]
    fn ecdsa_p384_private_key_der_matches() {
        let fx = fx();
        let kp = fx.ecdsa("rustls-ec384", EcdsaSpec::es384());
        let key = kp.private_key_der_rustls();
        assert_eq!(key.secret_der(), kp.private_key_pkcs8_der());
    }
}

#[cfg(feature = "ed25519")]
mod ed25519_key_tests {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn ed25519_private_key_der_matches() {
        let fx = fx();
        let kp = fx.ed25519("rustls-ed", Ed25519Spec::new());
        let key = kp.private_key_der_rustls();
        assert_eq!(key.secret_der(), kp.private_key_pkcs8_der());
    }
}

// =========================================================================
// TLS handshake tests
// =========================================================================

mod tls_handshake_tests {
    use super::*;

    #[test]
    fn successful_tls_handshake_with_chain() {
        install_provider();
        let fx = fx();
        let chain = fx.x509_chain("hs-chain", ChainSpec::new("test.example.com"));

        let provider = ring_provider();
        let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

        let server_name: rustls::pki_types::ServerName<'_> = "test.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client =
            rustls::ClientConnection::new(client_config, server_name.to_owned()).unwrap();

        try_handshake(&mut server, &mut client).expect("handshake should succeed");
        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }

    #[test]
    fn different_domains_different_chains() {
        install_provider();
        let fx = fx();

        let chain_a = fx.x509_chain("domain-a", ChainSpec::new("a.example.com"));
        let chain_b = fx.x509_chain("domain-b", ChainSpec::new("b.example.com"));

        // Different labels should produce different chains
        assert_ne!(
            chain_a.leaf_cert_der(),
            chain_b.leaf_cert_der(),
            "different labels must produce different certs"
        );
    }

    #[test]
    fn mtls_handshake_succeeds() {
        install_provider();
        let fx = fx();
        let chain = fx.x509_chain("mtls-comp", ChainSpec::new("test.example.com"));

        let provider = ring_provider();
        let server_config =
            Arc::new(chain.server_config_mtls_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_mtls_rustls_with_provider(provider));

        let server_name: rustls::pki_types::ServerName<'_> = "test.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client =
            rustls::ClientConnection::new(client_config, server_name.to_owned()).unwrap();

        try_handshake(&mut server, &mut client).expect("mTLS handshake should succeed");
        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }

    #[test]
    fn wrong_server_name_fails() {
        install_provider();
        let fx = fx();
        let chain = fx.x509_chain("sni-test", ChainSpec::new("correct.example.com"));

        let provider = ring_provider();
        let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

        // Client connects with wrong SNI
        let wrong_name: rustls::pki_types::ServerName<'_> = "wrong.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client =
            rustls::ClientConnection::new(client_config, wrong_name.to_owned()).unwrap();

        let result = try_handshake(&mut server, &mut client);
        assert!(result.is_err(), "TLS handshake with wrong SNI should fail");
    }

    #[test]
    fn cross_ca_handshake_fails() {
        install_provider();
        let fx = fx();

        let chain_server = fx.x509_chain("cross-server", ChainSpec::new("test.example.com"));
        let chain_client = fx.x509_chain("cross-client", ChainSpec::new("test.example.com"));

        let provider = ring_provider();
        // Server uses chain_server's cert, client trusts chain_client's CA
        let server_config =
            Arc::new(chain_server.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain_client.client_config_rustls_with_provider(provider));

        let server_name: rustls::pki_types::ServerName<'_> = "test.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client =
            rustls::ClientConnection::new(client_config, server_name.to_owned()).unwrap();

        let result = try_handshake(&mut server, &mut client);
        assert!(result.is_err(), "TLS handshake with cross-CA should fail");
    }
}

// =========================================================================
// Determinism tests
// =========================================================================

mod determinism_tests {
    use super::*;

    #[test]
    fn deterministic_chain_produces_same_der() {
        let fx1 = deterministic_factory("rustls-det-v1");
        let fx2 = deterministic_factory("rustls-det-v1");

        let chain1 = fx1.x509_chain("det-chain", ChainSpec::new("test.example.com"));
        let chain2 = fx2.x509_chain("det-chain", ChainSpec::new("test.example.com"));

        assert_eq!(chain1.leaf_cert_der(), chain2.leaf_cert_der());
        assert_eq!(
            chain1.leaf_private_key_pkcs8_der(),
            chain2.leaf_private_key_pkcs8_der()
        );
        assert_eq!(chain1.root_cert_der(), chain2.root_cert_der());
    }

    #[test]
    fn deterministic_self_signed_produces_same_der() {
        let fx1 = deterministic_factory("rustls-det-ss-v1");
        let fx2 = deterministic_factory("rustls-det-ss-v1");

        let cert1 = fx1.x509_self_signed("det-ss", X509Spec::self_signed("test.example.com"));
        let cert2 = fx2.x509_self_signed("det-ss", X509Spec::self_signed("test.example.com"));

        assert_eq!(cert1.cert_der(), cert2.cert_der());
        assert_eq!(cert1.private_key_pkcs8_der(), cert2.private_key_pkcs8_der());
    }

    #[test]
    fn different_seeds_produce_different_chains() {
        let fx1 = deterministic_factory("rustls-det-diff-a");
        let fx2 = deterministic_factory("rustls-det-diff-b");

        let chain1 = fx1.x509_chain("diff-seed", ChainSpec::new("test.example.com"));
        let chain2 = fx2.x509_chain("diff-seed", ChainSpec::new("test.example.com"));

        assert_ne!(
            chain1.leaf_cert_der(),
            chain2.leaf_cert_der(),
            "different seeds must produce different chains"
        );
    }
}

// =========================================================================
// Debug safety tests
// =========================================================================

mod debug_safety {
    use super::*;

    #[test]
    fn chain_debug_does_not_leak_key_material() {
        let fx = fx();
        let chain = fx.x509_chain("debug-chain", ChainSpec::new("test.example.com"));
        let debug_str = format!("{:?}", chain);
        assert!(
            !debug_str.contains("BEGIN"),
            "Debug output must not contain PEM markers"
        );
    }

    #[test]
    fn self_signed_debug_does_not_leak_key_material() {
        let fx = fx();
        let cert = fx.x509_self_signed("debug-ss", X509Spec::self_signed("test.example.com"));
        let debug_str = format!("{:?}", cert);
        assert!(
            !debug_str.contains("BEGIN"),
            "Debug output must not contain PEM markers"
        );
    }
}
