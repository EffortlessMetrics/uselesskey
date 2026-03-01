//! Cross-adapter integration tests for uselesskey-rustls.
//!
//! Tests cover:
//! - RSA, ECDSA, and Ed25519 key conversion to rustls types
//! - Private key PEM/DER parsing via rustls-pki-types
//! - X.509 certificate chain building for TLS handshakes
//! - Deterministic mode produces consistent rustls keys

use std::sync::{Arc, Once, OnceLock};

use rustls::crypto::CryptoProvider;
use rustls_pki_types::PrivateKeyDer;
use uselesskey_core::{Factory, Seed};
use uselesskey_rustls::RustlsPrivateKeyExt;

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-rustls-adapter-integration-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
    .clone()
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
// RSA key conversion
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_rustls {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rsa_private_key_converts_to_pkcs8() {
        let fx = fx();
        let kp = fx.rsa("rustls-rsa", RsaSpec::rs256());
        let key = kp.private_key_der_rustls();

        match &key {
            PrivateKeyDer::Pkcs8(_) => {}
            _ => panic!("expected PKCS#8 variant"),
        }
        assert_eq!(key.secret_der(), kp.private_key_pkcs8_der());
    }

    #[test]
    fn rsa_private_key_der_is_nonempty() {
        let fx = fx();
        let kp = fx.rsa("rustls-rsa-nonempty", RsaSpec::rs256());
        let key = kp.private_key_der_rustls();
        assert!(!key.secret_der().is_empty());
    }

    #[test]
    fn rsa_deterministic_produces_same_rustls_key() {
        let seed = Seed::from_env_value("rustls-rsa-det-test").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.rsa("det-rsa", RsaSpec::rs256());
        let kp2 = fx2.rsa("det-rsa", RsaSpec::rs256());

        let key1 = kp1.private_key_der_rustls();
        let key2 = kp2.private_key_der_rustls();
        assert_eq!(key1.secret_der(), key2.secret_der());
    }

    #[test]
    fn rsa_different_labels_produce_different_keys() {
        let fx = fx();
        let kp_a = fx.rsa("rsa-label-a", RsaSpec::rs256());
        let kp_b = fx.rsa("rsa-label-b", RsaSpec::rs256());

        let key_a = kp_a.private_key_der_rustls();
        let key_b = kp_b.private_key_der_rustls();
        assert_ne!(key_a.secret_der(), key_b.secret_der());
    }
}

// =========================================================================
// ECDSA key conversion
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_rustls {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn ecdsa_p256_converts_to_pkcs8() {
        let fx = fx();
        let kp = fx.ecdsa("rustls-ec256", EcdsaSpec::es256());
        let key = kp.private_key_der_rustls();

        match &key {
            PrivateKeyDer::Pkcs8(_) => {}
            _ => panic!("expected PKCS#8 variant"),
        }
        assert_eq!(key.secret_der(), kp.private_key_pkcs8_der());
    }

    #[test]
    fn ecdsa_p384_converts_to_pkcs8() {
        let fx = fx();
        let kp = fx.ecdsa("rustls-ec384", EcdsaSpec::es384());
        let key = kp.private_key_der_rustls();

        match &key {
            PrivateKeyDer::Pkcs8(_) => {}
            _ => panic!("expected PKCS#8 variant"),
        }
        assert_eq!(key.secret_der(), kp.private_key_pkcs8_der());
    }

    #[test]
    fn ecdsa_deterministic_produces_same_rustls_key() {
        let seed = Seed::from_env_value("rustls-ecdsa-det-test").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ecdsa("det-ec", EcdsaSpec::es256());
        let kp2 = fx2.ecdsa("det-ec", EcdsaSpec::es256());

        let key1 = kp1.private_key_der_rustls();
        let key2 = kp2.private_key_der_rustls();
        assert_eq!(key1.secret_der(), key2.secret_der());
    }

    #[test]
    fn ecdsa_p256_and_p384_produce_different_keys() {
        let fx = fx();
        let kp_256 = fx.ecdsa("ec-curve-test", EcdsaSpec::es256());
        let kp_384 = fx.ecdsa("ec-curve-test", EcdsaSpec::es384());

        let key_256 = kp_256.private_key_der_rustls();
        let key_384 = kp_384.private_key_der_rustls();
        assert_ne!(key_256.secret_der(), key_384.secret_der());
    }
}

// =========================================================================
// Ed25519 key conversion
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_rustls {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn ed25519_converts_to_pkcs8() {
        let fx = fx();
        let kp = fx.ed25519("rustls-ed", Ed25519Spec::new());
        let key = kp.private_key_der_rustls();

        match &key {
            PrivateKeyDer::Pkcs8(_) => {}
            _ => panic!("expected PKCS#8 variant"),
        }
        assert_eq!(key.secret_der(), kp.private_key_pkcs8_der());
    }

    #[test]
    fn ed25519_der_is_nonempty() {
        let fx = fx();
        let kp = fx.ed25519("rustls-ed-nonempty", Ed25519Spec::new());
        let key = kp.private_key_der_rustls();
        assert!(!key.secret_der().is_empty());
    }

    #[test]
    fn ed25519_deterministic_produces_same_rustls_key() {
        let seed = Seed::from_env_value("rustls-ed-det-test").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ed25519("det-ed", Ed25519Spec::new());
        let kp2 = fx2.ed25519("det-ed", Ed25519Spec::new());

        let key1 = kp1.private_key_der_rustls();
        let key2 = kp2.private_key_der_rustls();
        assert_eq!(key1.secret_der(), key2.secret_der());
    }
}

// =========================================================================
// X.509 chain TLS handshake integration
// =========================================================================

#[cfg(feature = "x509")]
mod x509_tls_chain {
    use super::*;
    use uselesskey_rustls::{RustlsChainExt, RustlsClientConfigExt, RustlsServerConfigExt};
    use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

    #[test]
    fn chain_produces_leaf_plus_intermediate() {
        let fx = fx();
        let chain = fx.x509_chain("chain-len", ChainSpec::new("test.example.com"));
        let certs = chain.chain_der_rustls();
        assert_eq!(certs.len(), 2, "chain should have leaf + intermediate");
    }

    #[test]
    fn chain_root_differs_from_leaf() {
        let fx = fx();
        let chain = fx.x509_chain("chain-diff", ChainSpec::new("test.example.com"));
        let certs = chain.chain_der_rustls();
        let root = chain.root_certificate_der_rustls();
        assert_ne!(certs[0].as_ref(), root.as_ref());
        assert_ne!(certs[1].as_ref(), root.as_ref());
    }

    #[test]
    fn tls_handshake_succeeds_with_chain() {
        install_provider();
        let fx = fx();
        let chain = fx.x509_chain("tls-ok", ChainSpec::new("test.example.com"));

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
    fn self_signed_server_config_builds() {
        install_provider();
        let fx = fx();
        let cert = fx.x509_self_signed("ss-build", X509Spec::self_signed("test.example.com"));
        let _cfg = cert.server_config_rustls_with_provider(ring_provider());
    }

    #[test]
    fn deterministic_chains_produce_same_handshake() {
        install_provider();
        let seed = Seed::from_env_value("rustls-chain-det").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let chain1 = fx1.x509_chain("det-chain", ChainSpec::new("test.example.com"));
        let chain2 = fx2.x509_chain("det-chain", ChainSpec::new("test.example.com"));

        assert_eq!(
            chain1.leaf_cert_der(),
            chain2.leaf_cert_der(),
            "deterministic chains should produce identical leaf certs"
        );
        assert_eq!(
            chain1.root_cert_der(),
            chain2.root_cert_der(),
            "deterministic chains should produce identical root certs"
        );
    }

    #[test]
    fn different_chains_fail_cross_verification() {
        install_provider();
        let fx = fx();
        let chain_a = fx.x509_chain("cross-a", ChainSpec::new("test.example.com"));
        let chain_b = fx.x509_chain("cross-b", ChainSpec::new("test.example.com"));

        let provider = ring_provider();
        let server_config = Arc::new(chain_a.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain_b.client_config_rustls_with_provider(provider));

        let server_name: rustls::pki_types::ServerName<'_> = "test.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client =
            rustls::ClientConnection::new(client_config, server_name.to_owned()).unwrap();

        let result = try_handshake(&mut server, &mut client);
        assert!(
            result.is_err(),
            "cross-chain TLS handshake should fail (unknown CA)"
        );
    }
}
