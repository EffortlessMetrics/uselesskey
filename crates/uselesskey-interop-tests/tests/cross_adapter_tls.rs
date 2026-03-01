//! Cross-adapter TLS interoperability tests.
//!
//! These tests create X.509 certificates with uselesskey-x509 and verify they
//! work for TLS handshakes with different crypto providers.

#![cfg(feature = "cross-tls")]

use std::sync::{Arc, OnceLock};

use uselesskey_core::{Factory, Seed};
use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt};

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> &'static Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-cross-tls-seed-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
}

const MAX_HANDSHAKE_ITERATIONS: usize = 10;

/// Drive a TLS handshake to completion by exchanging bytes between client and
/// server until neither side needs to write.
fn complete_handshake(
    client: &mut rustls::ClientConnection,
    server: &mut rustls::ServerConnection,
) {
    let mut buf = Vec::new();
    for iteration in 0..MAX_HANDSHAKE_ITERATIONS {
        let mut progress = false;

        buf.clear();
        if client.wants_write() {
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                server.read_tls(&mut &buf[..]).unwrap();
                server.process_new_packets().unwrap();
                progress = true;
            }
        }

        buf.clear();
        if server.wants_write() {
            server.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                client.read_tls(&mut &buf[..]).unwrap();
                client.process_new_packets().unwrap();
                progress = true;
            }
        }

        if !progress {
            break;
        }

        assert!(
            iteration < MAX_HANDSHAKE_ITERATIONS - 1,
            "TLS handshake did not complete within {MAX_HANDSHAKE_ITERATIONS} iterations",
        );
    }

    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
}

// =========================================================================
// TLS with the ring crypto provider
// =========================================================================

mod ring_provider {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    #[test]
    fn tls_handshake_chain() {
        let fx = fx();
        let chain = fx.x509_chain("tls-ring-chain", ChainSpec::new("ring.example.com"));

        let provider = ring_provider();
        let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

        let server_name = "ring.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();

        complete_handshake(&mut client, &mut server);
    }

    #[test]
    fn ring_accepts_uselesskey_rsa_key() {
        let fx = fx();
        let keypair = fx.rsa("tls-ring-rsa", RsaSpec::rs256());
        let _ring_kp = ring::rsa::KeyPair::from_pkcs8(keypair.private_key_pkcs8_der())
            .expect("ring should accept uselesskey RSA key");
    }

    #[test]
    fn ring_accepts_uselesskey_ecdsa_key() {
        let fx = fx();
        let keypair = fx.ecdsa("tls-ring-ecdsa", EcdsaSpec::es256());
        let _ring_kp = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            keypair.private_key_pkcs8_der(),
            &ring::rand::SystemRandom::new(),
        )
        .expect("ring should accept uselesskey ECDSA key");
    }

    #[test]
    fn ring_accepts_uselesskey_ed25519_key() {
        let fx = fx();
        let keypair = fx.ed25519("tls-ring-ed25519", Ed25519Spec::new());
        let _ring_kp = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(
            keypair.private_key_pkcs8_der(),
        )
        .expect("ring should accept uselesskey Ed25519 key");
    }
}

// =========================================================================
// TLS with the aws-lc-rs crypto provider
// =========================================================================

#[cfg(all(feature = "aws-lc-rs-interop", any(not(windows), has_nasm)))]
mod aws_lc_rs_provider {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    fn aws_provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
    }

    #[test]
    fn tls_handshake_chain() {
        let fx = fx();
        let chain = fx.x509_chain("tls-aws-chain", ChainSpec::new("aws.example.com"));

        let provider = aws_provider();
        let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

        let server_name = "aws.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();

        complete_handshake(&mut client, &mut server);
    }

    #[test]
    fn aws_lc_rs_accepts_uselesskey_rsa_key() {
        let fx = fx();
        let keypair = fx.rsa("tls-aws-rsa", RsaSpec::rs256());
        let _aws_kp = aws_lc_rs::rsa::KeyPair::from_pkcs8(keypair.private_key_pkcs8_der())
            .expect("aws-lc-rs should accept uselesskey RSA key");
    }

    #[test]
    fn aws_lc_rs_accepts_uselesskey_ecdsa_key() {
        let fx = fx();
        let keypair = fx.ecdsa("tls-aws-ecdsa", EcdsaSpec::es256());
        let _aws_kp = aws_lc_rs::signature::EcdsaKeyPair::from_pkcs8(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            keypair.private_key_pkcs8_der(),
        )
        .expect("aws-lc-rs should accept uselesskey ECDSA key");
    }

    #[test]
    fn aws_lc_rs_accepts_uselesskey_ed25519_key() {
        let fx = fx();
        let keypair = fx.ed25519("tls-aws-ed25519", Ed25519Spec::new());
        let _aws_kp =
            aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(keypair.private_key_pkcs8_der())
                .expect("aws-lc-rs should accept uselesskey Ed25519 key");
    }
}
