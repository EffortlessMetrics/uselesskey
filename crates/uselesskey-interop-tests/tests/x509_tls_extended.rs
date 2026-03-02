//! Extended X.509 + rustls TLS interop tests.
//!
//! Covers self-signed certificate TLS, data exchange after handshake,
//! and provider-specific scenarios.

#![cfg(feature = "cross-tls")]

use std::io::{Read, Write};
use std::sync::{Arc, OnceLock};

use uselesskey_core::{Factory, Seed};
use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> &'static Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-x509-tls-extended-seed-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
}

const MAX_HANDSHAKE_ITERATIONS: usize = 10;

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
// Self-signed certificate TLS
// =========================================================================

#[test]
fn self_signed_tls_handshake_ring_provider() {
    let cert = fx().x509_self_signed(
        "tls-ext-ss-ring",
        X509Spec::self_signed("ss-ring.example.com").with_sans(vec!["ss-ring.example.com".into()]),
    );

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = Arc::new(cert.server_config_rustls_with_provider(provider.clone()));
    let client_config = Arc::new(cert.client_config_rustls_with_provider(provider));

    let server_name = "ss-ring.example.com".try_into().unwrap();
    let mut server = rustls::ServerConnection::new(server_config).unwrap();
    let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();

    complete_handshake(&mut client, &mut server);
}

#[cfg(all(feature = "aws-lc-rs-interop", any(not(windows), has_nasm)))]
#[test]
fn self_signed_tls_handshake_aws_provider() {
    let cert = fx().x509_self_signed(
        "tls-ext-ss-aws",
        X509Spec::self_signed("ss-aws.example.com").with_sans(vec!["ss-aws.example.com".into()]),
    );

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server_config = Arc::new(cert.server_config_rustls_with_provider(provider.clone()));
    let client_config = Arc::new(cert.client_config_rustls_with_provider(provider));

    let server_name = "ss-aws.example.com".try_into().unwrap();
    let mut server = rustls::ServerConnection::new(server_config).unwrap();
    let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();

    complete_handshake(&mut client, &mut server);
}

// =========================================================================
// Data exchange over TLS (chain-based)
// =========================================================================

#[test]
fn chain_tls_bidirectional_data_exchange() {
    let chain = fx().x509_chain("tls-ext-bidir", ChainSpec::new("bidirectional.example.com"));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
    let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

    let server_name = "bidirectional.example.com".try_into().unwrap();
    let mut server = rustls::ServerConnection::new(server_config).unwrap();
    let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();

    complete_handshake(&mut client, &mut server);

    // Client → Server
    let client_msg = b"hello from client via uselesskey TLS";
    client.writer().write_all(client_msg).unwrap();

    let mut buf = Vec::new();
    client.write_tls(&mut buf).unwrap();
    server.read_tls(&mut &buf[..]).unwrap();
    server.process_new_packets().unwrap();

    let mut received = vec![0u8; client_msg.len()];
    server.reader().read_exact(&mut received).unwrap();
    assert_eq!(&received, client_msg);

    // Server → Client
    let server_msg = b"hello from server via uselesskey TLS";
    server.writer().write_all(server_msg).unwrap();

    buf.clear();
    server.write_tls(&mut buf).unwrap();
    client.read_tls(&mut &buf[..]).unwrap();
    client.process_new_packets().unwrap();

    let mut received = vec![0u8; server_msg.len()];
    client.reader().read_exact(&mut received).unwrap();
    assert_eq!(&received, server_msg);
}

// =========================================================================
// Data exchange over TLS (self-signed)
// =========================================================================

#[test]
fn self_signed_tls_data_exchange() {
    let cert = fx().x509_self_signed(
        "tls-ext-ss-data",
        X509Spec::self_signed("ss-data.example.com").with_sans(vec!["ss-data.example.com".into()]),
    );

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = Arc::new(cert.server_config_rustls_with_provider(provider.clone()));
    let client_config = Arc::new(cert.client_config_rustls_with_provider(provider));

    let server_name = "ss-data.example.com".try_into().unwrap();
    let mut server = rustls::ServerConnection::new(server_config).unwrap();
    let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();

    complete_handshake(&mut client, &mut server);

    let payload = b"self-signed TLS data round-trip";
    client.writer().write_all(payload).unwrap();

    let mut buf = Vec::new();
    client.write_tls(&mut buf).unwrap();
    server.read_tls(&mut &buf[..]).unwrap();
    server.process_new_packets().unwrap();

    let mut received = vec![0u8; payload.len()];
    server.reader().read_exact(&mut received).unwrap();
    assert_eq!(&received, payload);
}

// =========================================================================
// aws-lc-rs provider data exchange
// =========================================================================

#[cfg(all(feature = "aws-lc-rs-interop", any(not(windows), has_nasm)))]
#[test]
fn chain_tls_data_exchange_aws_provider() {
    let chain = fx().x509_chain("tls-ext-aws-data", ChainSpec::new("aws-data.example.com"));

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
    let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

    let server_name = "aws-data.example.com".try_into().unwrap();
    let mut server = rustls::ServerConnection::new(server_config).unwrap();
    let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();

    complete_handshake(&mut client, &mut server);

    let payload = b"aws-provider TLS data round-trip";
    client.writer().write_all(payload).unwrap();

    let mut buf = Vec::new();
    client.write_tls(&mut buf).unwrap();
    server.read_tls(&mut &buf[..]).unwrap();
    server.process_new_packets().unwrap();

    let mut received = vec![0u8; payload.len()];
    server.reader().read_exact(&mut received).unwrap();
    assert_eq!(&received, payload);
}
