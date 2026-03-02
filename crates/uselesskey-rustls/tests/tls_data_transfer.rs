//! TLS data-transfer integration tests.
//!
//! Tests cover:
//! - Bidirectional data transfer after TLS handshake
//! - Multiple sequential handshakes from the same chain
//! - Cross-factory deterministic chain handshake
//! - mTLS data transfer
//! - Large payload transfer

#![cfg(all(feature = "tls-config", feature = "x509"))]

use std::io::{Read, Write};
use std::sync::{Arc, Once};

use rustls::crypto::CryptoProvider;
use uselesskey_core::{Factory, Seed};
use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt};

use std::sync::OnceLock;

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> &'static Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-rustls-data-xfer-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
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

fn complete_handshake(
    server: &mut rustls::ServerConnection,
    client: &mut rustls::ClientConnection,
) {
    let mut buf = Vec::new();
    for _ in 0..MAX_HANDSHAKE_ITERATIONS {
        let mut progress = false;

        buf.clear();
        if client.wants_write() {
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                server.read_tls(&mut &buf[..]).unwrap();
                server.process_new_packets().expect("server process");
                progress = true;
            }
        }

        buf.clear();
        if server.wants_write() {
            server.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                client.read_tls(&mut &buf[..]).unwrap();
                client.process_new_packets().expect("client process");
                progress = true;
            }
        }

        if !progress {
            break;
        }
    }
    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
}

/// Transfer a round-trip message: client -> server -> client.
fn transfer_roundtrip(
    server: &mut rustls::ServerConnection,
    client: &mut rustls::ClientConnection,
    request: &[u8],
    response: &[u8],
) {
    // client writes request
    client.writer().write_all(request).unwrap();
    let mut buf = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut buf).unwrap();
    }
    server.read_tls(&mut &buf[..]).unwrap();
    server.process_new_packets().unwrap();

    let mut received = Vec::new();
    loop {
        let mut tmp = [0u8; 4096];
        match server.reader().read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => received.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("server read error: {e:?}"),
        }
    }
    assert_eq!(received, request);

    // server writes response
    server.writer().write_all(response).unwrap();
    buf.clear();
    while server.wants_write() {
        server.write_tls(&mut buf).unwrap();
    }
    client.read_tls(&mut &buf[..]).unwrap();
    client.process_new_packets().unwrap();

    let mut received = Vec::new();
    loop {
        let mut tmp = [0u8; 4096];
        match client.reader().read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => received.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("client read error: {e:?}"),
        }
    }
    assert_eq!(received, response);
}

fn make_connections(
    chain: &uselesskey_x509::X509Chain,
    domain: &str,
) -> (rustls::ServerConnection, rustls::ClientConnection) {
    let provider = ring_provider();
    let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
    let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

    let server_name: rustls::pki_types::ServerName<'_> = domain.try_into().unwrap();
    let server = rustls::ServerConnection::new(server_config).unwrap();
    let client = rustls::ClientConnection::new(client_config, server_name.to_owned()).unwrap();
    (server, client)
}

// =========================================================================
// Bidirectional data transfer after handshake
// =========================================================================

#[test]
fn data_transfer_after_chain_handshake() {
    install_provider();
    let chain = fx().x509_chain("data-xfer", ChainSpec::new("test.example.com"));
    let (mut server, mut client) = make_connections(&chain, "test.example.com");

    complete_handshake(&mut server, &mut client);
    transfer_roundtrip(
        &mut server,
        &mut client,
        b"GET / HTTP/1.1\r\n",
        b"HTTP/1.1 200 OK\r\n",
    );
}

// =========================================================================
// Multiple sequential handshakes from the same chain
// =========================================================================

#[test]
fn multiple_handshakes_same_chain() {
    install_provider();
    let chain = fx().x509_chain("multi-hs", ChainSpec::new("test.example.com"));

    for i in 0..3 {
        let (mut server, mut client) = make_connections(&chain, "test.example.com");
        complete_handshake(&mut server, &mut client);
        let req = format!("request-{i}");
        let resp = format!("response-{i}");
        transfer_roundtrip(&mut server, &mut client, req.as_bytes(), resp.as_bytes());
    }
}

// =========================================================================
// Cross-factory deterministic chain handshake
// =========================================================================

#[test]
fn cross_factory_deterministic_handshake() {
    install_provider();
    let seed = Seed::from_env_value("rustls-cross-fac-v1").unwrap();

    // Factory1 produces the server chain, Factory2 produces the client trust store
    let fx1 = Factory::deterministic(seed);
    let fx2 = Factory::deterministic(seed);

    let chain1 = fx1.x509_chain("cross-fac", ChainSpec::new("test.example.com"));
    let chain2 = fx2.x509_chain("cross-fac", ChainSpec::new("test.example.com"));

    // Verify they are the same chain
    assert_eq!(chain1.leaf_cert_der(), chain2.leaf_cert_der());

    let provider = ring_provider();
    // Server uses chain1, client trusts chain2's root (same root, different factory instance)
    let server_config = Arc::new(chain1.server_config_rustls_with_provider(provider.clone()));
    let client_config = Arc::new(chain2.client_config_rustls_with_provider(provider));

    let server_name: rustls::pki_types::ServerName<'_> = "test.example.com".try_into().unwrap();
    let mut server = rustls::ServerConnection::new(server_config).unwrap();
    let mut client = rustls::ClientConnection::new(client_config, server_name.to_owned()).unwrap();

    complete_handshake(&mut server, &mut client);
    transfer_roundtrip(&mut server, &mut client, b"cross-factory", b"ok");
}

// =========================================================================
// mTLS with data transfer
// =========================================================================

#[test]
fn mtls_data_transfer() {
    install_provider();
    let fx = fx();
    let chain = fx.x509_chain("mtls-data", ChainSpec::new("test.example.com"));

    let provider = ring_provider();
    use uselesskey_rustls::RustlsMtlsExt;
    let server_config = Arc::new(chain.server_config_mtls_rustls_with_provider(provider.clone()));
    let client_config = Arc::new(chain.client_config_mtls_rustls_with_provider(provider));

    let server_name: rustls::pki_types::ServerName<'_> = "test.example.com".try_into().unwrap();
    let mut server = rustls::ServerConnection::new(server_config).unwrap();
    let mut client = rustls::ClientConnection::new(client_config, server_name.to_owned()).unwrap();

    complete_handshake(&mut server, &mut client);
    transfer_roundtrip(
        &mut server,
        &mut client,
        b"mutual-auth-request",
        b"mutual-auth-response",
    );
}

// =========================================================================
// Non-trivial payload transfer
// =========================================================================

#[test]
fn nontrivial_payload_transfer() {
    install_provider();
    let chain = fx().x509_chain("large-data", ChainSpec::new("test.example.com"));
    let (mut server, mut client) = make_connections(&chain, "test.example.com");

    complete_handshake(&mut server, &mut client);

    let request = vec![0xABu8; 512];
    let response = vec![0xCDu8; 512];
    transfer_roundtrip(&mut server, &mut client, &request, &response);
}
