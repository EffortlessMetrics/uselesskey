//! Negative-path integration tests for the rustls adapter.
//!
//! These tests verify that TLS handshakes fail as expected when using
//! negative X.509 chain fixtures (expired certs, unknown CAs).

#![cfg(all(feature = "tls-config", feature = "x509"))]

use std::sync::{Arc, Once};

use rustls::crypto::CryptoProvider;
use uselesskey_core::{Factory, Seed};
use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt};

use std::sync::OnceLock;

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-rustls-negative-test-seed-v1")
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

/// Maximum iterations for TLS handshake loops to prevent infinite loops.
const MAX_HANDSHAKE_ITERATIONS: usize = 10;

/// Attempt a TLS handshake between server and client connections.
///
/// Returns `Ok(())` if the handshake completes successfully, or `Err(error)`
/// if any `process_new_packets()` call returns an error during the handshake.
fn try_handshake(
    server: &mut rustls::ServerConnection,
    client: &mut rustls::ClientConnection,
) -> Result<(), rustls::Error> {
    let mut buf = Vec::new();
    for _iteration in 0..MAX_HANDSHAKE_ITERATIONS {
        let mut progress = false;

        // client -> server
        buf.clear();
        if client.wants_write() {
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                server.read_tls(&mut &buf[..]).unwrap();
                server.process_new_packets()?;
                progress = true;
            }
        }

        // server -> client
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

#[test]
fn expired_leaf_cert_handshake_fails() {
    install_provider();
    let fx = fx();

    let chain = fx.x509_chain("neg-expired", ChainSpec::new("test.example.com"));
    let expired = chain.expired_leaf();

    let provider = ring_provider();
    // Server uses the expired-leaf chain
    let server_config = Arc::new(expired.server_config_rustls_with_provider(provider.clone()));
    // Client trusts the same CA (valid root from the good chain)
    let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

    let server_name: rustls::pki_types::ServerName<'_> = "test.example.com".try_into().unwrap();
    let mut server = rustls::ServerConnection::new(server_config).unwrap();
    let mut client = rustls::ClientConnection::new(client_config, server_name.to_owned()).unwrap();

    let result = try_handshake(&mut server, &mut client);
    assert!(
        result.is_err(),
        "TLS handshake with expired leaf cert should fail"
    );
}

#[test]
fn unknown_ca_handshake_fails() {
    install_provider();
    let fx = fx();

    // Generate two independent chains with different labels and therefore different CAs
    let chain_a = fx.x509_chain("neg-ca-a", ChainSpec::new("test.example.com"));
    let chain_b = fx.x509_chain("neg-ca-b", ChainSpec::new("test.example.com"));

    let provider = ring_provider();
    // Server uses chain A's cert
    let server_config = Arc::new(chain_a.server_config_rustls_with_provider(provider.clone()));
    // Client trusts chain B's root CA (different CA entirely)
    let client_config = Arc::new(chain_b.client_config_rustls_with_provider(provider));

    let server_name: rustls::pki_types::ServerName<'_> = "test.example.com".try_into().unwrap();
    let mut server = rustls::ServerConnection::new(server_config).unwrap();
    let mut client = rustls::ClientConnection::new(client_config, server_name.to_owned()).unwrap();

    let result = try_handshake(&mut server, &mut client);
    assert!(result.is_err(), "TLS handshake with unknown CA should fail");
}
