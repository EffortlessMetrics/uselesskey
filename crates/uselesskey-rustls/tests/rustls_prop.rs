#![cfg(all(feature = "tls-config", feature = "x509"))]

use proptest::prelude::*;

use std::sync::{Arc, Once};

use rustls::crypto::CryptoProvider;
use uselesskey_core::{Factory, Seed};
use uselesskey_rustls::{RustlsChainExt, RustlsClientConfigExt, RustlsServerConfigExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt};

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

proptest! {
    #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

    /// TLS handshake succeeds for any seed.
    #[test]
    fn tls_handshake_succeeds_for_any_seed(seed in any::<[u8; 32]>()) {
        install_provider();

        let fx = Factory::deterministic(Seed::new(seed));
        let chain = fx.x509_chain("prop-tls", ChainSpec::new("test.example.com"));

        let provider = ring_provider();
        let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

        let server_name: rustls::pki_types::ServerName<'_> =
            "test.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client =
            rustls::ClientConnection::new(client_config, server_name.to_owned()).unwrap();

        let result = try_handshake(&mut server, &mut client);
        prop_assert!(result.is_ok(), "TLS handshake should succeed: {:?}", result.err());
    }

    /// Chain has expected structure: 2 certs (leaf + intermediate) and a root.
    #[test]
    fn chain_structure_is_valid(seed in any::<[u8; 32]>()) {
        let fx = Factory::deterministic(Seed::new(seed));
        let chain = fx.x509_chain("prop-chain", ChainSpec::new("test.example.com"));

        let certs = chain.chain_der_rustls();
        prop_assert_eq!(certs.len(), 2, "chain should have leaf + intermediate");

        let root = chain.root_certificate_der_rustls();
        prop_assert!(!root.as_ref().is_empty(), "root cert should be non-empty");
    }

    /// Different seeds produce different certificates.
    #[test]
    fn different_seeds_produce_different_chains(
        seed1 in any::<[u8; 32]>(),
        seed2 in any::<[u8; 32]>(),
    ) {
        prop_assume!(seed1 != seed2);

        let fx1 = Factory::deterministic(Seed::new(seed1));
        let fx2 = Factory::deterministic(Seed::new(seed2));
        let chain1 = fx1.x509_chain("prop-chain", ChainSpec::new("test.example.com"));
        let chain2 = fx2.x509_chain("prop-chain", ChainSpec::new("test.example.com"));

        prop_assert_ne!(
            chain1.leaf_cert_der(),
            chain2.leaf_cert_der(),
            "different seeds should produce different leaf certs"
        );
    }
}
