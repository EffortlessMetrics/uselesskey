//! Thread safety tests for uselesskey-tonic adapter.
//!
//! Verifies that tonic TLS config construction is safe under concurrent access
//! from multiple threads sharing the same Factory and X.509 fixtures.

mod testutil;

use std::sync::Arc;
use std::thread;
use testutil::fx;
use uselesskey_tonic::{TonicClientTlsExt, TonicIdentityExt, TonicMtlsExt, TonicServerTlsExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

#[test]
fn concurrent_identity_from_shared_chain() {
    let fx = fx();
    let chain = Arc::new(fx.x509_chain("thread-id", ChainSpec::new("thread.example.com")));

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let chain = Arc::clone(&chain);
            thread::spawn(move || {
                let _identity = chain.identity_tonic();
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread should not panic");
    }
}

#[test]
fn concurrent_server_tls_from_shared_chain() {
    let fx = fx();
    let chain = Arc::new(fx.x509_chain("thread-srv", ChainSpec::new("thread.example.com")));

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let chain = Arc::clone(&chain);
            thread::spawn(move || {
                let _server = chain.server_tls_config_tonic();
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread should not panic");
    }
}

#[test]
fn concurrent_client_tls_from_shared_chain() {
    let fx = fx();
    let chain = Arc::new(fx.x509_chain("thread-cli", ChainSpec::new("thread.example.com")));

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let chain = Arc::clone(&chain);
            thread::spawn(move || {
                let _client = chain.client_tls_config_tonic("thread.example.com");
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread should not panic");
    }
}

#[test]
fn concurrent_mtls_from_shared_chain() {
    let fx = fx();
    let chain = Arc::new(fx.x509_chain("thread-mtls", ChainSpec::new("thread.example.com")));

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let chain = Arc::clone(&chain);
            thread::spawn(move || {
                let _server = chain.server_tls_config_mtls_tonic();
                let _client = chain.client_tls_config_mtls_tonic("thread.example.com");
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread should not panic");
    }
}

#[test]
fn concurrent_mixed_configs_from_shared_cert() {
    let fx = fx();
    let cert = Arc::new(fx.x509_self_signed("thread-ss", X509Spec::self_signed("localhost")));

    let handles: Vec<_> = (0..4)
        .map(|i| {
            let cert = Arc::clone(&cert);
            thread::spawn(move || match i % 3 {
                0 => {
                    let _identity = cert.identity_tonic();
                }
                1 => {
                    let _server = cert.server_tls_config_tonic();
                }
                _ => {
                    let _client = cert.client_tls_config_tonic("localhost");
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread should not panic");
    }
}

#[test]
fn concurrent_factory_generates_different_chains() {
    let fx = Arc::new(fx());

    let handles: Vec<_> = (0..4)
        .map(|i| {
            let fx = Arc::clone(&fx);
            thread::spawn(move || {
                let chain = fx.x509_chain(
                    format!("thread-gen-{i}"),
                    ChainSpec::new(format!("svc{i}.example.com")),
                );
                let _server = chain.server_tls_config_tonic();
                let _client = chain.client_tls_config_tonic(format!("svc{i}.example.com"));
                chain.leaf_cert_der().to_vec()
            })
        })
        .collect();

    let results: Vec<Vec<u8>> = handles
        .into_iter()
        .map(|h| h.join().expect("thread should not panic"))
        .collect();

    // All chains from different labels should differ
    for i in 0..results.len() {
        for j in (i + 1)..results.len() {
            assert_ne!(
                results[i], results[j],
                "Chains {i} and {j} should be different"
            );
        }
    }
}
