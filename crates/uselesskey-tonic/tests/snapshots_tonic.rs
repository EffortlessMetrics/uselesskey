//! Insta snapshot tests for uselesskey-tonic adapter.
//!
//! These tests snapshot tonic TLS config shapes produced by the adapter
//! to detect unintended changes in adapter output.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_tonic::{TonicClientTlsExt, TonicIdentityExt, TonicMtlsExt, TonicServerTlsExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

#[test]
fn snapshot_tonic_available_config_types() {
    #[derive(Serialize)]
    struct TonicConfigTypes {
        identity_from_self_signed: bool,
        identity_from_chain: bool,
        server_tls_from_self_signed: bool,
        server_tls_from_chain: bool,
        client_tls_from_self_signed: bool,
        client_tls_from_chain: bool,
        mtls_server_from_chain: bool,
        mtls_client_from_chain: bool,
    }

    let fx = fx();
    let cert = fx.x509_self_signed("snapshot-ss", X509Spec::self_signed("test.example.com"));
    let chain = fx.x509_chain("snapshot-chain", ChainSpec::new("test.example.com"));

    let result = TonicConfigTypes {
        identity_from_self_signed: {
            let _ = cert.identity_tonic();
            true
        },
        identity_from_chain: {
            let _ = chain.identity_tonic();
            true
        },
        server_tls_from_self_signed: {
            let _ = cert.server_tls_config_tonic();
            true
        },
        server_tls_from_chain: {
            let _ = chain.server_tls_config_tonic();
            true
        },
        client_tls_from_self_signed: {
            let _ = cert.client_tls_config_tonic("test.example.com");
            true
        },
        client_tls_from_chain: {
            let _ = chain.client_tls_config_tonic("test.example.com");
            true
        },
        mtls_server_from_chain: {
            let _ = chain.server_tls_config_mtls_tonic();
            true
        },
        mtls_client_from_chain: {
            let _ = chain.client_tls_config_mtls_tonic("test.example.com");
            true
        },
    };

    insta::assert_yaml_snapshot!("tonic_available_config_types", result);
}

#[test]
fn snapshot_tonic_chain_certificate_shapes() {
    let fx = fx();
    let chain = fx.x509_chain("snapshot-shapes", ChainSpec::new("test.example.com"));

    #[derive(Serialize)]
    struct ChainCertShapes {
        chain_pem_cert_count: usize,
        root_pem_starts_with_cert_header: bool,
        leaf_pem_starts_with_cert_header: bool,
        leaf_key_pem_starts_with_key_header: bool,
    }

    let result = ChainCertShapes {
        chain_pem_cert_count: chain
            .chain_pem()
            .matches("-----BEGIN CERTIFICATE-----")
            .count(),
        root_pem_starts_with_cert_header: chain
            .root_cert_pem()
            .starts_with("-----BEGIN CERTIFICATE-----"),
        leaf_pem_starts_with_cert_header: chain
            .leaf_cert_pem()
            .starts_with("-----BEGIN CERTIFICATE-----"),
        leaf_key_pem_starts_with_key_header: chain
            .leaf_private_key_pkcs8_pem()
            .starts_with("-----BEGIN PRIVATE KEY-----"),
    };

    insta::assert_yaml_snapshot!("tonic_chain_certificate_shapes", result);
}

#[test]
fn snapshot_tonic_self_signed_certificate_shapes() {
    let fx = fx();
    let cert = fx.x509_self_signed(
        "snapshot-ss-shapes",
        X509Spec::self_signed("test.example.com"),
    );

    #[derive(Serialize)]
    struct SelfSignedShapes {
        cert_der_len: usize,
        private_key_der_len: usize,
        cert_pem_starts_with_cert_header: bool,
        key_pem_starts_with_key_header: bool,
    }

    let result = SelfSignedShapes {
        cert_der_len: cert.cert_der().len(),
        private_key_der_len: cert.private_key_pkcs8_der().len(),
        cert_pem_starts_with_cert_header: cert
            .cert_pem()
            .starts_with("-----BEGIN CERTIFICATE-----"),
        key_pem_starts_with_key_header: cert
            .private_key_pkcs8_pem()
            .starts_with("-----BEGIN PRIVATE KEY-----"),
    };

    insta::assert_yaml_snapshot!("tonic_self_signed_certificate_shapes", result);
}
