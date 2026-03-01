//! Insta snapshot tests for uselesskey-rustls adapter.
//!
//! These tests snapshot certificate and key shapes produced by the rustls adapter
//! to detect unintended changes in adapter output.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_rustls::{RustlsCertExt, RustlsChainExt, RustlsPrivateKeyExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

#[derive(Serialize)]
struct CertDerSnapshot {
    label: &'static str,
    cert_der_len: usize,
}

#[derive(Serialize)]
struct PrivateKeySnapshot {
    label: &'static str,
    key_type: &'static str,
    key_der_len: usize,
}

#[test]
fn snapshot_rustls_self_signed_cert_der_len() {
    let fx = fx();
    let cert = fx.x509_self_signed("snapshot-ss", X509Spec::self_signed("test.example.com"));

    let cert_der = cert.certificate_der_rustls();

    let result = CertDerSnapshot {
        label: "self-signed",
        cert_der_len: cert_der.as_ref().len(),
    };

    insta::assert_yaml_snapshot!("rustls_self_signed_cert_der_len", result);
}

#[test]
fn snapshot_rustls_chain_cert_der_lengths() {
    let fx = fx();
    let chain = fx.x509_chain("snapshot-chain", ChainSpec::new("test.example.com"));

    let chain_certs = chain.chain_der_rustls();
    let root = chain.root_certificate_der_rustls();

    #[derive(Serialize)]
    struct ChainDerLengths {
        leaf_cert_der_len: usize,
        intermediate_cert_der_len: usize,
        root_cert_der_len: usize,
        chain_count: usize,
    }

    let result = ChainDerLengths {
        leaf_cert_der_len: chain_certs[0].as_ref().len(),
        intermediate_cert_der_len: chain_certs[1].as_ref().len(),
        root_cert_der_len: root.as_ref().len(),
        chain_count: chain_certs.len(),
    };

    insta::assert_yaml_snapshot!("rustls_chain_cert_der_lengths", result);
}

#[test]
fn snapshot_rustls_self_signed_private_key_type() {
    let fx = fx();
    let cert = fx.x509_self_signed("snapshot-ss-key", X509Spec::self_signed("test.example.com"));

    let key = cert.private_key_der_rustls();
    let key_type = match &key {
        rustls_pki_types::PrivateKeyDer::Pkcs1(_) => "PKCS1",
        rustls_pki_types::PrivateKeyDer::Pkcs8(_) => "PKCS8",
        rustls_pki_types::PrivateKeyDer::Sec1(_) => "SEC1",
        _ => "Unknown",
    };

    let result = PrivateKeySnapshot {
        label: "self-signed",
        key_type,
        key_der_len: key.secret_der().len(),
    };

    insta::assert_yaml_snapshot!("rustls_self_signed_private_key_type", result, {
        ".key_der_len" => "[REDACTED]",
    });
}

#[test]
fn snapshot_rustls_chain_private_key_type() {
    let fx = fx();
    let chain = fx.x509_chain("snapshot-chain-key", ChainSpec::new("test.example.com"));

    let key = chain.private_key_der_rustls();
    let key_type = match &key {
        rustls_pki_types::PrivateKeyDer::Pkcs1(_) => "PKCS1",
        rustls_pki_types::PrivateKeyDer::Pkcs8(_) => "PKCS8",
        rustls_pki_types::PrivateKeyDer::Sec1(_) => "SEC1",
        _ => "Unknown",
    };

    let result = PrivateKeySnapshot {
        label: "chain-leaf",
        key_type,
        key_der_len: key.secret_der().len(),
    };

    insta::assert_yaml_snapshot!("rustls_chain_private_key_type", result, {
        ".key_der_len" => "[REDACTED]",
    });
}
