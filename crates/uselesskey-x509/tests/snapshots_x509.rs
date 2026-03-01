//! Insta snapshot tests for uselesskey-x509.
//!
//! These tests snapshot certificate metadata (lengths, headers, subjects)
//! to detect unintended changes. Key material is always redacted.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_x509::{X509FactoryExt, X509Spec};

#[derive(Serialize)]
struct PemShape {
    first_line: String,
    last_line: String,
    line_count: usize,
    total_len: usize,
}

fn pem_shape(pem: &str) -> PemShape {
    let lines: Vec<&str> = pem.lines().collect();
    PemShape {
        first_line: lines.first().unwrap_or(&"").to_string(),
        last_line: lines.last().unwrap_or(&"").to_string(),
        line_count: lines.len(),
        total_len: pem.len(),
    }
}

#[test]
fn snapshot_x509_cert_pem_shape() {
    let fx = fx();
    let spec = X509Spec::self_signed("snap.example.com");
    let cert = fx.x509_self_signed("snap-cert", spec);
    let shape = pem_shape(cert.cert_pem());
    insta::assert_yaml_snapshot!("x509_cert_pem_shape", shape);
}

#[test]
fn snapshot_x509_private_key_pem_shape() {
    let fx = fx();
    let spec = X509Spec::self_signed("snap.example.com");
    let cert = fx.x509_self_signed("snap-cert", spec);
    let shape = pem_shape(cert.private_key_pkcs8_pem());
    insta::assert_yaml_snapshot!("x509_private_key_pem_shape", shape);
}

#[derive(Serialize)]
struct CertDerLengths {
    cert_der_len: usize,
    private_key_der_len: usize,
}

#[test]
fn snapshot_x509_der_lengths() {
    let fx = fx();
    let spec = X509Spec::self_signed("snap.example.com");
    let cert = fx.x509_self_signed("snap-cert", spec);

    let result = CertDerLengths {
        cert_der_len: cert.cert_der().len(),
        private_key_der_len: cert.private_key_pkcs8_der().len(),
    };

    insta::assert_yaml_snapshot!("x509_der_lengths", result);
}

#[test]
fn snapshot_x509_cert_metadata() {
    let fx = fx();
    let spec = X509Spec::self_signed("snap.example.com");
    let cert = fx.x509_self_signed("snap-cert", spec);

    // Parse the certificate to extract metadata
    let (_, parsed) =
        x509_parser::parse_x509_certificate(cert.cert_der()).expect("valid DER certificate");

    #[derive(Serialize)]
    struct CertMetadata {
        subject_cn: String,
        issuer_cn: String,
        is_self_signed: bool,
        version: u32,
        serial_number: String,
    }

    fn extract_cn(name: &x509_parser::prelude::X509Name<'_>) -> String {
        name.iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or("")
            .to_string()
    }

    let meta = CertMetadata {
        subject_cn: extract_cn(parsed.subject()),
        issuer_cn: extract_cn(parsed.issuer()),
        is_self_signed: parsed.subject() == parsed.issuer(),
        version: parsed.version().0,
        serial_number: parsed.raw_serial_as_string(),
    };

    insta::assert_yaml_snapshot!("x509_cert_metadata", meta, {
        ".serial_number" => "[REDACTED]",
    });
}
