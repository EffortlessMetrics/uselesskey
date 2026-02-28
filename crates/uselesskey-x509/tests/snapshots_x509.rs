//! Insta snapshot tests for X.509 certificate fixtures.
//!
//! These tests verify deterministic certificate metadata by snapshotting
//! parsed certificate fields. Actual signature and public key bytes are
//! redacted because they are large and not semantically interesting.

mod testutil;

use insta::assert_yaml_snapshot;
use serde::Serialize;
use testutil::fx;
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};
use x509_parser::prelude::*;

#[derive(Serialize)]
struct CertMetadata {
    version: String,
    subject: String,
    issuer: String,
    serial: String,
    signature_algorithm: String,
    not_before: String,
    not_after: String,
    is_ca: bool,
    extensions: Vec<ExtInfo>,
}

#[derive(Serialize)]
struct ExtInfo {
    oid: String,
    critical: bool,
    parsed: String,
}

#[derive(Serialize)]
struct PemStructure {
    header: String,
    footer: String,
    body_lines: String,
}

/// Extract snapshot-friendly metadata from a DER-encoded certificate.
/// Signature and public key bytes are redacted.
fn cert_metadata(der: &[u8]) -> CertMetadata {
    let (_, parsed) = X509Certificate::from_der(der).expect("parse cert");

    let extensions = parsed
        .extensions()
        .iter()
        .map(|ext| {
            let desc = match ext.parsed_extension() {
                ParsedExtension::BasicConstraints(bc) => {
                    format!(
                        "BasicConstraints(ca={}, pathlen={:?})",
                        bc.ca, bc.path_len_constraint
                    )
                }
                ParsedExtension::KeyUsage(ku) => {
                    format!(
                        "KeyUsage(digital_signature={}, key_encipherment={}, key_cert_sign={}, crl_sign={})",
                        ku.digital_signature(),
                        ku.key_encipherment(),
                        ku.key_cert_sign(),
                        ku.crl_sign()
                    )
                }
                ParsedExtension::ExtendedKeyUsage(eku) => {
                    format!(
                        "ExtendedKeyUsage(server_auth={}, client_auth={})",
                        eku.server_auth, eku.client_auth
                    )
                }
                ParsedExtension::SubjectAlternativeName(san) => {
                    let names: Vec<String> =
                        san.general_names.iter().map(|n| format!("{n}")).collect();
                    format!("SubjectAlternativeName({:?})", names)
                }
                _ => "other".into(),
            };
            ExtInfo {
                oid: ext.oid.to_id_string(),
                critical: ext.critical,
                parsed: desc,
            }
        })
        .collect();

    CertMetadata {
        version: format!("{}", parsed.version()),
        subject: parsed.subject().to_string(),
        issuer: parsed.issuer().to_string(),
        serial: parsed.raw_serial_as_string(),
        signature_algorithm: parsed.signature_algorithm.algorithm.to_id_string(),
        not_before: parsed.validity().not_before.to_rfc2822().unwrap(),
        not_after: parsed.validity().not_after.to_rfc2822().unwrap(),
        is_ca: parsed.is_ca(),
        extensions,
    }
}

/// Extract PEM structure info (header/footer lines, line count) without the body.
fn pem_structure(pem: &str) -> PemStructure {
    let lines: Vec<&str> = pem.lines().collect();
    let header = lines.first().unwrap_or(&"").to_string();
    let footer = lines.last().unwrap_or(&"").to_string();
    let body_line_count = lines.len().saturating_sub(2);

    PemStructure {
        header,
        footer,
        body_lines: format!("[{body_line_count} base64 lines]"),
    }
}

// =========================================================================
// Self-signed leaf certificate
// =========================================================================

#[test]
fn snapshots_self_signed_leaf_metadata() {
    let fx = fx();
    let spec = X509Spec::self_signed("snapshot.example.com");
    let cert = fx.x509_self_signed("snapshot-leaf", spec);

    assert_yaml_snapshot!("self_signed_leaf_metadata", cert_metadata(cert.cert_der()));
}

#[test]
fn snapshots_self_signed_leaf_cert_pem_structure() {
    let fx = fx();
    let spec = X509Spec::self_signed("snapshot.example.com");
    let cert = fx.x509_self_signed("snapshot-leaf", spec);

    assert_yaml_snapshot!(
        "self_signed_leaf_cert_pem_structure",
        pem_structure(cert.cert_pem())
    );
}

#[test]
fn snapshots_self_signed_leaf_key_pem_structure() {
    let fx = fx();
    let spec = X509Spec::self_signed("snapshot.example.com");
    let cert = fx.x509_self_signed("snapshot-leaf", spec);

    assert_yaml_snapshot!(
        "self_signed_leaf_key_pem_structure",
        pem_structure(cert.private_key_pkcs8_pem())
    );
}

// =========================================================================
// Self-signed CA certificate
// =========================================================================

#[test]
fn snapshots_self_signed_ca_metadata() {
    let fx = fx();
    let spec = X509Spec::self_signed_ca("ca.snapshot.example.com");
    let cert = fx.x509_self_signed("snapshot-ca", spec);

    assert_yaml_snapshot!("self_signed_ca_metadata", cert_metadata(cert.cert_der()));
}

// =========================================================================
// Certificate with SANs
// =========================================================================

#[test]
fn snapshots_cert_with_sans_metadata() {
    let fx = fx();
    let spec = X509Spec::self_signed("san.snapshot.example.com").with_sans(vec![
        "san.snapshot.example.com".to_string(),
        "alt.snapshot.example.com".to_string(),
    ]);
    let cert = fx.x509_self_signed("snapshot-san", spec);

    assert_yaml_snapshot!("cert_with_sans_metadata", cert_metadata(cert.cert_der()));
}

// =========================================================================
// Negative fixture: expired
// =========================================================================

#[test]
fn snapshots_expired_cert_metadata() {
    let fx = fx();
    let spec = X509Spec::self_signed("expired.snapshot.example.com");
    let cert = fx.x509_self_signed("snapshot-expired", spec);
    let expired = cert.expired();

    assert_yaml_snapshot!("expired_cert_metadata", cert_metadata(expired.cert_der()));
}

// =========================================================================
// Negative fixture: not yet valid
// =========================================================================

#[test]
fn snapshots_not_yet_valid_cert_metadata() {
    let fx = fx();
    let spec = X509Spec::self_signed("future.snapshot.example.com");
    let cert = fx.x509_self_signed("snapshot-future", spec);
    let future_cert = cert.not_yet_valid();

    assert_yaml_snapshot!(
        "not_yet_valid_cert_metadata",
        cert_metadata(future_cert.cert_der())
    );
}

// =========================================================================
// Negative fixture: wrong key usage
// =========================================================================

#[test]
fn snapshots_wrong_key_usage_cert_metadata() {
    let fx = fx();
    let spec = X509Spec::self_signed("badku.snapshot.example.com");
    let cert = fx.x509_self_signed("snapshot-badku", spec);
    let wrong = cert.wrong_key_usage();

    assert_yaml_snapshot!(
        "wrong_key_usage_cert_metadata",
        cert_metadata(wrong.cert_der())
    );
}

// =========================================================================
// Certificate chain
// =========================================================================

#[test]
fn snapshots_chain_leaf_metadata() {
    let fx = fx();
    let spec = ChainSpec::new("chain.snapshot.example.com");
    let chain = fx.x509_chain("snapshot-chain", spec);

    assert_yaml_snapshot!("chain_leaf_metadata", cert_metadata(chain.leaf_cert_der()));
}

#[test]
fn snapshots_chain_intermediate_metadata() {
    let fx = fx();
    let spec = ChainSpec::new("chain.snapshot.example.com");
    let chain = fx.x509_chain("snapshot-chain", spec);

    assert_yaml_snapshot!(
        "chain_intermediate_metadata",
        cert_metadata(chain.intermediate_cert_der())
    );
}

#[test]
fn snapshots_chain_root_metadata() {
    let fx = fx();
    let spec = ChainSpec::new("chain.snapshot.example.com");
    let chain = fx.x509_chain("snapshot-chain", spec);

    assert_yaml_snapshot!("chain_root_metadata", cert_metadata(chain.root_cert_der()));
}
