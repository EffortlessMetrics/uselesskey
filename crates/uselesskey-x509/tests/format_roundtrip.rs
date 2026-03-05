//! Format roundtrip integration tests for X.509.

mod testutil;

use testutil::fx;
use uselesskey_x509::{X509FactoryExt, X509Negative, X509Spec};

// ---------------------------------------------------------------------------
// PEM
// ---------------------------------------------------------------------------

#[test]
fn cert_pem_has_certificate_headers() {
    let cert = fx().x509_self_signed("pem-hdr", X509Spec::self_signed("test.example.com"));
    let pem = cert.cert_pem();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
}

#[test]
fn private_key_pem_has_pkcs8_headers() {
    let cert = fx().x509_self_signed("pem-key", X509Spec::self_signed("test.example.com"));
    let pem = cert.private_key_pkcs8_pem();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
}

// ---------------------------------------------------------------------------
// DER
// ---------------------------------------------------------------------------

#[test]
fn cert_der_starts_with_sequence_tag() {
    let cert = fx().x509_self_signed("der-cert", X509Spec::self_signed("test.example.com"));
    let der = cert.cert_der();
    assert!(!der.is_empty());
    assert_eq!(der[0], 0x30, "X.509 cert DER must start with SEQUENCE tag");
}

#[test]
fn private_key_der_starts_with_sequence_tag() {
    let cert = fx().x509_self_signed("der-key", X509Spec::self_signed("test.example.com"));
    let der = cert.private_key_pkcs8_der();
    assert_eq!(der[0], 0x30, "PKCS#8 DER must start with SEQUENCE tag");
}

// ---------------------------------------------------------------------------
// Negative: expired / not-yet-valid
// ---------------------------------------------------------------------------

#[test]
fn expired_cert_has_different_der_than_valid() {
    let cert = fx().x509_self_signed("neg-exp", X509Spec::self_signed("test.example.com"));
    let expired = cert.negative(X509Negative::Expired);
    assert_ne!(
        cert.cert_der(),
        expired.cert_der(),
        "expired cert must differ from valid cert"
    );
}

#[test]
fn not_yet_valid_cert_has_different_der_than_valid() {
    let cert = fx().x509_self_signed("neg-nyv", X509Spec::self_signed("test.example.com"));
    let nyv = cert.negative(X509Negative::NotYetValid);
    assert_ne!(
        cert.cert_der(),
        nyv.cert_der(),
        "not-yet-valid cert must differ from valid cert"
    );
}

// ---------------------------------------------------------------------------
// Corrupt PEM
// ---------------------------------------------------------------------------

#[test]
fn corrupt_cert_pem_bad_header() {
    let cert = fx().x509_self_signed("corrupt-cert", X509Spec::self_signed("test.example.com"));
    let corrupt = cert.corrupt_cert_pem(uselesskey_core::negative::CorruptPem::BadHeader);
    assert!(
        !corrupt.starts_with("-----BEGIN CERTIFICATE-----"),
        "corrupt BadHeader must not have original header"
    );
}

#[test]
fn truncated_cert_der_has_requested_length() {
    let cert = fx().x509_self_signed("trunc-cert", X509Spec::self_signed("test.example.com"));
    let truncated = cert.truncate_cert_der(20);
    assert_eq!(truncated.len(), 20);
}
