//! Self-signed certificate negative fixture tests through tonic adapters.
//!
//! Covers:
//! - wrong_key_usage certs build tonic configs
//! - not_yet_valid certs build all tonic configs including mTLS-like setups
//! - corrupt PEM and truncated DER through tonic adapter layer
//! - identity_pem() integration with tonic

mod testutil;

use testutil::fx;
use uselesskey_core::negative::CorruptPem;
use uselesskey_tonic::{TonicClientTlsExt, TonicIdentityExt, TonicServerTlsExt};
use uselesskey_x509::{X509FactoryExt, X509Spec};

// =========================================================================
// wrong_key_usage through tonic
// =========================================================================

#[test]
fn wrong_key_usage_identity_builds() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-wku", X509Spec::self_signed("localhost"));
    let wrong = cert.wrong_key_usage();
    let _identity = wrong.identity_tonic();
}

#[test]
fn wrong_key_usage_server_tls_builds() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-wku-srv", X509Spec::self_signed("localhost"));
    let wrong = cert.wrong_key_usage();
    let _server = wrong.server_tls_config_tonic();
}

#[test]
fn wrong_key_usage_client_tls_builds() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-wku-cli", X509Spec::self_signed("localhost"));
    let wrong = cert.wrong_key_usage();
    let _client = wrong.client_tls_config_tonic("localhost");
}

// =========================================================================
// not_yet_valid through tonic
// =========================================================================

#[test]
fn not_yet_valid_server_tls_builds() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-nyv-srv", X509Spec::self_signed("future.example.com"));
    let future = cert.not_yet_valid();
    let _server = future.server_tls_config_tonic();
}

#[test]
fn not_yet_valid_client_tls_builds() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-nyv-cli", X509Spec::self_signed("future.example.com"));
    let future = cert.not_yet_valid();
    let _client = future.client_tls_config_tonic("future.example.com");
}

// =========================================================================
// Corrupt PEM variants
// =========================================================================

#[test]
fn corrupt_pem_bad_base64_differs_from_original() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-corrupt-b64", X509Spec::self_signed("localhost"));
    let corrupt = cert.corrupt_cert_pem(CorruptPem::BadBase64);
    assert_ne!(cert.cert_pem(), &corrupt);
    assert!(corrupt.contains("-----BEGIN CERTIFICATE-----"));
}

#[test]
fn corrupt_pem_bad_footer_differs() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-corrupt-ftr", X509Spec::self_signed("localhost"));
    let corrupt = cert.corrupt_cert_pem(CorruptPem::BadFooter);
    assert_ne!(cert.cert_pem(), &corrupt);
    assert!(
        corrupt.contains("-----END CORRUPTED KEY-----"),
        "BadFooter should replace the footer"
    );
}

#[test]
fn corrupt_pem_bad_header_differs() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-corrupt-hdr", X509Spec::self_signed("localhost"));
    let corrupt = cert.corrupt_cert_pem(CorruptPem::BadHeader);
    assert_ne!(cert.cert_pem(), &corrupt);
    assert!(
        corrupt.contains("-----BEGIN CORRUPTED KEY-----"),
        "BadHeader should replace the header"
    );
}

#[test]
fn corrupt_pem_extra_blank_line_differs() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-corrupt-blank", X509Spec::self_signed("localhost"));
    let corrupt = cert.corrupt_cert_pem(CorruptPem::ExtraBlankLine);
    assert_ne!(cert.cert_pem(), &corrupt);
}

#[test]
fn corrupt_pem_deterministic_produces_consistent_output() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-det-corrupt", X509Spec::self_signed("localhost"));
    let a = cert.corrupt_cert_pem_deterministic("variant-1");
    let b = cert.corrupt_cert_pem_deterministic("variant-1");
    assert_eq!(a, b, "Same variant should produce same corrupt PEM");
}

#[test]
fn corrupt_pem_different_variants_produce_different_output() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-det-diff", X509Spec::self_signed("localhost"));
    let a = cert.corrupt_cert_pem_deterministic("variant-a");
    let b = cert.corrupt_cert_pem_deterministic("variant-b");
    assert_ne!(
        a, b,
        "Different variants should produce different corrupt PEM"
    );
}

// =========================================================================
// Truncated DER
// =========================================================================

#[test]
fn truncated_der_is_shorter_than_original() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-trunc-len", X509Spec::self_signed("localhost"));
    let original = cert.cert_der();
    let half = original.len() / 2;
    let truncated = cert.truncate_cert_der(half);
    assert_eq!(truncated.len(), half);
}

#[test]
fn truncated_der_to_zero_is_empty() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-trunc-zero", X509Spec::self_signed("localhost"));
    let truncated = cert.truncate_cert_der(0);
    assert!(truncated.is_empty());
}

#[test]
fn corrupt_der_deterministic_produces_consistent_output() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-det-der", X509Spec::self_signed("localhost"));
    let a = cert.corrupt_cert_der_deterministic("variant-1");
    let b = cert.corrupt_cert_der_deterministic("variant-1");
    assert_eq!(a, b, "Same variant should produce same corrupt DER");
}

// =========================================================================
// identity_pem() integration
// =========================================================================

#[test]
fn identity_pem_contains_cert_and_key() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-idpem", X509Spec::self_signed("localhost"));
    let pem = cert.identity_pem();
    assert!(
        pem.contains("-----BEGIN CERTIFICATE-----"),
        "identity_pem should contain certificate"
    );
    assert!(
        pem.contains("-----BEGIN PRIVATE KEY-----"),
        "identity_pem should contain private key"
    );
}

// =========================================================================
// Negative self-signed certs produce different material from originals
// =========================================================================

#[test]
fn expired_cert_differs_from_original() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-diff-exp", X509Spec::self_signed("localhost"));
    let expired = cert.expired();
    assert_ne!(
        cert.cert_der(),
        expired.cert_der(),
        "Expired cert should differ from original"
    );
}

#[test]
fn not_yet_valid_cert_differs_from_original() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-diff-nyv", X509Spec::self_signed("localhost"));
    let future = cert.not_yet_valid();
    assert_ne!(
        cert.cert_der(),
        future.cert_der(),
        "Not-yet-valid cert should differ from original"
    );
}

#[test]
fn wrong_key_usage_cert_differs_from_original() {
    let fx = fx();
    let cert = fx.x509_self_signed("neg-diff-wku", X509Spec::self_signed("localhost"));
    let wrong = cert.wrong_key_usage();
    assert_ne!(
        cert.cert_der(),
        wrong.cert_der(),
        "Wrong key usage cert should differ from original"
    );
}
