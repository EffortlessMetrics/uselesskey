//! Negative fixture integration tests for RSA.
//!
//! Validates mismatch keys, corrupt PEM variants, and truncated DER
//! produce the expected invalid-but-structurally-correct outputs.

mod testutil;

use testutil::fx;
use uselesskey_core::negative::CorruptPem;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

// ---------------------------------------------------------------------------
// Mismatch variant
// ---------------------------------------------------------------------------

#[test]
fn mismatch_public_key_differs_from_original() {
    let kp = fx().rsa("mismatch-rsa", RsaSpec::rs256());
    let original_pub = kp.public_key_spki_der();
    let mismatched_pub = kp.mismatched_public_key_spki_der();
    assert_ne!(
        original_pub,
        mismatched_pub.as_slice(),
        "mismatched public key must differ from the original"
    );
}

#[test]
fn mismatch_key_is_valid_spki_der() {
    let kp = fx().rsa("mismatch-valid", RsaSpec::rs256());
    let mismatched = kp.mismatched_public_key_spki_der();
    assert!(!mismatched.is_empty(), "mismatched DER must not be empty");
    assert_eq!(
        mismatched[0], 0x30,
        "mismatched DER must start with SEQUENCE tag"
    );
}

#[test]
fn mismatch_is_deterministic() {
    let fx = fx();
    let kp1 = fx.rsa("mismatch-det", RsaSpec::rs256());
    let kp2 = fx.rsa("mismatch-det", RsaSpec::rs256());
    assert_eq!(
        kp1.mismatched_public_key_spki_der(),
        kp2.mismatched_public_key_spki_der(),
        "mismatched key must be deterministic"
    );
}

// ---------------------------------------------------------------------------
// Corrupt PEM variants
// ---------------------------------------------------------------------------

#[test]
fn corrupt_pem_bad_header() {
    let kp = fx().rsa("corrupt-hdr", RsaSpec::rs256());
    let corrupt = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(
        !corrupt.starts_with("-----BEGIN PRIVATE KEY-----"),
        "corrupt BadHeader must not have the original header"
    );
    // Should still look PEM-ish (has dashes)
    assert!(
        corrupt.contains("-----"),
        "corrupt PEM should still contain dashes"
    );
}

#[test]
fn corrupt_pem_bad_footer() {
    let kp = fx().rsa("corrupt-ftr", RsaSpec::rs256());
    let corrupt = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    assert!(
        !corrupt.trim_end().ends_with("-----END PRIVATE KEY-----"),
        "corrupt BadFooter must not have the original footer"
    );
}

#[test]
fn corrupt_pem_bad_base64() {
    let kp = fx().rsa("corrupt-b64", RsaSpec::rs256());
    let corrupt = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    // The corrupt PEM should still have PEM headers
    assert!(
        corrupt.contains("BEGIN"),
        "BadBase64 variant should retain PEM framing"
    );
}

#[test]
fn corrupt_pem_truncate() {
    let kp = fx().rsa("corrupt-trunc", RsaSpec::rs256());
    let original = kp.private_key_pkcs8_pem();
    let corrupt = kp.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 50 });
    assert!(
        corrupt.len() < original.len(),
        "truncated PEM must be shorter than original"
    );
}

// ---------------------------------------------------------------------------
// Truncated DER
// ---------------------------------------------------------------------------

#[test]
fn truncated_der_has_requested_length() {
    let kp = fx().rsa("trunc-der", RsaSpec::rs256());
    let truncated = kp.private_key_pkcs8_der_truncated(10);
    assert_eq!(
        truncated.len(),
        10,
        "truncated DER must be exactly 10 bytes"
    );
}

#[test]
fn truncated_der_is_prefix_of_original() {
    let kp = fx().rsa("trunc-prefix", RsaSpec::rs256());
    let original = kp.private_key_pkcs8_der();
    let truncated = kp.private_key_pkcs8_der_truncated(20);
    assert_eq!(
        &original[..20],
        truncated.as_slice(),
        "truncated DER must be a prefix of the original"
    );
}
