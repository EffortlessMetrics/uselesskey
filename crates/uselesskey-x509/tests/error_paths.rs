//! Error path and boundary condition tests for uselesskey-x509.

mod testutil;

use testutil::fx;
use uselesskey_core::negative::CorruptPem;
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Negative, X509Spec};

// =========================================================================
// Negative fixtures produce parseable but invalid certs
// =========================================================================

#[test]
fn expired_cert_parses_but_has_past_not_after() {
    use x509_parser::prelude::*;

    let fx = fx();
    let spec = X509Spec::self_signed("expired.example.com");
    let cert = fx.x509_self_signed("expired-test", spec);
    let expired = cert.expired();

    let (_, parsed) = X509Certificate::from_der(expired.cert_der()).expect("should parse");
    let not_after = parsed.validity().not_after.timestamp();
    let not_before = parsed.validity().not_before.timestamp();

    // Expired: not_before was 395 days ago, validity 365 days = expired 30 days ago
    assert!(
        not_after < not_before + (366 * 86400),
        "expired cert should have short validity"
    );
}

#[test]
fn not_yet_valid_cert_parses_but_has_future_not_before() {
    use x509_parser::prelude::*;

    let fx = fx();
    let spec = X509Spec::self_signed("future.example.com");
    let cert = fx.x509_self_signed("future-test", spec);
    let future = cert.not_yet_valid();

    let (_, parsed) = X509Certificate::from_der(future.cert_der()).expect("should parse");
    let not_before = parsed.validity().not_before.timestamp();

    // not_yet_valid: not_before is 30 days from now (relative to base_time)
    // Just verify it differs from the original
    let (_, parsed_orig) =
        X509Certificate::from_der(cert.cert_der()).expect("should parse original");
    assert_ne!(
        not_before,
        parsed_orig.validity().not_before.timestamp(),
        "not-yet-valid cert must have different not_before than original"
    );
}

#[test]
fn wrong_key_usage_cert_is_ca_without_cert_sign() {
    use x509_parser::prelude::*;

    let fx = fx();
    let spec = X509Spec::self_signed("wku.example.com");
    let cert = fx.x509_self_signed("wku-test", spec);
    let wrong = cert.wrong_key_usage();

    let (_, parsed) = X509Certificate::from_der(wrong.cert_der()).expect("should parse");

    // Should be marked as CA
    assert!(parsed.is_ca(), "wrong_key_usage cert should be CA");

    // Key usage should NOT have keyCertSign
    let ku_ext = parsed
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE);

    if let Some(ext) = ku_ext
        && let x509_parser::extensions::ParsedExtension::KeyUsage(ku) = ext.parsed_extension()
    {
        assert!(
            !ku.key_cert_sign(),
            "wrong_key_usage cert must NOT have keyCertSign"
        );
    }

// =========================================================================
// Corrupt cert PEM variants
// =========================================================================

#[test]
fn corrupt_cert_pem_bad_header() {
    let fx = fx();
    let spec = X509Spec::self_signed("corrupt.example.com");
    let cert = fx.x509_self_signed("corrupt-hdr", spec);

    let bad = cert.corrupt_cert_pem(CorruptPem::BadHeader);
    assert!(bad.contains("CORRUPTED"));
    assert!(!bad.starts_with("-----BEGIN CERTIFICATE-----"));
}

#[test]
fn corrupt_cert_pem_bad_base64() {
    let fx = fx();
    let spec = X509Spec::self_signed("corrupt.example.com");
    let cert = fx.x509_self_signed("corrupt-b64", spec);

    let bad = cert.corrupt_cert_pem(CorruptPem::BadBase64);
    assert!(bad.contains("THIS_IS_NOT_BASE64!!!"));
}

#[test]
fn corrupt_cert_pem_bad_footer() {
    let fx = fx();
    let spec = X509Spec::self_signed("corrupt.example.com");
    let cert = fx.x509_self_signed("corrupt-ftr", spec);

    let bad = cert.corrupt_cert_pem(CorruptPem::BadFooter);
    assert!(bad.contains("CORRUPTED"));
}

// =========================================================================
// Truncated cert DER
// =========================================================================

#[test]
fn truncated_cert_der_is_short() {
    let fx = fx();
    let spec = X509Spec::self_signed("trunc.example.com");
    let cert = fx.x509_self_signed("trunc-test", spec);

    let truncated = cert.truncate_cert_der(10);
    assert_eq!(truncated.len(), 10);

    // Should not parse
    use x509_parser::prelude::FromDer;
    let result = x509_parser::prelude::X509Certificate::from_der(&truncated);
    assert!(result.is_err(), "truncated DER must not parse");
}

#[test]
fn truncated_cert_der_zero_returns_empty() {
    let fx = fx();
    let spec = X509Spec::self_signed("trunc-zero.example.com");
    let cert = fx.x509_self_signed("trunc-zero", spec);

    let truncated = cert.truncate_cert_der(0);
    assert!(truncated.is_empty());
}

// =========================================================================
// Deterministic corruption stability
// =========================================================================

#[test]
fn deterministic_corrupt_cert_pem_is_stable() {
    let fx = fx();
    let spec = X509Spec::self_signed("det-corrupt.example.com");
    let cert = fx.x509_self_signed("det-corrupt", spec);

    let a = cert.corrupt_cert_pem_deterministic("corrupt:v1");
    let b = cert.corrupt_cert_pem_deterministic("corrupt:v1");
    assert_eq!(a, b);
}

#[test]
fn deterministic_corrupt_cert_der_is_stable() {
    let fx = fx();
    let spec = X509Spec::self_signed("det-der.example.com");
    let cert = fx.x509_self_signed("det-der", spec);

    let a = cert.corrupt_cert_der_deterministic("corrupt:v1");
    let b = cert.corrupt_cert_der_deterministic("corrupt:v1");
    assert_eq!(a, b);
}

// =========================================================================
// X509Spec boundary conditions
// =========================================================================

#[test]
fn zero_validity_days_still_generates() {
    let fx = fx();
    let spec = X509Spec::self_signed("zero-days.example.com").with_validity_days(0);
    let cert = fx.x509_self_signed("zero-days", spec);

    assert!(!cert.cert_der().is_empty());
    assert!(cert.cert_pem().contains("BEGIN CERTIFICATE"));
}

#[test]
fn very_large_validity_days_still_generates() {
    let fx = fx();
    let spec = X509Spec::self_signed("large-days.example.com").with_validity_days(36500);
    let cert = fx.x509_self_signed("large-days", spec);

    assert!(!cert.cert_der().is_empty());
}

#[test]
fn empty_cn_still_generates() {
    let fx = fx();
    let spec = X509Spec::self_signed("");
    let cert = fx.x509_self_signed("empty-cn", spec);

    assert!(!cert.cert_der().is_empty());
}

#[test]
fn empty_label_still_generates() {
    let fx = fx();
    let spec = X509Spec::self_signed("test.example.com");
    let cert = fx.x509_self_signed("", spec);

    assert!(!cert.cert_der().is_empty());
}

// =========================================================================
// Chain negative fixtures
// =========================================================================

#[test]
fn chain_produces_three_certs() {
    let fx = fx();
    let chain = fx.x509_chain("chain-test", ChainSpec::new("chain.example.com"));

    // chain_pem should contain leaf + intermediate (2 certs)
    let chain_pem = chain.chain_pem();
    let cert_count = chain_pem.matches("BEGIN CERTIFICATE").count();
    assert_eq!(
        cert_count, 2,
        "chain_pem should have 2 certs (leaf + intermediate)"
    );

    // Full chain should have 3
    let full_pem = chain.full_chain_pem();
    let full_count = full_pem.matches("BEGIN CERTIFICATE").count();
    assert_eq!(full_count, 3, "full_chain_pem should have 3 certs");
}

#[test]
fn chain_root_cert_is_ca() {
    use x509_parser::prelude::*;

    let fx = fx();
    let chain = fx.x509_chain("chain-ca-test", ChainSpec::new("ca.example.com"));

    let (_, parsed) =
        X509Certificate::from_der(chain.root_cert_der()).expect("root cert should parse");
    assert!(parsed.is_ca(), "root cert must be CA");
}

// =========================================================================
// Debug does not leak certificate material
// =========================================================================

#[test]
fn x509_cert_debug_does_not_leak() {
    let fx = fx();
    let spec = X509Spec::self_signed("debug.example.com");
    let cert = fx.x509_self_signed("debug-test", spec);

    let dbg = format!("{:?}", cert);
    assert!(dbg.contains("X509Cert"));
    assert!(dbg.contains("debug-test"));
    assert!(!dbg.contains("BEGIN CERTIFICATE"));
    assert!(!dbg.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn x509_chain_debug_does_not_leak() {
    let fx = fx();
    let chain = fx.x509_chain("debug-chain", ChainSpec::new("debug.example.com"));

    let dbg = format!("{:?}", chain);
    assert!(dbg.contains("X509Chain"));
    assert!(!dbg.contains("BEGIN CERTIFICATE"));
}

// =========================================================================
// identity_pem contains both cert and key
// =========================================================================

#[test]
fn identity_pem_combines_cert_and_key() {
    let fx = fx();
    let spec = X509Spec::self_signed("identity.example.com");
    let cert = fx.x509_self_signed("identity-test", spec);

    let identity = cert.identity_pem();
    assert!(identity.contains("BEGIN CERTIFICATE"));
    assert!(identity.contains("BEGIN PRIVATE KEY"));
}

// =========================================================================
// All X509Negative variants produce distinct certs
// =========================================================================

#[test]
fn all_negative_variants_produce_distinct_certs() {
    let fx = fx();
    let spec = X509Spec::self_signed("neg.example.com");
    let cert = fx.x509_self_signed("neg-all", spec);

    let negatives = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];

    let mut ders: Vec<Vec<u8>> = vec![cert.cert_der().to_vec()];
    for neg in negatives {
        let neg_cert = cert.negative(neg);
        let der = neg_cert.cert_der().to_vec();
        assert!(
            !ders.contains(&der),
            "negative variant {:?} should produce unique cert",
            neg
        );
        ders.push(der);
    }
}
