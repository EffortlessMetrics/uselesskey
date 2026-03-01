//! Coverage-gap tests for uselesskey-x509.
//!
//! Fills gaps not covered by existing prop/unit tests:
//! - X509Spec with custom RSA bits (4096)
//! - X509Spec with custom issuer_cn
//! - X509Spec with SANs verified in parsed cert
//! - Random mode smoke tests
//! - Negative fixtures (expired, not_yet_valid) verified via x509-parser
//! - Chain with custom RSA bits
//! - Self-signed CA negative variant (SelfSignedButClaimsCA)

mod testutil;

use testutil::fx;
use uselesskey_core::Factory;
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Negative, X509Spec};
use x509_parser::prelude::*;

// =========================================================================
// X509Spec with custom RSA bits
// =========================================================================

#[test]
fn self_signed_with_4096_bit_rsa() {
    let factory = fx();
    let spec = X509Spec::self_signed("rsa4096.example.com").with_rsa_bits(4096);
    let cert = factory.x509_self_signed("rsa4096-test", spec);

    assert!(cert.cert_pem().contains("-----BEGIN CERTIFICATE-----"));
    assert!(
        cert.private_key_pkcs8_pem()
            .contains("-----BEGIN PRIVATE KEY-----")
    );

    // The private key DER should be larger for 4096-bit
    let spec_2048 = X509Spec::self_signed("rsa2048.example.com");
    let cert_2048 = factory.x509_self_signed("rsa2048-test", spec_2048);
    assert!(
        cert.private_key_pkcs8_der().len() > cert_2048.private_key_pkcs8_der().len(),
        "4096-bit key DER should be larger than 2048-bit"
    );
}

// =========================================================================
// X509Spec with SANs verified in parsed cert
// =========================================================================

#[test]
fn self_signed_with_sans_appear_in_cert() {
    let factory = fx();
    let spec = X509Spec::self_signed("san.example.com").with_sans(vec![
        "san.example.com".to_string(),
        "www.san.example.com".to_string(),
    ]);
    let cert = factory.x509_self_signed("san-test", spec);

    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse cert");

    let san_ext = parsed
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
        .expect("should have SAN extension");

    let san = match san_ext.parsed_extension() {
        x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => san,
        other => panic!("expected SAN, got {:?}", other),
    };

    let dns_names: Vec<String> = san
        .general_names
        .iter()
        .filter_map(|gn| {
            if let x509_parser::extensions::GeneralName::DNSName(name) = gn {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect();

    assert!(dns_names.contains(&"san.example.com".to_string()));
    assert!(dns_names.contains(&"www.san.example.com".to_string()));
}

// =========================================================================
// Random mode smoke tests
// =========================================================================

#[test]
fn random_mode_self_signed_produces_valid_cert() {
    let factory = Factory::random();
    let spec = X509Spec::self_signed("random.example.com");
    let cert = factory.x509_self_signed("random-test", spec);

    assert!(!cert.cert_der().is_empty());
    assert!(cert.cert_pem().contains("-----BEGIN CERTIFICATE-----"));

    let result = X509Certificate::from_der(cert.cert_der());
    assert!(result.is_ok(), "Random mode cert should be parseable");
}

#[test]
fn random_mode_chain_produces_valid_chain() {
    let factory = Factory::random();
    let spec = ChainSpec::new("random-chain.example.com");
    let chain = factory.x509_chain("random-chain", spec);

    assert!(!chain.leaf_cert_der().is_empty());
    assert!(!chain.intermediate_cert_der().is_empty());
    assert!(!chain.root_cert_der().is_empty());

    let chain_pem = chain.chain_pem();
    assert_eq!(chain_pem.matches("-----BEGIN CERTIFICATE-----").count(), 2);
}

#[test]
fn random_mode_caches_same_identity() {
    let factory = Factory::random();
    let spec = X509Spec::self_signed("cache.example.com");
    let c1 = factory.x509_self_signed("cache-test", spec.clone());
    let c2 = factory.x509_self_signed("cache-test", spec);

    assert_eq!(c1.cert_der(), c2.cert_der());
}

// =========================================================================
// Negative fixtures verified via x509-parser
// =========================================================================

#[test]
fn expired_cert_has_past_not_after() {
    let factory = fx();
    let spec = X509Spec::self_signed("expired.example.com");
    let cert = factory.x509_self_signed("expired-verify", spec);
    let expired = cert.expired();

    let (_, parsed) = X509Certificate::from_der(expired.cert_der()).expect("parse expired cert");
    let not_after = parsed.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Expired cert should have not_after in the past
    assert!(
        not_after < now,
        "Expired cert not_after ({not_after}) should be before now ({now})"
    );
}

#[test]
fn not_yet_valid_cert_differs_from_good() {
    let factory = fx();
    let spec = X509Spec::self_signed("notyet.example.com");
    let cert = factory.x509_self_signed("notyet-verify", spec);
    let not_yet = cert.not_yet_valid();

    assert_ne!(cert.cert_der(), not_yet.cert_der());

    let (_, parsed) =
        X509Certificate::from_der(not_yet.cert_der()).expect("parse not-yet-valid cert");
    let not_before = parsed.validity().not_before.timestamp();
    let (_, good_parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse good cert");
    let good_not_before = good_parsed.validity().not_before.timestamp();

    assert!(
        not_before > good_not_before,
        "Not-yet-valid cert should have later not_before"
    );
}

// =========================================================================
// SelfSignedButClaimsCA negative
// =========================================================================

#[test]
fn self_signed_but_claims_ca_is_ca() {
    let factory = fx();
    let spec = X509Spec::self_signed("ca-claim.example.com");
    let cert = factory.x509_self_signed("ca-claim", spec);
    let ca_variant = cert.negative(X509Negative::SelfSignedButClaimsCA);

    let (_, parsed) = X509Certificate::from_der(ca_variant.cert_der()).expect("parse CA cert");
    assert!(parsed.is_ca(), "SelfSignedButClaimsCA should be CA");
    assert!(ca_variant.spec().is_ca);
}

// =========================================================================
// Wrong key usage negative verified
// =========================================================================

#[test]
fn wrong_key_usage_has_modified_key_usage() {
    let factory = fx();
    let spec = X509Spec::self_signed("wrongku.example.com");
    let cert = factory.x509_self_signed("wrongku-verify", spec);
    let wrong = cert.wrong_key_usage();

    assert_ne!(cert.cert_der(), wrong.cert_der());

    // Wrong key usage should still produce a parseable cert
    let (_, parsed) = X509Certificate::from_der(wrong.cert_der()).expect("parse wrong KU cert");
    assert!(parsed.is_ca(), "WrongKeyUsage sets is_ca=true");
}

// =========================================================================
// Chain with custom RSA bits
// =========================================================================

#[test]
fn chain_with_custom_rsa_bits() {
    let factory = fx();
    let spec = ChainSpec::new("chain4096.example.com").with_rsa_bits(4096);
    let chain = factory.x509_chain("chain-4096", spec);

    assert!(!chain.leaf_cert_der().is_empty());
    assert!(!chain.root_cert_der().is_empty());

    // Verify keys are 4096-bit by checking leaf private key DER length
    let default_spec = ChainSpec::new("chain2048.example.com");
    let default_chain = factory.x509_chain("chain-2048", default_spec);
    assert!(
        chain.leaf_private_key_pkcs8_der().len() > default_chain.leaf_private_key_pkcs8_der().len(),
        "4096-bit chain should have larger key DER"
    );
}

// =========================================================================
// X509Spec builder methods coverage
// =========================================================================

#[test]
fn custom_validity_days_reflected_in_cert() {
    let factory = fx();
    let spec = X509Spec::self_signed("validity.example.com").with_validity_days(30);
    let cert = factory.x509_self_signed("validity-test", spec);

    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse cert");
    let not_before = parsed.validity().not_before.timestamp();
    let not_after = parsed.validity().not_after.timestamp();
    let validity_days = (not_after - not_before) / 86400;

    assert_eq!(validity_days, 30, "Validity should be 30 days");
}

#[test]
fn custom_key_usage_reflected_in_cert() {
    use uselesskey_x509::KeyUsage;

    let factory = fx();
    let ku = KeyUsage {
        digital_signature: true,
        key_encipherment: false,
        key_cert_sign: false,
        crl_sign: false,
    };
    let spec = X509Spec::self_signed("ku.example.com").with_key_usage(ku);
    let cert = factory.x509_self_signed("ku-custom", spec);

    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse cert");

    let ku_ext = parsed
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE)
        .expect("should have KeyUsage extension");

    let ku_parsed = match ku_ext.parsed_extension() {
        x509_parser::extensions::ParsedExtension::KeyUsage(ku) => ku,
        other => panic!("expected KeyUsage, got {:?}", other),
    };

    assert!(ku_parsed.digital_signature());
    assert!(!ku_parsed.key_encipherment());
}
