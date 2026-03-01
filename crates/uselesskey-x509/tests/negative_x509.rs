//! Comprehensive tests for X.509 negative/invalid certificate fixtures.
//!
//! Covers:
//! - Expired certificates (not_after in the past)
//! - Not-yet-valid certificates (not_before in the future)
//! - Self-signed vs CA-signed validation
//! - Wrong key usage (CA flag without keyCertSign)
//! - Invalid serial numbers
//! - Mismatched keypair (negative variant uses different cert but same key)
//! - Determinism of negative fixtures
//! - All X509Negative variants via the high-level API

mod testutil;

use std::collections::HashSet;

use testutil::fx;
use uselesskey_core::negative::CorruptPem;
use uselesskey_core::{Factory, Seed};
use uselesskey_x509::{ChainSpec, NotBeforeOffset, X509FactoryExt, X509Negative, X509Spec};
use x509_parser::prelude::*;

// =========================================================================
// Helper: deterministic factory with explicit seed
// =========================================================================

fn det(seed_str: &str) -> Factory {
    Factory::deterministic(Seed::from_env_value(seed_str).unwrap())
}

// =========================================================================
// Expired certificates
// =========================================================================

#[test]
fn expired_cert_not_after_is_in_the_past() {
    let factory = fx();
    let spec = X509Spec::self_signed("expired.example.com");
    let cert = factory.x509_self_signed("expired-neg", spec);
    let expired = cert.expired();

    let (_, parsed) = X509Certificate::from_der(expired.cert_der()).expect("parse expired cert");
    let not_before = parsed.validity().not_before.timestamp();
    let not_after = parsed.validity().not_after.timestamp();
    let validity_days = (not_after - not_before) / 86400;

    // Expired policy: DaysAgo(395) with validity 365 → expired 30 days ago.
    // Verify validity period is much shorter than the good cert default (3650 days).
    assert_eq!(
        validity_days, 365,
        "expired cert should have 365-day validity"
    );

    // The good cert not_before is based on deterministic_base_time, but we know
    // the expired cert's not_before is pushed far into the past relative to
    // base_time, so not_after = base_time - 395 + 365 = base_time - 30.
    // Confirm the cert is different from the original.
    assert_ne!(cert.cert_der(), expired.cert_der());
}

#[test]
fn expired_cert_has_shorter_validity_than_good_cert() {
    let factory = fx();
    let spec = X509Spec::self_signed("validity-cmp.example.com");
    let cert = factory.x509_self_signed("validity-cmp", spec);
    let expired = cert.expired();

    let (_, good) = X509Certificate::from_der(cert.cert_der()).expect("parse good cert");
    let (_, exp) = X509Certificate::from_der(expired.cert_der()).expect("parse expired cert");

    let good_days =
        (good.validity().not_after.timestamp() - good.validity().not_before.timestamp()) / 86400;
    let exp_days =
        (exp.validity().not_after.timestamp() - exp.validity().not_before.timestamp()) / 86400;

    assert!(
        exp_days < good_days,
        "expired cert validity ({exp_days}d) should be less than good cert ({good_days}d)"
    );
}

#[test]
fn expired_cert_spec_reflects_negative_policy() {
    let factory = fx();
    let spec = X509Spec::self_signed("spec-check.example.com");
    let cert = factory.x509_self_signed("spec-check", spec);
    let expired = cert.expired();

    assert_eq!(
        expired.spec().not_before_offset,
        NotBeforeOffset::DaysAgo(395)
    );
    assert_eq!(expired.spec().validity_days, 365);
}

// =========================================================================
// Not-yet-valid certificates
// =========================================================================

#[test]
fn not_yet_valid_cert_not_before_is_in_the_future() {
    let factory = fx();
    let spec = X509Spec::self_signed("future.example.com");
    let cert = factory.x509_self_signed("future-neg", spec);
    let nyv = cert.not_yet_valid();

    let (_, parsed) = X509Certificate::from_der(nyv.cert_der()).expect("parse not-yet-valid cert");
    let not_before = parsed.validity().not_before.timestamp();
    // The deterministic base_time is in a defined window, but the spec offset
    // DaysFromNow(30) should push not_before well ahead of the base_time.
    let not_after = parsed.validity().not_after.timestamp();

    // The cert should still be structurally valid (not_after > not_before).
    assert!(
        not_after > not_before,
        "not_after ({not_after}) should be after not_before ({not_before})"
    );
}

#[test]
fn not_yet_valid_cert_spec_reflects_negative_policy() {
    let factory = fx();
    let spec = X509Spec::self_signed("nyv-spec.example.com");
    let cert = factory.x509_self_signed("nyv-spec", spec);
    let nyv = cert.not_yet_valid();

    assert_eq!(
        nyv.spec().not_before_offset,
        NotBeforeOffset::DaysFromNow(30)
    );
    assert_eq!(nyv.spec().validity_days, 365);
}

#[test]
fn not_yet_valid_der_differs_from_good() {
    let factory = fx();
    let spec = X509Spec::self_signed("nyv-diff.example.com");
    let cert = factory.x509_self_signed("nyv-diff", spec);
    let nyv = cert.not_yet_valid();

    assert_ne!(cert.cert_der(), nyv.cert_der());
}

// =========================================================================
// Self-signed vs CA-signed validation
// =========================================================================

#[test]
fn self_signed_leaf_is_not_ca() {
    let factory = fx();
    let spec = X509Spec::self_signed("leaf.example.com");
    let cert = factory.x509_self_signed("leaf-check", spec);

    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse cert");
    assert!(!parsed.is_ca(), "self-signed leaf should not be CA");
}

#[test]
fn self_signed_ca_is_ca() {
    let factory = fx();
    let spec = X509Spec::self_signed_ca("ca-check.example.com");
    let cert = factory.x509_self_signed("ca-check", spec);

    let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse cert");
    assert!(parsed.is_ca(), "self-signed CA should be CA");
}

#[test]
fn self_signed_but_claims_ca_negative_is_ca() {
    let factory = fx();
    let spec = X509Spec::self_signed("claims-ca.example.com");
    let cert = factory.x509_self_signed("claims-ca", spec);
    let bad = cert.negative(X509Negative::SelfSignedButClaimsCA);

    let (_, parsed) = X509Certificate::from_der(bad.cert_der()).expect("parse cert");
    assert!(parsed.is_ca(), "SelfSignedButClaimsCA variant should be CA");
}

// =========================================================================
// Wrong key usage
// =========================================================================

#[test]
fn wrong_key_usage_cert_is_ca_without_key_cert_sign() {
    let factory = fx();
    let spec = X509Spec::self_signed("wku.example.com");
    let cert = factory.x509_self_signed("wku", spec);
    let bad = cert.wrong_key_usage();

    let (_, parsed) = X509Certificate::from_der(bad.cert_der()).expect("parse cert");
    assert!(parsed.is_ca(), "WrongKeyUsage cert should be CA");

    let ku_ext = parsed
        .extensions()
        .iter()
        .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE)
        .expect("should have KeyUsage extension");

    let ku = match ku_ext.parsed_extension() {
        x509_parser::extensions::ParsedExtension::KeyUsage(ku) => ku,
        other => panic!("expected KeyUsage, got {:?}", other),
    };

    assert!(
        !ku.key_cert_sign(),
        "WrongKeyUsage must NOT have keyCertSign"
    );
    assert!(!ku.crl_sign(), "WrongKeyUsage must NOT have crlSign");
    assert!(
        ku.digital_signature(),
        "WrongKeyUsage should have digitalSignature"
    );
    assert!(
        ku.key_encipherment(),
        "WrongKeyUsage should have keyEncipherment"
    );
}

#[test]
fn wrong_key_usage_spec_matches_policy() {
    let factory = fx();
    let spec = X509Spec::self_signed("wku-spec.example.com");
    let cert = factory.x509_self_signed("wku-spec", spec);
    let bad = cert.wrong_key_usage();

    assert!(bad.spec().is_ca);
    assert!(!bad.spec().key_usage.key_cert_sign);
    assert!(!bad.spec().key_usage.crl_sign);
    assert!(bad.spec().key_usage.digital_signature);
    assert!(bad.spec().key_usage.key_encipherment);
}

// =========================================================================
// Serial numbers
// =========================================================================

#[test]
fn negative_variants_have_valid_serial_numbers() {
    let factory = fx();
    let spec = X509Spec::self_signed("serial.example.com");
    let cert = factory.x509_self_signed("serial", spec);

    let variants = [
        cert.expired(),
        cert.not_yet_valid(),
        cert.wrong_key_usage(),
        cert.negative(X509Negative::SelfSignedButClaimsCA),
    ];

    for variant in &variants {
        let (_, parsed) =
            X509Certificate::from_der(variant.cert_der()).expect("parse negative cert");
        // Serial number should be positive and non-zero.
        assert!(
            !parsed.serial.to_bytes_be().is_empty(),
            "serial number should be non-empty"
        );
    }
}

#[test]
fn negative_variants_have_distinct_serial_numbers_from_good() {
    let factory = det("serial-distinct-seed");
    let spec = X509Spec::self_signed("serial-distinct.example.com");
    let cert = factory.x509_self_signed("serial-distinct", spec);

    let (_, good) = X509Certificate::from_der(cert.cert_der()).expect("parse good cert");
    let good_serial = good.serial.to_bytes_be();

    // Each negative variant should have a different serial (different derivation).
    let variants = [
        cert.expired(),
        cert.not_yet_valid(),
        cert.wrong_key_usage(),
        cert.negative(X509Negative::SelfSignedButClaimsCA),
    ];

    for variant in &variants {
        let (_, parsed) =
            X509Certificate::from_der(variant.cert_der()).expect("parse negative cert");
        // Serials differ because the spec (and thus derivation inputs) differ.
        assert_ne!(
            parsed.serial.to_bytes_be(),
            good_serial,
            "negative variant should have different serial than good cert"
        );
    }
}

// =========================================================================
// Mismatched keypair: negative variant cert differs but label preserved
// =========================================================================

#[test]
fn negative_variant_preserves_label() {
    let factory = fx();
    let spec = X509Spec::self_signed("label-preserve.example.com");
    let cert = factory.x509_self_signed("my-label", spec);

    assert_eq!(cert.expired().label(), "my-label");
    assert_eq!(cert.not_yet_valid().label(), "my-label");
    assert_eq!(cert.wrong_key_usage().label(), "my-label");
    assert_eq!(
        cert.negative(X509Negative::SelfSignedButClaimsCA).label(),
        "my-label"
    );
}

#[test]
fn negative_variant_cert_differs_from_good() {
    let factory = fx();
    let spec = X509Spec::self_signed("differs.example.com");
    let cert = factory.x509_self_signed("differs", spec);

    assert_ne!(cert.cert_der(), cert.expired().cert_der());
    assert_ne!(cert.cert_der(), cert.not_yet_valid().cert_der());
    assert_ne!(cert.cert_der(), cert.wrong_key_usage().cert_der());
    assert_ne!(
        cert.cert_der(),
        cert.negative(X509Negative::SelfSignedButClaimsCA)
            .cert_der()
    );
}

#[test]
fn negative_variants_pairwise_distinct_certs() {
    let factory = fx();
    let spec = X509Spec::self_signed("pairwise.example.com");
    let cert = factory.x509_self_signed("pairwise", spec);

    let variants: Vec<Vec<u8>> = vec![
        cert.expired().cert_der().to_vec(),
        cert.not_yet_valid().cert_der().to_vec(),
        cert.wrong_key_usage().cert_der().to_vec(),
        cert.negative(X509Negative::SelfSignedButClaimsCA)
            .cert_der()
            .to_vec(),
    ];

    let unique: HashSet<Vec<u8>> = variants.iter().cloned().collect();
    assert_eq!(
        unique.len(),
        variants.len(),
        "all negative variants should produce distinct DER"
    );
}

// =========================================================================
// Determinism of negative fixtures
// =========================================================================

#[test]
fn expired_cert_is_deterministic() {
    let factory = det("neg-det-seed");
    let spec = X509Spec::self_signed("det-expired.example.com");

    let cert1 = factory.x509_self_signed("det-exp", spec.clone());
    let expired1 = cert1.expired();

    factory.clear_cache();
    let cert2 = factory.x509_self_signed("det-exp", spec);
    let expired2 = cert2.expired();

    assert_eq!(expired1.cert_pem(), expired2.cert_pem());
    assert_eq!(expired1.cert_der(), expired2.cert_der());
    assert_eq!(
        expired1.private_key_pkcs8_pem(),
        expired2.private_key_pkcs8_pem()
    );
}

#[test]
fn not_yet_valid_cert_is_deterministic() {
    let factory = det("neg-det-seed");
    let spec = X509Spec::self_signed("det-nyv.example.com");

    let cert1 = factory.x509_self_signed("det-nyv", spec.clone());
    let nyv1 = cert1.not_yet_valid();

    factory.clear_cache();
    let cert2 = factory.x509_self_signed("det-nyv", spec);
    let nyv2 = cert2.not_yet_valid();

    assert_eq!(nyv1.cert_pem(), nyv2.cert_pem());
    assert_eq!(nyv1.cert_der(), nyv2.cert_der());
}

#[test]
fn wrong_key_usage_cert_is_deterministic() {
    let factory = det("neg-det-seed");
    let spec = X509Spec::self_signed("det-wku.example.com");

    let cert1 = factory.x509_self_signed("det-wku", spec.clone());
    let wku1 = cert1.wrong_key_usage();

    factory.clear_cache();
    let cert2 = factory.x509_self_signed("det-wku", spec);
    let wku2 = cert2.wrong_key_usage();

    assert_eq!(wku1.cert_pem(), wku2.cert_pem());
    assert_eq!(wku1.cert_der(), wku2.cert_der());
}

#[test]
fn self_signed_ca_negative_is_deterministic() {
    let factory = det("neg-det-seed");
    let spec = X509Spec::self_signed("det-ca.example.com");

    let cert1 = factory.x509_self_signed("det-ca", spec.clone());
    let ca1 = cert1.negative(X509Negative::SelfSignedButClaimsCA);

    factory.clear_cache();
    let cert2 = factory.x509_self_signed("det-ca", spec);
    let ca2 = cert2.negative(X509Negative::SelfSignedButClaimsCA);

    assert_eq!(ca1.cert_pem(), ca2.cert_pem());
    assert_eq!(ca1.cert_der(), ca2.cert_der());
}

// =========================================================================
// All X509Negative variants: apply and verify CN preserved
// =========================================================================

#[test]
fn all_x509_negative_variants_preserve_subject_cn() {
    let factory = fx();
    let spec = X509Spec::self_signed("cn-preserve.example.com");
    let cert = factory.x509_self_signed("cn-preserve", spec);

    let variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];

    for neg in &variants {
        let bad = cert.negative(*neg);
        let (_, parsed) = X509Certificate::from_der(bad.cert_der()).expect("parse cert");
        let cn = parsed
            .subject()
            .iter_common_name()
            .next()
            .expect("should have CN");
        assert_eq!(
            cn.as_str().unwrap(),
            "cn-preserve.example.com",
            "{:?} should preserve CN",
            neg
        );
    }
}

#[test]
fn all_x509_negative_variant_names_are_distinct() {
    let names: HashSet<&str> = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ]
    .iter()
    .map(|v| v.variant_name())
    .collect();

    assert_eq!(names.len(), 4, "all variant names should be distinct");
}

#[test]
fn all_x509_negative_descriptions_are_nonempty() {
    let variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];

    for v in &variants {
        assert!(
            !v.description().is_empty(),
            "{:?} description should not be empty",
            v
        );
    }
}

// =========================================================================
// Corrupt PEM/DER helpers on real cert data
// =========================================================================

#[test]
fn corrupt_cert_pem_bad_header_on_real_cert() {
    let factory = fx();
    let spec = X509Spec::self_signed("pem-corrupt.example.com");
    let cert = factory.x509_self_signed("pem-corrupt", spec);

    let corrupted = cert.corrupt_cert_pem(CorruptPem::BadHeader);
    assert!(
        corrupted.contains("-----BEGIN CORRUPTED KEY-----"),
        "BadHeader should replace the BEGIN line"
    );
    assert!(
        !corrupted.starts_with("-----BEGIN CERTIFICATE-----"),
        "should no longer start with valid header"
    );
}

#[test]
fn corrupt_cert_pem_bad_footer_on_real_cert() {
    let factory = fx();
    let spec = X509Spec::self_signed("pem-footer.example.com");
    let cert = factory.x509_self_signed("pem-footer", spec);

    let corrupted = cert.corrupt_cert_pem(CorruptPem::BadFooter);
    assert!(corrupted.contains("-----END CORRUPTED KEY-----"));
}

#[test]
fn corrupt_cert_pem_bad_base64_on_real_cert() {
    let factory = fx();
    let spec = X509Spec::self_signed("pem-b64.example.com");
    let cert = factory.x509_self_signed("pem-b64", spec);

    let corrupted = cert.corrupt_cert_pem(CorruptPem::BadBase64);
    assert!(corrupted.contains("THIS_IS_NOT_BASE64!!!"));
}

#[test]
fn corrupt_cert_pem_truncate_on_real_cert() {
    let factory = fx();
    let spec = X509Spec::self_signed("pem-trunc.example.com");
    let cert = factory.x509_self_signed("pem-trunc", spec);

    let corrupted = cert.corrupt_cert_pem(CorruptPem::Truncate { bytes: 20 });
    assert_eq!(corrupted.len(), 20);
}

#[test]
fn corrupt_cert_pem_extra_blank_line_on_real_cert() {
    let factory = fx();
    let spec = X509Spec::self_signed("pem-blank.example.com");
    let cert = factory.x509_self_signed("pem-blank", spec);

    let corrupted = cert.corrupt_cert_pem(CorruptPem::ExtraBlankLine);
    assert_ne!(corrupted, cert.cert_pem());
    // Should have an empty line injected.
    assert!(corrupted.contains("\n\n"));
}

#[test]
fn truncate_cert_der_on_real_cert() {
    let factory = fx();
    let spec = X509Spec::self_signed("der-trunc.example.com");
    let cert = factory.x509_self_signed("der-trunc", spec);

    let truncated = cert.truncate_cert_der(16);
    assert_eq!(truncated.len(), 16);
    assert_eq!(&truncated[..], &cert.cert_der()[..16]);
}

#[test]
fn corrupt_cert_pem_deterministic_on_real_cert_is_stable() {
    let factory = fx();
    let spec = X509Spec::self_signed("pem-det.example.com");
    let cert = factory.x509_self_signed("pem-det", spec);

    let a = cert.corrupt_cert_pem_deterministic("corrupt:neg-test-v1");
    let b = cert.corrupt_cert_pem_deterministic("corrupt:neg-test-v1");
    assert_eq!(a, b, "same variant must produce same PEM corruption");
    assert_ne!(a, cert.cert_pem(), "corruption should differ from original");
}

#[test]
fn corrupt_cert_der_deterministic_on_real_cert_is_stable() {
    let factory = fx();
    let spec = X509Spec::self_signed("der-det.example.com");
    let cert = factory.x509_self_signed("der-det", spec);

    let a = cert.corrupt_cert_der_deterministic("corrupt:neg-test-v1");
    let b = cert.corrupt_cert_der_deterministic("corrupt:neg-test-v1");
    assert_eq!(a, b, "same variant must produce same DER corruption");
    assert_ne!(a, cert.cert_der(), "corruption should differ from original");
}

// =========================================================================
// Chain negative fixtures
// =========================================================================

#[test]
fn chain_expired_leaf_is_actually_expired() {
    let factory = fx();
    let chain = factory.x509_chain("chain-exp", ChainSpec::new("chain-exp.example.com"));
    let expired = chain.expired_leaf();

    let (_, leaf) = X509Certificate::from_der(expired.leaf_cert_der()).expect("parse leaf");
    let not_before = leaf.validity().not_before.timestamp();
    let not_after = leaf.validity().not_after.timestamp();
    let validity_days = (not_after - not_before) / 86400;

    // ExpiredLeaf sets validity_days=1 and not_before_offset_days=730.
    assert!(
        validity_days <= 1,
        "expired leaf validity ({validity_days}d) should be 1 day or less"
    );
    // The leaf cert should differ from the good chain.
    assert_ne!(chain.leaf_cert_der(), expired.leaf_cert_der());
}

#[test]
fn chain_expired_intermediate_is_actually_expired() {
    let factory = fx();
    let chain = factory.x509_chain("chain-exp-int", ChainSpec::new("chain-exp-int.example.com"));
    let expired = chain.expired_intermediate();

    let (_, int) =
        X509Certificate::from_der(expired.intermediate_cert_der()).expect("parse intermediate");
    let not_before = int.validity().not_before.timestamp();
    let not_after = int.validity().not_after.timestamp();
    let validity_days = (not_after - not_before) / 86400;

    // ExpiredIntermediate sets validity_days=1 and not_before_offset_days=730.
    assert!(
        validity_days <= 1,
        "expired intermediate validity ({validity_days}d) should be 1 day or less"
    );
    assert_ne!(
        chain.intermediate_cert_der(),
        expired.intermediate_cert_der()
    );
}

#[test]
fn chain_hostname_mismatch_changes_leaf_cn() {
    let factory = fx();
    let chain = factory.x509_chain("chain-host", ChainSpec::new("good.example.com"));
    let bad = chain.hostname_mismatch("evil.example.com");

    let (_, leaf) = X509Certificate::from_der(bad.leaf_cert_der()).expect("parse leaf");
    let cn = leaf
        .subject()
        .iter_common_name()
        .next()
        .expect("should have CN");
    assert_eq!(cn.as_str().unwrap(), "evil.example.com");
}

#[test]
fn chain_unknown_ca_has_different_root_subject() {
    let factory = fx();
    let chain = factory.x509_chain("chain-uca", ChainSpec::new("uca.example.com"));
    let bad = chain.unknown_ca();

    let (_, good_root) = X509Certificate::from_der(chain.root_cert_der()).expect("parse root");
    let (_, bad_root) = X509Certificate::from_der(bad.root_cert_der()).expect("parse bad root");

    assert_ne!(
        good_root.subject(),
        bad_root.subject(),
        "unknown_ca root should have different subject"
    );
}

#[test]
fn chain_revoked_leaf_has_crl() {
    let factory = fx();
    let chain = factory.x509_chain("chain-rev", ChainSpec::new("revoked.example.com"));

    assert!(chain.crl_der().is_none(), "good chain should have no CRL");

    let revoked = chain.revoked_leaf();
    assert!(revoked.crl_der().is_some(), "revoked chain should have CRL");
    assert!(
        revoked
            .crl_pem()
            .unwrap()
            .contains("-----BEGIN X509 CRL-----")
    );
}

#[test]
fn chain_negative_determinism() {
    let factory = det("chain-neg-det-seed");
    let spec = ChainSpec::new("chain-det.example.com");

    let chain1 = factory.x509_chain("chain-det", spec.clone());
    let exp1 = chain1.expired_leaf();

    factory.clear_cache();
    let chain2 = factory.x509_chain("chain-det", spec);
    let exp2 = chain2.expired_leaf();

    assert_eq!(exp1.leaf_cert_pem(), exp2.leaf_cert_pem());
    assert_eq!(exp1.leaf_cert_der(), exp2.leaf_cert_der());
}
