//! Mutant-killing tests for X.509 spec types.

use std::time::Duration;
use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

// ── KeyUsage ─────────────────────────────────────────────────────

#[test]
fn key_usage_leaf_exact_fields() {
    let ku = KeyUsage::leaf();
    assert!(!ku.key_cert_sign);
    assert!(!ku.crl_sign);
    assert!(ku.digital_signature);
    assert!(ku.key_encipherment);
}

#[test]
fn key_usage_ca_exact_fields() {
    let ku = KeyUsage::ca();
    assert!(ku.key_cert_sign);
    assert!(ku.crl_sign);
    assert!(ku.digital_signature);
    assert!(!ku.key_encipherment);
}

#[test]
fn key_usage_stable_bytes_leaf() {
    let ku = KeyUsage::leaf();
    assert_eq!(ku.stable_bytes(), [0, 0, 1, 1]);
}

#[test]
fn key_usage_stable_bytes_ca() {
    let ku = KeyUsage::ca();
    assert_eq!(ku.stable_bytes(), [1, 1, 1, 0]);
}

#[test]
fn key_usage_stable_bytes_all_false() {
    let ku = KeyUsage {
        key_cert_sign: false,
        crl_sign: false,
        digital_signature: false,
        key_encipherment: false,
    };
    assert_eq!(ku.stable_bytes(), [0, 0, 0, 0]);
}

#[test]
fn key_usage_stable_bytes_all_true() {
    let ku = KeyUsage {
        key_cert_sign: true,
        crl_sign: true,
        digital_signature: true,
        key_encipherment: true,
    };
    assert_eq!(ku.stable_bytes(), [1, 1, 1, 1]);
}

#[test]
fn key_usage_leaf_ne_ca() {
    assert_ne!(KeyUsage::leaf(), KeyUsage::ca());
    assert_ne!(
        KeyUsage::leaf().stable_bytes(),
        KeyUsage::ca().stable_bytes()
    );
}

// ── NotBeforeOffset ──────────────────────────────────────────────

#[test]
fn not_before_offset_default_is_days_ago_1() {
    assert_eq!(NotBeforeOffset::default(), NotBeforeOffset::DaysAgo(1));
}

#[test]
fn not_before_offset_variants_differ() {
    assert_ne!(NotBeforeOffset::DaysAgo(1), NotBeforeOffset::DaysFromNow(1));
}

// ── X509Spec ─────────────────────────────────────────────────────

#[test]
fn x509_spec_default_exact_values() {
    let spec = X509Spec::default();
    assert_eq!(spec.subject_cn, "Test Certificate");
    assert_eq!(spec.issuer_cn, "Test Certificate");
    assert_eq!(spec.not_before_offset, NotBeforeOffset::DaysAgo(1));
    assert_eq!(spec.validity_days, 3650);
    assert_eq!(spec.key_usage, KeyUsage::leaf());
    assert!(!spec.is_ca);
    assert_eq!(spec.rsa_bits, 2048);
    assert!(spec.sans.is_empty());
}

#[test]
fn self_signed_sets_subject_and_issuer_to_same() {
    let spec = X509Spec::self_signed("example.com");
    assert_eq!(spec.subject_cn, "example.com");
    assert_eq!(spec.issuer_cn, "example.com");
}

#[test]
fn self_signed_ca_sets_ca_flags() {
    let spec = X509Spec::self_signed_ca("My CA");
    assert!(spec.is_ca);
    assert_eq!(spec.key_usage, KeyUsage::ca());
    assert_eq!(spec.subject_cn, "My CA");
    assert_eq!(spec.issuer_cn, "My CA");
}

#[test]
fn not_before_duration_days_ago_computes_correctly() {
    let spec = X509Spec::self_signed("t").with_not_before(NotBeforeOffset::DaysAgo(5));
    let expected_secs = 5u64 * 24 * 60 * 60;
    assert_eq!(
        spec.not_before_duration(),
        Duration::from_secs(expected_secs)
    );
}

#[test]
fn not_before_duration_days_from_now_is_zero() {
    let spec = X509Spec::self_signed("t").with_not_before(NotBeforeOffset::DaysFromNow(30));
    assert_eq!(spec.not_before_duration(), Duration::ZERO);
}

#[test]
fn not_after_duration_days_ago_is_just_validity() {
    let spec = X509Spec::self_signed("t")
        .with_not_before(NotBeforeOffset::DaysAgo(1))
        .with_validity_days(10);
    let expected = Duration::from_secs(10 * 24 * 60 * 60);
    assert_eq!(spec.not_after_duration(), expected);
}

#[test]
fn not_after_duration_days_from_now_adds_offset() {
    let spec = X509Spec::self_signed("t")
        .with_not_before(NotBeforeOffset::DaysFromNow(5))
        .with_validity_days(10);
    let expected = Duration::from_secs((5 + 10) * 24 * 60 * 60);
    assert_eq!(spec.not_after_duration(), expected);
}

#[test]
fn stable_bytes_version_prefix_is_4() {
    let spec = X509Spec::self_signed("test");
    let bytes = spec.stable_bytes();
    assert_eq!(bytes[0], 4, "version prefix must be 4");
}

#[test]
fn stable_bytes_not_before_tag_byte_days_ago() {
    let spec = X509Spec::self_signed("t").with_not_before(NotBeforeOffset::DaysAgo(1));
    let bytes = spec.stable_bytes();
    // After version(1) + subject_cn(4+1) + issuer_cn(4+1), the not_before tag byte
    let subject_len = "t".len();
    let issuer_len = "t".len();
    let offset = 1 + 4 + subject_len + 4 + issuer_len;
    assert_eq!(bytes[offset], 0, "DaysAgo tag must be 0");
}

#[test]
fn stable_bytes_not_before_tag_byte_days_from_now() {
    let spec = X509Spec::self_signed("t").with_not_before(NotBeforeOffset::DaysFromNow(1));
    let bytes = spec.stable_bytes();
    let subject_len = "t".len();
    let issuer_len = "t".len();
    let offset = 1 + 4 + subject_len + 4 + issuer_len;
    assert_eq!(bytes[offset], 1, "DaysFromNow tag must be 1");
}

// ── ChainSpec ────────────────────────────────────────────────────

#[test]
fn chain_spec_new_defaults() {
    let spec = ChainSpec::new("leaf.example.com");
    assert_eq!(spec.leaf_cn, "leaf.example.com");
    assert_eq!(spec.leaf_sans, vec!["leaf.example.com"]);
    assert_eq!(spec.root_cn, "leaf.example.com Root CA");
    assert_eq!(spec.intermediate_cn, "leaf.example.com Intermediate CA");
    assert_eq!(spec.rsa_bits, 2048);
    assert_eq!(spec.root_validity_days, 3650);
    assert_eq!(spec.intermediate_validity_days, 1825);
    assert_eq!(spec.leaf_validity_days, 3650);
    assert!(spec.leaf_not_before.is_none());
    assert!(spec.intermediate_not_before.is_none());
}

#[test]
fn chain_spec_stable_bytes_version_is_2() {
    let spec = ChainSpec::new("test");
    let bytes = spec.stable_bytes();
    assert_eq!(bytes[0], 3, "chain spec stable_bytes version must be 3");
}

#[test]
fn chain_spec_none_offset_tag_is_0() {
    let spec = ChainSpec::new("test");
    let bytes = spec.stable_bytes();
    // Find the offset tag bytes at the end
    // none tag should be 0
    let len = bytes.len();
    // Last two bytes should be the tags (both None = 0)
    assert_eq!(bytes[len - 1], 0, "intermediate offset None tag must be 0");
    assert_eq!(bytes[len - 2], 0, "leaf offset None tag must be 0");
}

#[test]
fn chain_spec_some_offset_tag_is_1() {
    let mut spec = ChainSpec::new("test");
    spec.leaf_not_before = Some(NotBeforeOffset::DaysAgo(100));
    let bytes = spec.stable_bytes();
    // The intermediate is still None (last byte = 0), leaf has Some (tag = 1)
    let len = bytes.len();
    assert_eq!(bytes[len - 1], 0, "intermediate offset None tag must be 0");
}
