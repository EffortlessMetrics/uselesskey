//! Integration tests for uselesskey-core-x509-spec.
//!
//! Tests the X509Spec, ChainSpec, KeyUsage, and NotBeforeOffset types
//! from the perspective of an external consumer.

use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

#[test]
fn x509_spec_stable_bytes_version_prefix() {
    let spec = X509Spec::self_signed("test");
    let bytes = spec.stable_bytes();
    assert_eq!(bytes[0], 4, "stable_bytes version prefix should be 4");
}

#[test]
fn chain_spec_stable_bytes_version_prefix() {
    let spec = ChainSpec::new("test.example.com");
    let bytes = spec.stable_bytes();
    assert_eq!(bytes[0], 2, "stable_bytes version prefix should be 2");
}

#[test]
fn x509_spec_ca_vs_leaf_different_stable_bytes() {
    let leaf = X509Spec::self_signed("test");
    let ca = X509Spec::self_signed_ca("test");

    assert_ne!(
        leaf.stable_bytes(),
        ca.stable_bytes(),
        "CA and leaf specs must produce different stable_bytes"
    );
}

#[test]
fn key_usage_stable_bytes_encoding() {
    let leaf = KeyUsage::leaf();
    let bytes = leaf.stable_bytes();
    assert_eq!(bytes, [0, 0, 1, 1]);

    let ca = KeyUsage::ca();
    let bytes = ca.stable_bytes();
    assert_eq!(bytes, [1, 1, 1, 0]);
}

#[test]
fn chain_spec_defaults_are_sensible() {
    let spec = ChainSpec::new("myapp.example.com");
    assert_eq!(spec.leaf_cn, "myapp.example.com");
    assert_eq!(spec.leaf_sans, vec!["myapp.example.com"]);
    assert!(spec.root_cn.contains("Root CA"));
    assert!(spec.intermediate_cn.contains("Intermediate CA"));
    assert_eq!(spec.rsa_bits, 2048);
}

#[test]
fn x509_spec_not_before_duration_days_ago() {
    let spec = X509Spec::self_signed("test").with_not_before(NotBeforeOffset::DaysAgo(10));
    let dur = spec.not_before_duration();
    let expected_secs = 10u64 * 24 * 60 * 60;
    assert_eq!(dur.as_secs(), expected_secs);
}

#[test]
fn x509_spec_not_before_duration_days_from_now() {
    let spec = X509Spec::self_signed("test").with_not_before(NotBeforeOffset::DaysFromNow(10));
    let dur = spec.not_before_duration();
    assert_eq!(dur.as_secs(), 0);
}

#[test]
fn x509_spec_not_after_duration_includes_offset() {
    let spec = X509Spec::self_signed("test")
        .with_not_before(NotBeforeOffset::DaysFromNow(5))
        .with_validity_days(30);

    let dur = spec.not_after_duration();
    let expected_secs = (5u64 + 30) * 24 * 60 * 60;
    assert_eq!(dur.as_secs(), expected_secs);
}

#[test]
fn chain_spec_stable_bytes_deduplicates_sans() {
    let with_dupes = ChainSpec::new("test.example.com").with_sans(vec![
        "a.com".into(),
        "a.com".into(),
        "b.com".into(),
    ]);
    let without_dupes =
        ChainSpec::new("test.example.com").with_sans(vec!["a.com".into(), "b.com".into()]);
    assert_eq!(with_dupes.stable_bytes(), without_dupes.stable_bytes());
}

#[test]
fn chain_spec_stable_bytes_san_order_independent() {
    let ordered =
        ChainSpec::new("test.example.com").with_sans(vec!["a.com".into(), "b.com".into()]);
    let reversed =
        ChainSpec::new("test.example.com").with_sans(vec!["b.com".into(), "a.com".into()]);
    assert_eq!(ordered.stable_bytes(), reversed.stable_bytes());
}

#[test]
fn chain_spec_not_before_offsets() {
    let mut spec = ChainSpec::new("test.example.com");
    assert!(spec.leaf_not_before_offset_days.is_none());
    assert!(spec.intermediate_not_before_offset_days.is_none());

    spec.leaf_not_before_offset_days = Some(730);
    spec.intermediate_not_before_offset_days = Some(365);

    let bytes = spec.stable_bytes();
    assert!(!bytes.is_empty());
}
