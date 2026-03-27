//! Additional X509Spec and ChainSpec validation tests.
//!
//! Covers edge cases and cross-cutting concerns not in existing tests:
//! - Spec equality semantics (same fields → equal)
//! - ChainSpec with_sans overrides the auto-added leaf_cn
//! - stable_bytes length encoding prevents confusion between fields
//! - Zero-day validity and zero-RSA-bits edge cases

use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

// =========================================================================
// X509Spec: equality and hashing
// =========================================================================

#[test]
fn equal_specs_produce_equal_stable_bytes() {
    let a = X509Spec::self_signed("test.example.com")
        .with_validity_days(90)
        .with_sans(vec!["a.com".into()]);
    let b = X509Spec::self_signed("test.example.com")
        .with_validity_days(90)
        .with_sans(vec!["a.com".into()]);

    assert_eq!(a, b);
    assert_eq!(a.stable_bytes(), b.stable_bytes());
}

#[test]
fn spec_with_different_issuer_cn_not_equal() {
    let a = X509Spec::self_signed("test");
    let mut b = X509Spec::self_signed("test");
    b.issuer_cn = "different".to_string();

    assert_ne!(a, b);
    assert_ne!(a.stable_bytes(), b.stable_bytes());
}

// =========================================================================
// ChainSpec: with_sans overrides auto-added leaf_cn
// =========================================================================

#[test]
fn with_sans_replaces_default_leaf_cn() {
    let spec = ChainSpec::new("test.example.com").with_sans(vec!["other.example.com".to_string()]);

    assert_eq!(spec.leaf_sans, vec!["other.example.com"]);
    // Note: leaf_cn is still "test.example.com", but leaf_sans no longer contains it
    assert_eq!(spec.leaf_cn, "test.example.com");
}

#[test]
fn chain_spec_with_empty_sans() {
    let spec = ChainSpec::new("test.example.com").with_sans(vec![]);
    assert!(spec.leaf_sans.is_empty());
}

// =========================================================================
// stable_bytes: version prefix present
// =========================================================================

#[test]
fn x509_spec_stable_bytes_has_version_4() {
    let spec = X509Spec::self_signed("test");
    assert_eq!(spec.stable_bytes()[0], 4);
}

#[test]
fn chain_spec_stable_bytes_has_version_3() {
    let spec = ChainSpec::new("test");
    assert_eq!(spec.stable_bytes()[0], 3);
}

// =========================================================================
// stable_bytes: length encoding prevents field confusion
// =========================================================================

#[test]
fn stable_bytes_different_length_cns_differ() {
    let short = X509Spec::self_signed("a");
    let long = X509Spec::self_signed("aaaa");
    assert_ne!(short.stable_bytes(), long.stable_bytes());
}

#[test]
fn chain_stable_bytes_different_length_cns_differ() {
    let short = ChainSpec::new("a");
    let long = ChainSpec::new("aaaa");
    assert_ne!(short.stable_bytes(), long.stable_bytes());
}

// =========================================================================
// KeyUsage: custom combinations
// =========================================================================

#[test]
fn custom_key_usage_stable_bytes() {
    let ku = KeyUsage {
        key_cert_sign: true,
        crl_sign: false,
        digital_signature: false,
        key_encipherment: true,
    };
    assert_eq!(ku.stable_bytes(), [1, 0, 0, 1]);
}

#[test]
fn all_false_key_usage() {
    let ku = KeyUsage {
        key_cert_sign: false,
        crl_sign: false,
        digital_signature: false,
        key_encipherment: false,
    };
    assert_eq!(ku.stable_bytes(), [0, 0, 0, 0]);
}

#[test]
fn all_true_key_usage() {
    let ku = KeyUsage {
        key_cert_sign: true,
        crl_sign: true,
        digital_signature: true,
        key_encipherment: true,
    };
    assert_eq!(ku.stable_bytes(), [1, 1, 1, 1]);
}

// =========================================================================
// NotBeforeOffset: edge cases
// =========================================================================

#[test]
fn not_before_offset_default_is_days_ago_1() {
    assert_eq!(NotBeforeOffset::default(), NotBeforeOffset::DaysAgo(1));
}

#[test]
fn days_ago_zero() {
    let spec = X509Spec::self_signed("test").with_not_before(NotBeforeOffset::DaysAgo(0));
    assert_eq!(spec.not_before_duration(), std::time::Duration::ZERO);
}

#[test]
fn days_from_now_zero() {
    let spec = X509Spec::self_signed("test").with_not_before(NotBeforeOffset::DaysFromNow(0));
    assert_eq!(spec.not_before_duration(), std::time::Duration::ZERO);
    assert_eq!(
        spec.not_after_duration(),
        std::time::Duration::from_secs(spec.validity_days as u64 * 86400)
    );
}

// =========================================================================
// ChainSpec: not_before_offset_days encoding in stable_bytes
// =========================================================================

#[test]
fn chain_stable_bytes_leaf_offset_none_vs_some_differ() {
    let base = ChainSpec::new("test");
    let mut with_offset = base.clone();
    with_offset.leaf_not_before = Some(NotBeforeOffset::DaysAgo(1));
    assert_ne!(base.stable_bytes(), with_offset.stable_bytes());
}

#[test]
fn chain_stable_bytes_intermediate_offset_none_vs_some_differ() {
    let base = ChainSpec::new("test");
    let mut with_offset = base.clone();
    with_offset.intermediate_not_before = Some(NotBeforeOffset::DaysAgo(1));
    assert_ne!(base.stable_bytes(), with_offset.stable_bytes());
}

#[test]
fn chain_stable_bytes_both_offsets_set_differs_from_one() {
    let mut one = ChainSpec::new("test");
    one.leaf_not_before = Some(NotBeforeOffset::DaysAgo(100));

    let mut both = one.clone();
    both.intermediate_not_before = Some(NotBeforeOffset::DaysAgo(200));

    assert_ne!(one.stable_bytes(), both.stable_bytes());
}
