use std::time::Duration;

use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

// ---------------------------------------------------------------------------
// X509Spec — construction and defaults
// ---------------------------------------------------------------------------

#[test]
fn self_signed_sets_subject_and_issuer() {
    let spec = X509Spec::self_signed("myapp.example.com");
    assert_eq!(spec.subject_cn, "myapp.example.com");
    assert_eq!(spec.issuer_cn, "myapp.example.com");
    assert!(!spec.is_ca);
}

#[test]
fn self_signed_ca_sets_ca_flags() {
    let ca = X509Spec::self_signed_ca("Test Root CA");
    assert!(ca.is_ca);
    assert!(ca.key_usage.key_cert_sign);
    assert!(ca.key_usage.crl_sign);
    assert!(ca.key_usage.digital_signature);
    assert!(!ca.key_usage.key_encipherment);
}

#[test]
fn default_spec_values() {
    let spec = X509Spec::default();
    assert_eq!(spec.validity_days, 3650);
    assert_eq!(spec.rsa_bits, 2048);
    assert!(!spec.is_ca);
    assert!(spec.sans.is_empty());
    assert_eq!(spec.not_before_offset, NotBeforeOffset::DaysAgo(1));
}

// ---------------------------------------------------------------------------
// X509Spec — builder chain
// ---------------------------------------------------------------------------

#[test]
fn builder_chain_applies_all_fields() {
    let spec = X509Spec::self_signed("builder.test")
        .with_validity_days(90)
        .with_not_before(NotBeforeOffset::DaysFromNow(7))
        .with_rsa_bits(4096)
        .with_key_usage(KeyUsage::ca())
        .with_is_ca(true)
        .with_sans(vec!["a.test".into(), "b.test".into()]);

    assert_eq!(spec.validity_days, 90);
    assert_eq!(spec.not_before_offset, NotBeforeOffset::DaysFromNow(7));
    assert_eq!(spec.rsa_bits, 4096);
    assert!(spec.is_ca);
    assert!(spec.key_usage.key_cert_sign);
    assert_eq!(spec.sans, vec!["a.test", "b.test"]);
}

// ---------------------------------------------------------------------------
// KeyUsage
// ---------------------------------------------------------------------------

#[test]
fn key_usage_leaf_defaults() {
    let ku = KeyUsage::leaf();
    assert!(!ku.key_cert_sign);
    assert!(!ku.crl_sign);
    assert!(ku.digital_signature);
    assert!(ku.key_encipherment);
}

#[test]
fn key_usage_ca_defaults() {
    let ku = KeyUsage::ca();
    assert!(ku.key_cert_sign);
    assert!(ku.crl_sign);
    assert!(ku.digital_signature);
    assert!(!ku.key_encipherment);
}

#[test]
fn key_usage_default_is_leaf() {
    assert_eq!(KeyUsage::default(), KeyUsage::leaf());
}

#[test]
fn key_usage_stable_bytes_leaf_vs_ca_differ() {
    assert_ne!(
        KeyUsage::leaf().stable_bytes(),
        KeyUsage::ca().stable_bytes()
    );
}

// ---------------------------------------------------------------------------
// X509Spec — stable_bytes determinism
// ---------------------------------------------------------------------------

#[test]
fn stable_bytes_deterministic() {
    let spec = X509Spec::self_signed("determinism-test");
    assert_eq!(spec.stable_bytes(), spec.stable_bytes());
}

#[test]
fn stable_bytes_different_cn_differ() {
    let a = X509Spec::self_signed("alpha.test");
    let b = X509Spec::self_signed("beta.test");
    assert_ne!(a.stable_bytes(), b.stable_bytes());
}

#[test]
fn stable_bytes_san_order_independent() {
    let a = X509Spec::self_signed("test").with_sans(vec!["z.test".into(), "a.test".into()]);
    let b = X509Spec::self_signed("test").with_sans(vec!["a.test".into(), "z.test".into()]);
    assert_eq!(a.stable_bytes(), b.stable_bytes());
}

#[test]
fn stable_bytes_deduplicates_sans() {
    let with_dupes = X509Spec::self_signed("test").with_sans(vec![
        "a.test".into(),
        "a.test".into(),
        "b.test".into(),
    ]);
    let without_dupes =
        X509Spec::self_signed("test").with_sans(vec!["a.test".into(), "b.test".into()]);
    assert_eq!(with_dupes.stable_bytes(), without_dupes.stable_bytes());
}

#[test]
fn stable_bytes_each_field_matters() {
    let base = X509Spec::self_signed("test");
    let base_bytes = base.stable_bytes();

    let changes: Vec<(&str, X509Spec)> = vec![
        ("validity_days", base.clone().with_validity_days(999)),
        ("is_ca", base.clone().with_is_ca(true)),
        ("rsa_bits", base.clone().with_rsa_bits(4096)),
        (
            "not_before_offset",
            base.clone()
                .with_not_before(NotBeforeOffset::DaysFromNow(7)),
        ),
        ("key_usage", base.clone().with_key_usage(KeyUsage::ca())),
        ("sans", base.clone().with_sans(vec!["extra.test".into()])),
    ];

    for (field, changed) in changes {
        assert_ne!(
            changed.stable_bytes(),
            base_bytes,
            "{field} must affect stable_bytes"
        );
    }
}

#[test]
fn stable_bytes_issuer_cn_matters() {
    let mut spec = X509Spec::self_signed("test");
    let base_bytes = spec.stable_bytes();
    spec.issuer_cn = "Other Issuer".to_string();
    assert_ne!(spec.stable_bytes(), base_bytes);
}

#[test]
fn stable_bytes_not_before_variants_differ() {
    let ago = X509Spec::self_signed("test").with_not_before(NotBeforeOffset::DaysAgo(1));
    let future = X509Spec::self_signed("test").with_not_before(NotBeforeOffset::DaysFromNow(1));
    assert_ne!(ago.stable_bytes(), future.stable_bytes());
}

// ---------------------------------------------------------------------------
// X509Spec — duration helpers
// ---------------------------------------------------------------------------

#[test]
fn not_before_duration_days_ago() {
    let spec = X509Spec::self_signed("test").with_not_before(NotBeforeOffset::DaysAgo(3));
    assert_eq!(
        spec.not_before_duration(),
        Duration::from_secs(3 * 24 * 60 * 60)
    );
}

#[test]
fn not_before_duration_days_from_now_is_zero() {
    let spec = X509Spec::self_signed("test").with_not_before(NotBeforeOffset::DaysFromNow(3));
    assert_eq!(spec.not_before_duration(), Duration::ZERO);
}

#[test]
fn not_after_duration_days_ago() {
    let spec = X509Spec::self_signed("test")
        .with_not_before(NotBeforeOffset::DaysAgo(1))
        .with_validity_days(30);
    assert_eq!(
        spec.not_after_duration(),
        Duration::from_secs(30 * 24 * 60 * 60)
    );
}

#[test]
fn not_after_duration_days_from_now() {
    let spec = X509Spec::self_signed("test")
        .with_not_before(NotBeforeOffset::DaysFromNow(5))
        .with_validity_days(30);
    assert_eq!(
        spec.not_after_duration(),
        Duration::from_secs((5 + 30) * 24 * 60 * 60)
    );
}

// ---------------------------------------------------------------------------
// ChainSpec — construction and defaults
// ---------------------------------------------------------------------------

#[test]
fn chain_spec_defaults() {
    let cs = ChainSpec::new("test.example.com");
    assert_eq!(cs.leaf_cn, "test.example.com");
    assert_eq!(cs.leaf_sans, vec!["test.example.com"]);
    assert_eq!(cs.root_cn, "test.example.com Root CA");
    assert_eq!(cs.intermediate_cn, "test.example.com Intermediate CA");
    assert_eq!(cs.rsa_bits, 2048);
    assert_eq!(cs.root_validity_days, 3650);
    assert_eq!(cs.intermediate_validity_days, 1825);
    assert_eq!(cs.leaf_validity_days, 3650);
    assert!(cs.leaf_not_before.is_none());
    assert!(cs.intermediate_not_before.is_none());
}

#[test]
fn chain_spec_builder_chain() {
    let cs = ChainSpec::new("example.com")
        .with_sans(vec!["example.com".into(), "www.example.com".into()])
        .with_root_cn("Custom Root")
        .with_intermediate_cn("Custom Int")
        .with_rsa_bits(4096)
        .with_root_validity_days(7300)
        .with_intermediate_validity_days(3650)
        .with_leaf_validity_days(90);

    assert_eq!(cs.leaf_sans.len(), 2);
    assert_eq!(cs.root_cn, "Custom Root");
    assert_eq!(cs.intermediate_cn, "Custom Int");
    assert_eq!(cs.rsa_bits, 4096);
    assert_eq!(cs.root_validity_days, 7300);
    assert_eq!(cs.intermediate_validity_days, 3650);
    assert_eq!(cs.leaf_validity_days, 90);
}

// ---------------------------------------------------------------------------
// ChainSpec — stable_bytes
// ---------------------------------------------------------------------------

#[test]
fn chain_stable_bytes_deterministic() {
    let cs = ChainSpec::new("test.example.com");
    assert_eq!(cs.stable_bytes(), cs.stable_bytes());
}

#[test]
fn chain_stable_bytes_different_leaf_cn_differ() {
    let a = ChainSpec::new("alpha.test");
    let b = ChainSpec::new("beta.test");
    assert_ne!(a.stable_bytes(), b.stable_bytes());
}

#[test]
fn chain_stable_bytes_san_order_independent() {
    let a = ChainSpec::new("test").with_sans(vec!["z.test".into(), "a.test".into()]);
    let b = ChainSpec::new("test").with_sans(vec!["a.test".into(), "z.test".into()]);
    assert_eq!(a.stable_bytes(), b.stable_bytes());
}

#[test]
fn chain_stable_bytes_each_field_matters() {
    let base = ChainSpec::new("test.example.com");
    let base_bytes = base.stable_bytes();

    let changes: Vec<(&str, ChainSpec)> = vec![
        ("rsa_bits", base.clone().with_rsa_bits(4096)),
        (
            "root_validity_days",
            base.clone().with_root_validity_days(999),
        ),
        (
            "intermediate_validity_days",
            base.clone().with_intermediate_validity_days(999),
        ),
        (
            "leaf_validity_days",
            base.clone().with_leaf_validity_days(999),
        ),
        ("root_cn", base.clone().with_root_cn("Other Root")),
        (
            "intermediate_cn",
            base.clone().with_intermediate_cn("Other Int"),
        ),
        (
            "leaf_sans",
            base.clone().with_sans(vec!["extra.example.com".into()]),
        ),
    ];

    for (field, changed) in changes {
        assert_ne!(
            changed.stable_bytes(),
            base_bytes,
            "{field} must affect stable_bytes"
        );
    }
}

#[test]
fn chain_stable_bytes_optional_offsets_matter() {
    let base = ChainSpec::new("test.example.com");
    let base_bytes = base.stable_bytes();

    let mut with_leaf_offset = base.clone();
    with_leaf_offset.leaf_not_before = Some(NotBeforeOffset::DaysAgo(100));
    assert_ne!(with_leaf_offset.stable_bytes(), base_bytes);

    let mut with_int_offset = base.clone();
    with_int_offset.intermediate_not_before = Some(NotBeforeOffset::DaysAgo(100));
    assert_ne!(with_int_offset.stable_bytes(), base_bytes);

    // Different offset values differ from each other
    let mut offset_200 = base.clone();
    offset_200.leaf_not_before = Some(NotBeforeOffset::DaysAgo(200));
    assert_ne!(with_leaf_offset.stable_bytes(), offset_200.stable_bytes());
}
