use std::time::Duration;

use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

// ---------------------------------------------------------------------------
// X509Spec – construction and defaults
// ---------------------------------------------------------------------------

#[test]
fn default_spec_has_expected_values() {
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
fn self_signed_sets_subject_and_issuer_to_same_cn() {
    let spec = X509Spec::self_signed("my-service.example.com");
    assert_eq!(spec.subject_cn, "my-service.example.com");
    assert_eq!(spec.issuer_cn, "my-service.example.com");
    assert!(!spec.is_ca);
    assert_eq!(spec.key_usage, KeyUsage::leaf());
}

#[test]
fn self_signed_ca_sets_ca_flags() {
    let spec = X509Spec::self_signed_ca("Root CA");
    assert_eq!(spec.subject_cn, "Root CA");
    assert_eq!(spec.issuer_cn, "Root CA");
    assert!(spec.is_ca);
    assert_eq!(spec.key_usage, KeyUsage::ca());
}

// ---------------------------------------------------------------------------
// X509Spec – builder chain
// ---------------------------------------------------------------------------

#[test]
fn builder_methods_are_chainable_and_apply() {
    let spec = X509Spec::self_signed("builder.test")
        .with_validity_days(365)
        .with_not_before(NotBeforeOffset::DaysFromNow(10))
        .with_rsa_bits(4096)
        .with_key_usage(KeyUsage::ca())
        .with_is_ca(true)
        .with_sans(vec!["a.test".into(), "b.test".into()]);

    assert_eq!(spec.validity_days, 365);
    assert_eq!(spec.not_before_offset, NotBeforeOffset::DaysFromNow(10));
    assert_eq!(spec.rsa_bits, 4096);
    assert!(spec.is_ca);
    assert_eq!(spec.key_usage, KeyUsage::ca());
    assert_eq!(spec.sans, vec!["a.test", "b.test"]);
}

#[test]
fn with_sans_replaces_previous_sans() {
    let spec = X509Spec::self_signed("test")
        .with_sans(vec!["first.test".into()])
        .with_sans(vec!["second.test".into()]);

    assert_eq!(spec.sans, vec!["second.test"]);
}

// ---------------------------------------------------------------------------
// KeyUsage – construction and encoding
// ---------------------------------------------------------------------------

#[test]
fn key_usage_default_equals_leaf() {
    assert_eq!(KeyUsage::default(), KeyUsage::leaf());
}

#[test]
fn key_usage_leaf_flags() {
    let ku = KeyUsage::leaf();
    assert!(!ku.key_cert_sign);
    assert!(!ku.crl_sign);
    assert!(ku.digital_signature);
    assert!(ku.key_encipherment);
}

#[test]
fn key_usage_ca_flags() {
    let ku = KeyUsage::ca();
    assert!(ku.key_cert_sign);
    assert!(ku.crl_sign);
    assert!(ku.digital_signature);
    assert!(!ku.key_encipherment);
}

#[test]
fn key_usage_stable_bytes_leaf_and_ca_differ() {
    assert_ne!(
        KeyUsage::leaf().stable_bytes(),
        KeyUsage::ca().stable_bytes()
    );
}

#[test]
fn key_usage_stable_bytes_encodes_each_flag() {
    let ku = KeyUsage {
        key_cert_sign: true,
        crl_sign: false,
        digital_signature: true,
        key_encipherment: false,
    };
    assert_eq!(ku.stable_bytes(), [1, 0, 1, 0]);
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

// ---------------------------------------------------------------------------
// NotBeforeOffset – default
// ---------------------------------------------------------------------------

#[test]
fn not_before_offset_default_is_days_ago_1() {
    assert_eq!(NotBeforeOffset::default(), NotBeforeOffset::DaysAgo(1));
}

// ---------------------------------------------------------------------------
// X509Spec – duration helpers
// ---------------------------------------------------------------------------

const DAY_SECS: u64 = 24 * 60 * 60;

#[test]
fn not_before_duration_days_ago() {
    let spec = X509Spec::self_signed("t").with_not_before(NotBeforeOffset::DaysAgo(5));
    assert_eq!(
        spec.not_before_duration(),
        Duration::from_secs(5 * DAY_SECS)
    );
}

#[test]
fn not_before_duration_days_from_now_is_zero() {
    let spec = X509Spec::self_signed("t").with_not_before(NotBeforeOffset::DaysFromNow(5));
    assert_eq!(spec.not_before_duration(), Duration::ZERO);
}

#[test]
fn not_after_duration_with_days_ago_offset() {
    let spec = X509Spec::self_signed("t")
        .with_not_before(NotBeforeOffset::DaysAgo(2))
        .with_validity_days(30);
    // DaysAgo → base = ZERO, so not_after = 30 days
    assert_eq!(
        spec.not_after_duration(),
        Duration::from_secs(30 * DAY_SECS)
    );
}

#[test]
fn not_after_duration_with_days_from_now_offset() {
    let spec = X509Spec::self_signed("t")
        .with_not_before(NotBeforeOffset::DaysFromNow(10))
        .with_validity_days(30);
    // DaysFromNow(10) → base = 10 days, not_after = 10 + 30 = 40 days
    assert_eq!(
        spec.not_after_duration(),
        Duration::from_secs(40 * DAY_SECS)
    );
}

#[test]
fn not_after_duration_zero_validity() {
    let spec = X509Spec::self_signed("t")
        .with_not_before(NotBeforeOffset::DaysAgo(0))
        .with_validity_days(0);
    assert_eq!(spec.not_after_duration(), Duration::ZERO);
}

// ---------------------------------------------------------------------------
// X509Spec – stable_bytes encoding
// ---------------------------------------------------------------------------

#[test]
fn stable_bytes_starts_with_version_4() {
    let bytes = X509Spec::self_signed("v").stable_bytes();
    assert_eq!(bytes[0], 4, "X509Spec version prefix should be 4");
}

#[test]
fn stable_bytes_deterministic_same_input() {
    let a = X509Spec::self_signed("determinism-test").stable_bytes();
    let b = X509Spec::self_signed("determinism-test").stable_bytes();
    assert_eq!(a, b);
}

#[test]
fn stable_bytes_differs_for_different_subjects() {
    let a = X509Spec::self_signed("alpha").stable_bytes();
    let b = X509Spec::self_signed("beta").stable_bytes();
    assert_ne!(a, b);
}

#[test]
fn stable_bytes_deduplicates_sans() {
    let with_dupes = X509Spec::self_signed("t").with_sans(vec![
        "x.test".into(),
        "x.test".into(),
        "y.test".into(),
    ]);
    let without_dupes =
        X509Spec::self_signed("t").with_sans(vec!["x.test".into(), "y.test".into()]);
    assert_eq!(with_dupes.stable_bytes(), without_dupes.stable_bytes());
}

#[test]
fn stable_bytes_sans_order_independent() {
    let a = X509Spec::self_signed("t").with_sans(vec!["b.test".into(), "a.test".into()]);
    let b = X509Spec::self_signed("t").with_sans(vec!["a.test".into(), "b.test".into()]);
    assert_eq!(a.stable_bytes(), b.stable_bytes());
}

#[test]
fn stable_bytes_sensitive_to_every_field() {
    let base = X509Spec::self_signed("base");
    let base_bytes = base.stable_bytes();

    let mutations: Vec<(&str, X509Spec)> = vec![
        ("validity_days", base.clone().with_validity_days(1)),
        ("is_ca", base.clone().with_is_ca(true)),
        ("rsa_bits", base.clone().with_rsa_bits(4096)),
        (
            "not_before",
            base.clone()
                .with_not_before(NotBeforeOffset::DaysFromNow(7)),
        ),
        ("key_usage", base.clone().with_key_usage(KeyUsage::ca())),
        ("sans", base.clone().with_sans(vec!["san.test".into()])),
        ("issuer_cn", {
            let mut s = base.clone();
            s.issuer_cn = "Other Issuer".into();
            s
        }),
    ];

    for (field, mutated) in mutations {
        assert_ne!(
            mutated.stable_bytes(),
            base_bytes,
            "changing {field} must change stable_bytes"
        );
    }
}

#[test]
fn stable_bytes_not_before_variants_differ() {
    let ago = X509Spec::self_signed("t").with_not_before(NotBeforeOffset::DaysAgo(1));
    let future = X509Spec::self_signed("t").with_not_before(NotBeforeOffset::DaysFromNow(1));
    assert_ne!(ago.stable_bytes(), future.stable_bytes());
}

// ---------------------------------------------------------------------------
// X509Spec – trait impls
// ---------------------------------------------------------------------------

#[test]
fn spec_clone_produces_equal_value() {
    let spec = X509Spec::self_signed("clone-test").with_validity_days(42);
    let cloned = spec.clone();
    assert_eq!(spec, cloned);
}

#[test]
fn spec_debug_does_not_panic() {
    let spec = X509Spec::self_signed("debug-test");
    let dbg = format!("{:?}", spec);
    assert!(!dbg.is_empty());
}

#[test]
fn key_usage_hash_consistency() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(KeyUsage::leaf());
    set.insert(KeyUsage::leaf());
    set.insert(KeyUsage::ca());
    assert_eq!(set.len(), 2);
}

// ---------------------------------------------------------------------------
// ChainSpec – construction and defaults
// ---------------------------------------------------------------------------

#[test]
fn chain_spec_defaults() {
    let spec = ChainSpec::new("leaf.example.com");
    assert_eq!(spec.leaf_cn, "leaf.example.com");
    assert_eq!(spec.leaf_sans, vec!["leaf.example.com"]);
    assert_eq!(spec.root_cn, "leaf.example.com Root CA");
    assert_eq!(spec.intermediate_cn, "leaf.example.com Intermediate CA");
    assert_eq!(spec.rsa_bits, 2048);
    assert_eq!(spec.root_validity_days, 3650);
    assert_eq!(spec.intermediate_validity_days, 1825);
    assert_eq!(spec.leaf_validity_days, 3650);
    assert!(spec.leaf_not_before_offset_days.is_none());
    assert!(spec.intermediate_not_before_offset_days.is_none());
}

// ---------------------------------------------------------------------------
// ChainSpec – builder chain
// ---------------------------------------------------------------------------

#[test]
fn chain_spec_builders_apply() {
    let spec = ChainSpec::new("site.test")
        .with_sans(vec!["site.test".into(), "www.site.test".into()])
        .with_root_cn("Custom Root")
        .with_intermediate_cn("Custom Int")
        .with_rsa_bits(4096)
        .with_root_validity_days(7300)
        .with_intermediate_validity_days(3650)
        .with_leaf_validity_days(90);

    assert_eq!(spec.leaf_sans, vec!["site.test", "www.site.test"]);
    assert_eq!(spec.root_cn, "Custom Root");
    assert_eq!(spec.intermediate_cn, "Custom Int");
    assert_eq!(spec.rsa_bits, 4096);
    assert_eq!(spec.root_validity_days, 7300);
    assert_eq!(spec.intermediate_validity_days, 3650);
    assert_eq!(spec.leaf_validity_days, 90);
}

#[test]
fn chain_spec_with_sans_replaces_auto_san() {
    let spec = ChainSpec::new("host.test").with_sans(vec!["other.test".into()]);
    assert_eq!(spec.leaf_sans, vec!["other.test"]);
}

// ---------------------------------------------------------------------------
// ChainSpec – stable_bytes encoding
// ---------------------------------------------------------------------------

#[test]
fn chain_stable_bytes_starts_with_version_2() {
    let bytes = ChainSpec::new("v").stable_bytes();
    assert_eq!(bytes[0], 2, "ChainSpec version prefix should be 2");
}

#[test]
fn chain_stable_bytes_deterministic() {
    let a = ChainSpec::new("d.test").stable_bytes();
    let b = ChainSpec::new("d.test").stable_bytes();
    assert_eq!(a, b);
}

#[test]
fn chain_stable_bytes_differs_for_different_leaf_cn() {
    let a = ChainSpec::new("alpha.test").stable_bytes();
    let b = ChainSpec::new("beta.test").stable_bytes();
    assert_ne!(a, b);
}

#[test]
fn chain_stable_bytes_san_order_independent() {
    let a = ChainSpec::new("t").with_sans(vec!["b.test".into(), "a.test".into()]);
    let b = ChainSpec::new("t").with_sans(vec!["a.test".into(), "b.test".into()]);
    assert_eq!(a.stable_bytes(), b.stable_bytes());
}

#[test]
fn chain_stable_bytes_deduplicates_sans() {
    let with_dupes =
        ChainSpec::new("t").with_sans(vec!["x.test".into(), "x.test".into(), "y.test".into()]);
    let without_dupes = ChainSpec::new("t").with_sans(vec!["x.test".into(), "y.test".into()]);
    assert_eq!(with_dupes.stable_bytes(), without_dupes.stable_bytes());
}

#[test]
fn chain_stable_bytes_sensitive_to_every_field() {
    let base = ChainSpec::new("base.test");
    let base_bytes = base.stable_bytes();

    let mutations: Vec<(&str, ChainSpec)> = vec![
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
            base.clone().with_sans(vec!["extra.test".into()]),
        ),
        ("leaf_not_before_offset_days", {
            let mut s = base.clone();
            s.leaf_not_before_offset_days = Some(100);
            s
        }),
        ("intermediate_not_before_offset_days", {
            let mut s = base.clone();
            s.intermediate_not_before_offset_days = Some(100);
            s
        }),
    ];

    for (field, mutated) in mutations {
        assert_ne!(
            mutated.stable_bytes(),
            base_bytes,
            "changing {field} must change chain stable_bytes"
        );
    }
}

#[test]
fn chain_stable_bytes_optional_offsets_none_vs_some() {
    let base = ChainSpec::new("t");

    let mut with_leaf = base.clone();
    with_leaf.leaf_not_before_offset_days = Some(0);
    assert_ne!(base.stable_bytes(), with_leaf.stable_bytes());

    let mut with_int = base.clone();
    with_int.intermediate_not_before_offset_days = Some(0);
    assert_ne!(base.stable_bytes(), with_int.stable_bytes());
}

#[test]
fn chain_stable_bytes_optional_offsets_different_values() {
    let mut a = ChainSpec::new("t");
    a.leaf_not_before_offset_days = Some(100);
    let mut b = ChainSpec::new("t");
    b.leaf_not_before_offset_days = Some(200);
    assert_ne!(a.stable_bytes(), b.stable_bytes());
}

// ---------------------------------------------------------------------------
// ChainSpec – trait impls
// ---------------------------------------------------------------------------

#[test]
fn chain_spec_clone_produces_equal_value() {
    let spec = ChainSpec::new("clone.test").with_rsa_bits(4096);
    assert_eq!(spec.clone(), spec);
}

#[test]
fn chain_spec_debug_does_not_panic() {
    let spec = ChainSpec::new("debug.test");
    let dbg = format!("{:?}", spec);
    assert!(!dbg.is_empty());
}

#[test]
fn chain_spec_hash_consistency() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(ChainSpec::new("a.test"));
    set.insert(ChainSpec::new("a.test"));
    set.insert(ChainSpec::new("b.test"));
    assert_eq!(set.len(), 2);
}
