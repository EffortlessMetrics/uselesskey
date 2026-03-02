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

// ---------------------------------------------------------------------------
// Trait implementations — Clone, Debug, PartialEq, Hash
// ---------------------------------------------------------------------------

#[test]
fn x509_spec_clone_equals_original() {
    let spec = X509Spec::self_signed("clone-test")
        .with_validity_days(90)
        .with_sans(vec!["a.test".into()]);
    let cloned = spec.clone();
    assert_eq!(spec, cloned);
    assert_eq!(spec.stable_bytes(), cloned.stable_bytes());
}

#[test]
fn x509_spec_debug_contains_type_name() {
    let spec = X509Spec::self_signed("debug-test");
    let dbg = format!("{spec:?}");
    assert!(dbg.contains("X509Spec"));
    assert!(dbg.contains("debug-test"));
}

#[test]
fn x509_spec_ne_for_different_cn() {
    let a = X509Spec::self_signed("alpha");
    let b = X509Spec::self_signed("beta");
    assert_ne!(a, b);
}

#[test]
fn x509_spec_hash_equal_for_equal_specs() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let a = X509Spec::self_signed("hash-test");
    let b = X509Spec::self_signed("hash-test");

    let mut ha = DefaultHasher::new();
    a.hash(&mut ha);
    let mut hb = DefaultHasher::new();
    b.hash(&mut hb);
    assert_eq!(ha.finish(), hb.finish());
}

#[test]
fn chain_spec_clone_equals_original() {
    let spec = ChainSpec::new("clone.example.com")
        .with_rsa_bits(4096)
        .with_sans(vec!["a.com".into()]);
    let cloned = spec.clone();
    assert_eq!(spec, cloned);
    assert_eq!(spec.stable_bytes(), cloned.stable_bytes());
}

#[test]
fn chain_spec_debug_contains_type_name() {
    let spec = ChainSpec::new("debug.example.com");
    let dbg = format!("{spec:?}");
    assert!(dbg.contains("ChainSpec"));
    assert!(dbg.contains("debug.example.com"));
}

#[test]
fn chain_spec_ne_for_different_leaf_cn() {
    let a = ChainSpec::new("alpha.example.com");
    let b = ChainSpec::new("beta.example.com");
    assert_ne!(a, b);
}

#[test]
fn chain_spec_hash_equal_for_equal_specs() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let a = ChainSpec::new("hash.example.com");
    let b = ChainSpec::new("hash.example.com");

    let mut ha = DefaultHasher::new();
    a.hash(&mut ha);
    let mut hb = DefaultHasher::new();
    b.hash(&mut hb);
    assert_eq!(ha.finish(), hb.finish());
}

#[test]
fn key_usage_clone_equals_original() {
    let leaf = KeyUsage::leaf();
    let cloned = leaf;
    assert_eq!(leaf, cloned);

    let ca = KeyUsage::ca();
    let cloned = ca;
    assert_eq!(ca, cloned);
}

#[test]
fn key_usage_debug_contains_type_name() {
    let ku = KeyUsage::leaf();
    let dbg = format!("{ku:?}");
    assert!(dbg.contains("KeyUsage"));
}

#[test]
fn key_usage_hash_equal_for_equal_values() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let a = KeyUsage::leaf();
    let b = KeyUsage::leaf();

    let mut ha = DefaultHasher::new();
    a.hash(&mut ha);
    let mut hb = DefaultHasher::new();
    b.hash(&mut hb);
    assert_eq!(ha.finish(), hb.finish());
}

#[test]
fn not_before_offset_clone_equals_original() {
    let ago = NotBeforeOffset::DaysAgo(5);
    let cloned = ago;
    assert_eq!(ago, cloned);

    let future = NotBeforeOffset::DaysFromNow(10);
    let cloned = future;
    assert_eq!(future, cloned);
}

#[test]
fn not_before_offset_debug_contains_variant() {
    let ago = NotBeforeOffset::DaysAgo(5);
    let dbg = format!("{ago:?}");
    assert!(dbg.contains("DaysAgo"));
    assert!(dbg.contains("5"));

    let future = NotBeforeOffset::DaysFromNow(10);
    let dbg = format!("{future:?}");
    assert!(dbg.contains("DaysFromNow"));
    assert!(dbg.contains("10"));
}

#[test]
fn not_before_offset_ne_across_variants() {
    assert_ne!(NotBeforeOffset::DaysAgo(1), NotBeforeOffset::DaysFromNow(1));
}

#[test]
fn not_before_offset_ne_different_values() {
    assert_ne!(NotBeforeOffset::DaysAgo(1), NotBeforeOffset::DaysAgo(2));
    assert_ne!(
        NotBeforeOffset::DaysFromNow(1),
        NotBeforeOffset::DaysFromNow(2)
    );
}

// ---------------------------------------------------------------------------
// Fingerprint stability — snapshot values
// ---------------------------------------------------------------------------

#[test]
fn x509_spec_stable_bytes_starts_with_version_4() {
    let spec = X509Spec::self_signed("test");
    assert_eq!(spec.stable_bytes()[0], 4);
}

#[test]
fn chain_spec_stable_bytes_starts_with_version_2() {
    let spec = ChainSpec::new("test.example.com");
    assert_eq!(spec.stable_bytes()[0], 2);
}

#[test]
fn x509_spec_stable_bytes_snapshot() {
    let spec = X509Spec::self_signed("snapshot.test").with_validity_days(365);
    let bytes = spec.stable_bytes();
    let again = spec.stable_bytes();
    assert_eq!(bytes, again);
    assert!(bytes.len() > 10);
}
