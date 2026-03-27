//! Comprehensive tests for `uselesskey-core-x509-spec`.
//!
//! Covers gaps not addressed by existing test files:
//! - Rstest parameterized tests for builder methods
//! - Exact stable_bytes wire-format verification
//! - HashMap/HashSet usage (real-world cache-key scenario)
//! - Edge cases: empty strings, Unicode, large SANs, zero validity
//! - ChainSpec negative offset values
//! - Cross-type stable_bytes collision resistance
//! - Copy/Clone semantics for value types

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use rstest::rstest;
use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

// =========================================================================
// Rstest parameterized: X509Spec builder methods
// =========================================================================

#[rstest]
#[case(1)]
#[case(30)]
#[case(365)]
#[case(3650)]
#[case(0)]
#[case(u32::MAX)]
fn x509_with_validity_days_preserves(#[case] days: u32) {
    let spec = X509Spec::self_signed("test").with_validity_days(days);
    assert_eq!(spec.validity_days, days);
}

#[rstest]
#[case(1024)]
#[case(2048)]
#[case(3072)]
#[case(4096)]
#[case(0)]
fn x509_with_rsa_bits_preserves(#[case] bits: usize) {
    let spec = X509Spec::self_signed("test").with_rsa_bits(bits);
    assert_eq!(spec.rsa_bits, bits);
}

#[rstest]
#[case(NotBeforeOffset::DaysAgo(0))]
#[case(NotBeforeOffset::DaysAgo(1))]
#[case(NotBeforeOffset::DaysAgo(365))]
#[case(NotBeforeOffset::DaysFromNow(0))]
#[case(NotBeforeOffset::DaysFromNow(7))]
#[case(NotBeforeOffset::DaysFromNow(365))]
fn x509_with_not_before_preserves(#[case] offset: NotBeforeOffset) {
    let spec = X509Spec::self_signed("test").with_not_before(offset);
    assert_eq!(spec.not_before_offset, offset);
}

#[rstest]
#[case(true)]
#[case(false)]
fn x509_with_is_ca_preserves(#[case] is_ca: bool) {
    let spec = X509Spec::self_signed("test").with_is_ca(is_ca);
    assert_eq!(spec.is_ca, is_ca);
}

// =========================================================================
// Rstest parameterized: ChainSpec builder methods
// =========================================================================

#[rstest]
#[case(1)]
#[case(3650)]
#[case(7300)]
fn chain_with_root_validity_days_preserves(#[case] days: u32) {
    let spec = ChainSpec::new("test").with_root_validity_days(days);
    assert_eq!(spec.root_validity_days, days);
}

#[rstest]
#[case(1)]
#[case(1825)]
#[case(3650)]
fn chain_with_intermediate_validity_days_preserves(#[case] days: u32) {
    let spec = ChainSpec::new("test").with_intermediate_validity_days(days);
    assert_eq!(spec.intermediate_validity_days, days);
}

#[rstest]
#[case(1)]
#[case(90)]
#[case(3650)]
fn chain_with_leaf_validity_days_preserves(#[case] days: u32) {
    let spec = ChainSpec::new("test").with_leaf_validity_days(days);
    assert_eq!(spec.leaf_validity_days, days);
}

// =========================================================================
// Exact stable_bytes wire-format verification for X509Spec
// =========================================================================

#[test]
fn x509_stable_bytes_exact_format_minimal() {
    // Use short CN "a" with defaults to verify exact layout
    let spec = X509Spec::self_signed("a");
    let bytes = spec.stable_bytes();

    let mut expected = Vec::new();
    // Version prefix
    expected.push(4);
    // Subject CN: length (4 bytes big-endian) + "a"
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.push(b'a');
    // Issuer CN: length (4 bytes big-endian) + "a"
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.push(b'a');
    // not_before_offset: DaysAgo(1) → tag=0, value=1
    expected.push(0);
    expected.extend_from_slice(&1u32.to_be_bytes());
    // validity_days: 3650
    expected.extend_from_slice(&3650u32.to_be_bytes());
    // key_usage: leaf = [0, 0, 1, 1]
    expected.extend_from_slice(&[0, 0, 1, 1]);
    // is_ca: false
    expected.push(0);
    // rsa_bits: 2048
    expected.extend_from_slice(&2048u32.to_be_bytes());
    // SANs: empty → count=0
    expected.extend_from_slice(&0u32.to_be_bytes());

    assert_eq!(
        bytes, expected,
        "wire format mismatch for minimal self_signed spec"
    );
}

#[test]
fn x509_stable_bytes_exact_format_with_sans() {
    let spec = X509Spec::self_signed("b")
        .with_validity_days(90)
        .with_not_before(NotBeforeOffset::DaysFromNow(7))
        .with_rsa_bits(4096)
        .with_is_ca(true)
        .with_key_usage(KeyUsage::ca())
        .with_sans(vec!["z.com".into(), "a.com".into()]);
    let bytes = spec.stable_bytes();

    let mut expected = Vec::new();
    // Version prefix
    expected.push(4);
    // Subject CN: "b"
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.push(b'b');
    // Issuer CN: "b"
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.push(b'b');
    // not_before_offset: DaysFromNow(7) → tag=1, value=7
    expected.push(1);
    expected.extend_from_slice(&7u32.to_be_bytes());
    // validity_days: 90
    expected.extend_from_slice(&90u32.to_be_bytes());
    // key_usage: ca = [1, 1, 1, 0]
    expected.extend_from_slice(&[1, 1, 1, 0]);
    // is_ca: true
    expected.push(1);
    // rsa_bits: 4096
    expected.extend_from_slice(&4096u32.to_be_bytes());
    // SANs: sorted+deduped = ["a.com", "z.com"], count=2
    expected.extend_from_slice(&2u32.to_be_bytes());
    // "a.com"
    expected.extend_from_slice(&5u32.to_be_bytes());
    expected.extend_from_slice(b"a.com");
    // "z.com"
    expected.extend_from_slice(&5u32.to_be_bytes());
    expected.extend_from_slice(b"z.com");

    assert_eq!(
        bytes, expected,
        "wire format mismatch for CA spec with SANs"
    );
}

// =========================================================================
// Exact stable_bytes wire-format verification for ChainSpec
// =========================================================================

#[test]
fn chain_stable_bytes_exact_format_minimal() {
    let spec = ChainSpec::new("x");
    let bytes = spec.stable_bytes();

    let mut expected = Vec::new();
    // Version prefix
    expected.push(3);
    // leaf_cn: "x"
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.push(b'x');
    // leaf_sans: sorted+deduped ["x"], count=1
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.push(b'x');
    // root_cn: "x Root CA"
    let root_cn = "x Root CA";
    expected.extend_from_slice(&(root_cn.len() as u32).to_be_bytes());
    expected.extend_from_slice(root_cn.as_bytes());
    // intermediate_cn: "x Intermediate CA"
    let int_cn = "x Intermediate CA";
    expected.extend_from_slice(&(int_cn.len() as u32).to_be_bytes());
    expected.extend_from_slice(int_cn.as_bytes());
    // rsa_bits: 2048
    expected.extend_from_slice(&2048u32.to_be_bytes());
    // validity periods
    expected.extend_from_slice(&3650u32.to_be_bytes());
    expected.extend_from_slice(&1825u32.to_be_bytes());
    expected.extend_from_slice(&3650u32.to_be_bytes());
    // leaf_not_before: None → tag=0
    expected.push(0);
    // intermediate_not_before: None → tag=0
    expected.push(0);
    // intermediate_is_ca: None → tag=0
    expected.push(0);
    // intermediate_key_usage: None → tag=0
    expected.push(0);

    assert_eq!(
        bytes, expected,
        "wire format mismatch for minimal ChainSpec"
    );
}

#[test]
fn chain_stable_bytes_exact_format_with_offsets() {
    let mut spec = ChainSpec::new("y").with_rsa_bits(4096);
    spec.leaf_not_before = Some(NotBeforeOffset::DaysFromNow(730));
    spec.intermediate_not_before = Some(NotBeforeOffset::DaysAgo(365));
    let bytes = spec.stable_bytes();

    // Verify new tail encoding:
    // leaf tag=2 + u32, intermediate tag=1 + u32, intermediate_is_ca tag=0, key_usage tag=0
    let len = bytes.len();
    assert_eq!(bytes[len - 2], 0, "intermediate_is_ca None tag");
    assert_eq!(bytes[len - 1], 0, "intermediate_key_usage None tag");
    assert_eq!(&bytes[len - 6..len - 2], &365u32.to_be_bytes());
    assert_eq!(bytes[len - 7], 1, "intermediate DaysAgo tag");
    assert_eq!(&bytes[len - 11..len - 7], &730u32.to_be_bytes());
    assert_eq!(bytes[len - 12], 2, "leaf DaysFromNow tag");
}

// =========================================================================
// HashMap/HashSet usage (real-world cache-key scenario)
// =========================================================================

#[test]
fn x509_spec_works_as_hashmap_key() {
    let mut map = HashMap::new();
    let spec1 = X509Spec::self_signed("key1");
    let spec2 = X509Spec::self_signed("key2");
    map.insert(spec1.clone(), "value1");
    map.insert(spec2.clone(), "value2");

    assert_eq!(map.len(), 2);
    assert_eq!(map[&spec1], "value1");
    assert_eq!(map[&spec2], "value2");

    // Inserting equal spec overwrites
    let spec1_dup = X509Spec::self_signed("key1");
    map.insert(spec1_dup, "overwritten");
    assert_eq!(map.len(), 2);
    assert_eq!(map[&spec1], "overwritten");
}

#[test]
fn x509_spec_works_in_hashset() {
    let mut set = HashSet::new();
    set.insert(X509Spec::self_signed("a"));
    set.insert(X509Spec::self_signed("b"));
    set.insert(X509Spec::self_signed("a")); // duplicate

    assert_eq!(set.len(), 2);
    assert!(set.contains(&X509Spec::self_signed("a")));
    assert!(set.contains(&X509Spec::self_signed("b")));
}

#[test]
fn chain_spec_works_as_hashmap_key() {
    let mut map = HashMap::new();
    let spec1 = ChainSpec::new("host1.example.com");
    let spec2 = ChainSpec::new("host2.example.com");
    map.insert(spec1.clone(), 1);
    map.insert(spec2.clone(), 2);

    assert_eq!(map.len(), 2);
    assert_eq!(map[&spec1], 1);
    assert_eq!(map[&spec2], 2);
}

#[test]
fn chain_spec_works_in_hashset() {
    let mut set = HashSet::new();
    set.insert(ChainSpec::new("a"));
    set.insert(ChainSpec::new("b"));
    set.insert(ChainSpec::new("a")); // duplicate

    assert_eq!(set.len(), 2);
}

#[test]
fn key_usage_works_in_hashset() {
    let mut set = HashSet::new();
    set.insert(KeyUsage::leaf());
    set.insert(KeyUsage::ca());
    set.insert(KeyUsage::leaf()); // duplicate

    assert_eq!(set.len(), 2);
}

// =========================================================================
// Edge cases: empty strings
// =========================================================================

#[test]
fn x509_spec_empty_cn() {
    let spec = X509Spec::self_signed("");
    assert_eq!(spec.subject_cn, "");
    assert_eq!(spec.issuer_cn, "");
    // stable_bytes still works
    let bytes = spec.stable_bytes();
    assert!(!bytes.is_empty());
    // Deterministic
    assert_eq!(bytes, spec.stable_bytes());
}

#[test]
fn chain_spec_empty_cn() {
    let spec = ChainSpec::new("");
    assert_eq!(spec.leaf_cn, "");
    assert_eq!(spec.leaf_sans, vec![""]);
    assert_eq!(spec.root_cn, " Root CA");
    assert_eq!(spec.intermediate_cn, " Intermediate CA");
    let bytes = spec.stable_bytes();
    assert!(!bytes.is_empty());
}

#[test]
fn x509_spec_empty_sans_entry() {
    let spec = X509Spec::self_signed("test").with_sans(vec!["".into()]);
    assert_eq!(spec.sans, vec![""]);
    let bytes = spec.stable_bytes();
    assert!(!bytes.is_empty());
}

// =========================================================================
// Edge cases: Unicode
// =========================================================================

#[test]
fn x509_spec_unicode_cn() {
    let spec = X509Spec::self_signed("日本語.example.com");
    assert_eq!(spec.subject_cn, "日本語.example.com");
    let bytes = spec.stable_bytes();
    assert!(bytes.len() > 10);
    assert_eq!(bytes, spec.stable_bytes());
}

#[test]
fn chain_spec_unicode_cn() {
    let spec = ChainSpec::new("中文.example.com");
    assert_eq!(spec.leaf_cn, "中文.example.com");
    assert!(spec.root_cn.starts_with("中文.example.com"));
    let bytes = spec.stable_bytes();
    assert_eq!(bytes, spec.stable_bytes());
}

#[test]
fn x509_spec_unicode_sans() {
    let spec = X509Spec::self_signed("test").with_sans(vec!["émoji.com".into(), "über.de".into()]);
    let bytes = spec.stable_bytes();
    assert_eq!(bytes, spec.stable_bytes());
}

// =========================================================================
// Edge cases: large SAN lists
// =========================================================================

#[test]
fn x509_spec_many_sans() {
    let sans: Vec<String> = (0..100).map(|i| format!("host{i}.example.com")).collect();
    let spec = X509Spec::self_signed("test").with_sans(sans.clone());
    assert_eq!(spec.sans.len(), 100);
    let bytes = spec.stable_bytes();
    assert_eq!(bytes, spec.stable_bytes());
}

#[test]
fn chain_spec_many_sans() {
    let sans: Vec<String> = (0..50).map(|i| format!("host{i}.example.com")).collect();
    let spec = ChainSpec::new("test").with_sans(sans);
    assert_eq!(spec.leaf_sans.len(), 50);
    let bytes = spec.stable_bytes();
    assert_eq!(bytes, spec.stable_bytes());
}

// =========================================================================
// Edge cases: zero validity
// =========================================================================

#[test]
fn x509_spec_zero_validity_days() {
    let spec = X509Spec::self_signed("test").with_validity_days(0);
    assert_eq!(spec.validity_days, 0);
    assert_eq!(spec.not_after_duration(), Duration::ZERO);
}

#[test]
fn x509_spec_zero_validity_days_from_now() {
    let spec = X509Spec::self_signed("test")
        .with_not_before(NotBeforeOffset::DaysFromNow(5))
        .with_validity_days(0);
    assert_eq!(
        spec.not_after_duration(),
        Duration::from_secs(5 * 86400),
        "not_after should be offset only when validity is 0"
    );
}

// =========================================================================
// ChainSpec negative offset values
// =========================================================================

#[test]
fn chain_spec_negative_leaf_offset() {
    let mut spec = ChainSpec::new("test");
    spec.leaf_not_before = Some(NotBeforeOffset::DaysFromNow(730));
    let bytes = spec.stable_bytes();
    assert_eq!(bytes, spec.stable_bytes());
}

#[test]
fn chain_spec_negative_intermediate_offset() {
    let mut spec = ChainSpec::new("test");
    spec.intermediate_not_before = Some(NotBeforeOffset::DaysFromNow(365));
    let bytes = spec.stable_bytes();
    assert_eq!(bytes, spec.stable_bytes());
}

#[test]
fn chain_spec_positive_vs_negative_offset_differ() {
    let mut pos = ChainSpec::new("test");
    pos.leaf_not_before = Some(NotBeforeOffset::DaysAgo(100));
    let mut neg = ChainSpec::new("test");
    neg.leaf_not_before = Some(NotBeforeOffset::DaysFromNow(100));
    assert_ne!(pos.stable_bytes(), neg.stable_bytes());
}

#[test]
fn chain_spec_zero_offset_differs_from_none() {
    let base = ChainSpec::new("test");
    let mut zero = ChainSpec::new("test");
    zero.leaf_not_before = Some(NotBeforeOffset::DaysAgo(0));
    assert_ne!(
        base.stable_bytes(),
        zero.stable_bytes(),
        "None and Some(0) must produce different stable_bytes"
    );
}

// =========================================================================
// Cross-type collision resistance
// =========================================================================

#[test]
fn x509_spec_and_chain_spec_never_collide() {
    // Even with similar-looking params, X509Spec and ChainSpec must have
    // different stable_bytes (different version prefixes: 4 vs 2).
    let x509 = X509Spec::self_signed("test");
    let chain = ChainSpec::new("test");
    assert_ne!(
        x509.stable_bytes(),
        chain.stable_bytes(),
        "X509Spec and ChainSpec must not produce the same stable_bytes"
    );
}

// =========================================================================
// Copy/Clone semantics
// =========================================================================

#[test]
fn key_usage_is_copy() {
    let ku = KeyUsage::leaf();
    let copy = ku; // Copy
    let _still_usable = ku; // original still usable
    assert_eq!(ku, copy);
}

#[test]
fn not_before_offset_is_copy() {
    let nbo = NotBeforeOffset::DaysAgo(5);
    let copy = nbo; // Copy
    let _still_usable = nbo; // original still usable
    assert_eq!(nbo, copy);
}

// =========================================================================
// Debug output: no key material, contains structural info
// =========================================================================

#[test]
fn x509_spec_debug_shows_all_fields() {
    let spec = X509Spec::self_signed("debug.test")
        .with_validity_days(90)
        .with_rsa_bits(4096)
        .with_is_ca(true)
        .with_sans(vec!["alt.test".into()]);
    let dbg = format!("{spec:?}");
    assert!(dbg.contains("debug.test"), "Debug must include CN");
    assert!(dbg.contains("90"), "Debug must include validity_days");
    assert!(dbg.contains("4096"), "Debug must include rsa_bits");
    assert!(dbg.contains("true"), "Debug must include is_ca");
    assert!(dbg.contains("alt.test"), "Debug must include SANs");
}

#[test]
fn chain_spec_debug_shows_key_fields() {
    let spec = ChainSpec::new("chain.test")
        .with_root_cn("My Root")
        .with_intermediate_cn("My Int");
    let dbg = format!("{spec:?}");
    assert!(dbg.contains("chain.test"));
    assert!(dbg.contains("My Root"));
    assert!(dbg.contains("My Int"));
}

#[test]
fn key_usage_debug_shows_flags() {
    let ku = KeyUsage {
        key_cert_sign: true,
        crl_sign: false,
        digital_signature: true,
        key_encipherment: false,
    };
    let dbg = format!("{ku:?}");
    assert!(dbg.contains("key_cert_sign"));
    assert!(dbg.contains("digital_signature"));
}

#[test]
fn not_before_offset_debug_shows_variant_and_value() {
    let ago = NotBeforeOffset::DaysAgo(42);
    assert!(format!("{ago:?}").contains("42"));
    let future = NotBeforeOffset::DaysFromNow(99);
    assert!(format!("{future:?}").contains("99"));
}

// =========================================================================
// Rstest parameterized: stable_bytes field sensitivity matrix
// =========================================================================

#[rstest]
#[case("validity_days", X509Spec::self_signed("t").with_validity_days(1))]
#[case("rsa_bits", X509Spec::self_signed("t").with_rsa_bits(4096))]
#[case("is_ca", X509Spec::self_signed("t").with_is_ca(true))]
#[case("key_usage", X509Spec::self_signed("t").with_key_usage(KeyUsage::ca()))]
#[case("not_before", X509Spec::self_signed("t").with_not_before(NotBeforeOffset::DaysFromNow(1)))]
#[case("sans", X509Spec::self_signed("t").with_sans(vec!["x".into()]))]
fn x509_each_field_changes_stable_bytes(#[case] field: &str, #[case] changed: X509Spec) {
    let base = X509Spec::self_signed("t");
    assert_ne!(
        base.stable_bytes(),
        changed.stable_bytes(),
        "changing {field} must alter stable_bytes"
    );
}

#[rstest]
#[case("rsa_bits", ChainSpec::new("t").with_rsa_bits(4096))]
#[case("root_cn", ChainSpec::new("t").with_root_cn("X"))]
#[case("intermediate_cn", ChainSpec::new("t").with_intermediate_cn("X"))]
#[case("root_validity", ChainSpec::new("t").with_root_validity_days(1))]
#[case("inter_validity", ChainSpec::new("t").with_intermediate_validity_days(1))]
#[case("leaf_validity", ChainSpec::new("t").with_leaf_validity_days(1))]
#[case("sans", ChainSpec::new("t").with_sans(vec!["x".into()]))]
fn chain_each_field_changes_stable_bytes(#[case] field: &str, #[case] changed: ChainSpec) {
    let base = ChainSpec::new("t");
    assert_ne!(
        base.stable_bytes(),
        changed.stable_bytes(),
        "changing {field} must alter stable_bytes"
    );
}

// =========================================================================
// Rstest parameterized: duration computation
// =========================================================================

#[rstest]
#[case(NotBeforeOffset::DaysAgo(0), 0)]
#[case(NotBeforeOffset::DaysAgo(1), 86400)]
#[case(NotBeforeOffset::DaysAgo(30), 30 * 86400)]
#[case(NotBeforeOffset::DaysFromNow(0), 0)]
#[case(NotBeforeOffset::DaysFromNow(1), 0)]
#[case(NotBeforeOffset::DaysFromNow(365), 0)]
fn not_before_duration_table(#[case] offset: NotBeforeOffset, #[case] expected_secs: u64) {
    let spec = X509Spec::self_signed("t").with_not_before(offset);
    assert_eq!(
        spec.not_before_duration(),
        Duration::from_secs(expected_secs)
    );
}

#[rstest]
#[case(NotBeforeOffset::DaysAgo(1), 30, 30 * 86400)]
#[case(NotBeforeOffset::DaysAgo(0), 0, 0)]
#[case(NotBeforeOffset::DaysFromNow(5), 30, (5 + 30) * 86400)]
#[case(NotBeforeOffset::DaysFromNow(0), 10, 10 * 86400)]
fn not_after_duration_table(
    #[case] offset: NotBeforeOffset,
    #[case] validity: u32,
    #[case] expected_secs: u64,
) {
    let spec = X509Spec::self_signed("t")
        .with_not_before(offset)
        .with_validity_days(validity);
    assert_eq!(
        spec.not_after_duration(),
        Duration::from_secs(expected_secs)
    );
}

// =========================================================================
// Into<String> builder trait bounds
// =========================================================================

#[test]
fn x509_self_signed_accepts_string() {
    let cn = String::from("owned.test");
    let spec = X509Spec::self_signed(cn);
    assert_eq!(spec.subject_cn, "owned.test");
}

#[test]
fn x509_self_signed_ca_accepts_string() {
    let cn = String::from("Owned CA");
    let spec = X509Spec::self_signed_ca(cn);
    assert_eq!(spec.subject_cn, "Owned CA");
}

#[test]
fn chain_spec_new_accepts_string() {
    let cn = String::from("owned.example.com");
    let spec = ChainSpec::new(cn);
    assert_eq!(spec.leaf_cn, "owned.example.com");
}

#[test]
fn chain_spec_with_root_cn_accepts_string() {
    let spec = ChainSpec::new("test").with_root_cn(String::from("Root"));
    assert_eq!(spec.root_cn, "Root");
}

#[test]
fn chain_spec_with_intermediate_cn_accepts_string() {
    let spec = ChainSpec::new("test").with_intermediate_cn(String::from("Int"));
    assert_eq!(spec.intermediate_cn, "Int");
}

// =========================================================================
// Stable_bytes length consistency
// =========================================================================

#[test]
fn x509_stable_bytes_length_grows_with_sans() {
    let no_sans = X509Spec::self_signed("t");
    let one_san = X509Spec::self_signed("t").with_sans(vec!["a.com".into()]);
    let two_sans = X509Spec::self_signed("t").with_sans(vec!["a.com".into(), "b.com".into()]);

    assert!(one_san.stable_bytes().len() > no_sans.stable_bytes().len());
    assert!(two_sans.stable_bytes().len() > one_san.stable_bytes().len());
}

#[test]
fn chain_stable_bytes_length_grows_with_sans() {
    let no_sans = ChainSpec::new("t").with_sans(vec![]);
    let one_san = ChainSpec::new("t").with_sans(vec!["a.com".into()]);
    let two_sans = ChainSpec::new("t").with_sans(vec!["a.com".into(), "b.com".into()]);

    assert!(one_san.stable_bytes().len() > no_sans.stable_bytes().len());
    assert!(two_sans.stable_bytes().len() > one_san.stable_bytes().len());
}

#[test]
fn x509_stable_bytes_length_grows_with_cn() {
    let short = X509Spec::self_signed("a");
    let long = X509Spec::self_signed("a".repeat(100));
    assert!(long.stable_bytes().len() > short.stable_bytes().len());
}

// =========================================================================
// ChainSpec auto-generated CN format
// =========================================================================

#[rstest]
#[case("example.com", "example.com Root CA", "example.com Intermediate CA")]
#[case("test", "test Root CA", "test Intermediate CA")]
#[case("my-service", "my-service Root CA", "my-service Intermediate CA")]
fn chain_spec_auto_cn_format(
    #[case] leaf: &str,
    #[case] expected_root: &str,
    #[case] expected_int: &str,
) {
    let spec = ChainSpec::new(leaf);
    assert_eq!(spec.root_cn, expected_root);
    assert_eq!(spec.intermediate_cn, expected_int);
}

// =========================================================================
// KeyUsage stable_bytes encoding: each flag occupies its own byte position
// =========================================================================

#[rstest]
#[case(true, false, false, false, [1, 0, 0, 0])]
#[case(false, true, false, false, [0, 1, 0, 0])]
#[case(false, false, true, false, [0, 0, 1, 0])]
#[case(false, false, false, true, [0, 0, 0, 1])]
fn key_usage_single_flag_position(
    #[case] cert_sign: bool,
    #[case] crl: bool,
    #[case] dig_sig: bool,
    #[case] key_enc: bool,
    #[case] expected: [u8; 4],
) {
    let ku = KeyUsage {
        key_cert_sign: cert_sign,
        crl_sign: crl,
        digital_signature: dig_sig,
        key_encipherment: key_enc,
    };
    assert_eq!(ku.stable_bytes(), expected);
}
