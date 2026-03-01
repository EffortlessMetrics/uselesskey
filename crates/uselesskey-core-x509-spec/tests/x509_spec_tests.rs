//! Comprehensive tests for uselesskey-core-x509-spec.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use proptest::prelude::*;
use rstest::rstest;
use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

const DAY_SECS: u64 = 24 * 60 * 60;

fn hash_of<T: Hash>(val: &T) -> u64 {
    let mut h = DefaultHasher::new();
    val.hash(&mut h);
    h.finish()
}

// ===========================================================================
// X509Spec – construction
// ===========================================================================

#[test]
fn self_signed_accepts_string_and_str() {
    let from_str = X509Spec::self_signed("hello");
    let from_string = X509Spec::self_signed(String::from("hello"));
    assert_eq!(from_str, from_string);
}

#[test]
fn self_signed_ca_accepts_string_and_str() {
    let from_str = X509Spec::self_signed_ca("CA");
    let from_string = X509Spec::self_signed_ca(String::from("CA"));
    assert_eq!(from_str, from_string);
}

#[test]
fn self_signed_with_empty_cn() {
    let spec = X509Spec::self_signed("");
    assert_eq!(spec.subject_cn, "");
    assert_eq!(spec.issuer_cn, "");
}

#[test]
fn self_signed_with_unicode_cn() {
    let spec = X509Spec::self_signed("日本語テスト");
    assert_eq!(spec.subject_cn, "日本語テスト");
    assert_eq!(spec.issuer_cn, "日本語テスト");
}

#[test]
fn default_spec_is_not_ca() {
    let spec = X509Spec::default();
    assert!(!spec.is_ca);
    assert!(!spec.key_usage.key_cert_sign);
    assert!(!spec.key_usage.crl_sign);
}

#[test]
fn self_signed_ca_has_all_ca_properties() {
    let spec = X509Spec::self_signed_ca("Test CA");
    assert!(spec.is_ca);
    assert!(spec.key_usage.key_cert_sign);
    assert!(spec.key_usage.crl_sign);
    assert!(spec.key_usage.digital_signature);
    assert!(!spec.key_usage.key_encipherment);
}

// ===========================================================================
// X509Spec – builder ergonomics
// ===========================================================================

#[test]
fn builder_methods_return_self_for_chaining() {
    // Ensures the builder pattern compiles as a single chain expression.
    let _spec = X509Spec::self_signed("chain")
        .with_validity_days(1)
        .with_not_before(NotBeforeOffset::DaysAgo(0))
        .with_rsa_bits(1024)
        .with_key_usage(KeyUsage::leaf())
        .with_is_ca(false)
        .with_sans(vec![]);
}

#[test]
fn with_validity_days_zero() {
    let spec = X509Spec::self_signed("t").with_validity_days(0);
    assert_eq!(spec.validity_days, 0);
}

#[test]
fn with_validity_days_max() {
    let spec = X509Spec::self_signed("t").with_validity_days(u32::MAX);
    assert_eq!(spec.validity_days, u32::MAX);
}

#[test]
fn with_rsa_bits_various_sizes() {
    for bits in [512, 1024, 2048, 4096, 8192] {
        let spec = X509Spec::self_signed("t").with_rsa_bits(bits);
        assert_eq!(spec.rsa_bits, bits);
    }
}

#[test]
fn with_sans_empty_vec() {
    let spec = X509Spec::self_signed("t").with_sans(vec![]);
    assert!(spec.sans.is_empty());
}

#[test]
fn with_sans_overwrites_previous() {
    let spec = X509Spec::self_signed("t")
        .with_sans(vec!["a.test".into()])
        .with_sans(vec!["b.test".into(), "c.test".into()]);
    assert_eq!(spec.sans, vec!["b.test", "c.test"]);
}

// ===========================================================================
// KeyUsage – stable_bytes binary layout
// ===========================================================================

#[test]
fn key_usage_stable_bytes_length_is_always_4() {
    assert_eq!(KeyUsage::leaf().stable_bytes().len(), 4);
    assert_eq!(KeyUsage::ca().stable_bytes().len(), 4);
    let custom = KeyUsage {
        key_cert_sign: false,
        crl_sign: false,
        digital_signature: false,
        key_encipherment: false,
    };
    assert_eq!(custom.stable_bytes().len(), 4);
}

#[rstest]
#[case(true, false, false, false, [1, 0, 0, 0])]
#[case(false, true, false, false, [0, 1, 0, 0])]
#[case(false, false, true, false, [0, 0, 1, 0])]
#[case(false, false, false, true, [0, 0, 0, 1])]
#[case(true, true, true, true, [1, 1, 1, 1])]
#[case(false, false, false, false, [0, 0, 0, 0])]
fn key_usage_stable_bytes_flag_mapping(
    #[case] kcs: bool,
    #[case] cs: bool,
    #[case] ds: bool,
    #[case] ke: bool,
    #[case] expected: [u8; 4],
) {
    let ku = KeyUsage {
        key_cert_sign: kcs,
        crl_sign: cs,
        digital_signature: ds,
        key_encipherment: ke,
    };
    assert_eq!(ku.stable_bytes(), expected);
}

#[test]
fn key_usage_leaf_and_ca_are_distinct() {
    let leaf = KeyUsage::leaf();
    let ca = KeyUsage::ca();
    assert_ne!(leaf, ca);
    assert_ne!(leaf.stable_bytes(), ca.stable_bytes());
}

// ===========================================================================
// KeyUsage – trait impls
// ===========================================================================

#[test]
fn key_usage_copy_semantics() {
    let a = KeyUsage::leaf();
    let b = a; // Copy
    assert_eq!(a, b); // `a` is still usable
}

#[test]
fn key_usage_hash_equal_values_same_hash() {
    assert_eq!(hash_of(&KeyUsage::leaf()), hash_of(&KeyUsage::leaf()));
}

#[test]
fn key_usage_hash_different_values_likely_different() {
    assert_ne!(hash_of(&KeyUsage::leaf()), hash_of(&KeyUsage::ca()));
}

#[test]
fn key_usage_debug_contains_field_names() {
    let dbg = format!("{:?}", KeyUsage::leaf());
    assert!(dbg.contains("key_cert_sign"));
    assert!(dbg.contains("digital_signature"));
}

// ===========================================================================
// NotBeforeOffset – defaults and equality
// ===========================================================================

#[test]
fn not_before_offset_default_is_days_ago_1() {
    assert_eq!(NotBeforeOffset::default(), NotBeforeOffset::DaysAgo(1));
}

#[test]
fn not_before_offset_days_ago_zero() {
    let offset = NotBeforeOffset::DaysAgo(0);
    assert_eq!(offset, NotBeforeOffset::DaysAgo(0));
}

#[test]
fn not_before_offset_days_from_now_zero() {
    let offset = NotBeforeOffset::DaysFromNow(0);
    assert_eq!(offset, NotBeforeOffset::DaysFromNow(0));
}

#[test]
fn not_before_offset_same_value_different_variant_not_equal() {
    assert_ne!(NotBeforeOffset::DaysAgo(0), NotBeforeOffset::DaysFromNow(0));
}

#[test]
fn not_before_offset_copy_semantics() {
    let a = NotBeforeOffset::DaysAgo(5);
    let b = a; // Copy
    assert_eq!(a, b);
}

#[test]
fn not_before_offset_hash_consistency() {
    assert_eq!(
        hash_of(&NotBeforeOffset::DaysAgo(1)),
        hash_of(&NotBeforeOffset::DaysAgo(1))
    );
    assert_ne!(
        hash_of(&NotBeforeOffset::DaysAgo(1)),
        hash_of(&NotBeforeOffset::DaysFromNow(1))
    );
}

// ===========================================================================
// X509Spec – duration helpers (edge cases)
// ===========================================================================

#[test]
fn not_before_duration_days_ago_zero_is_zero() {
    let spec = X509Spec::self_signed("t").with_not_before(NotBeforeOffset::DaysAgo(0));
    assert_eq!(spec.not_before_duration(), Duration::ZERO);
}

#[test]
fn not_after_duration_days_ago_zero_validity_zero() {
    let spec = X509Spec::self_signed("t")
        .with_not_before(NotBeforeOffset::DaysAgo(0))
        .with_validity_days(0);
    assert_eq!(spec.not_after_duration(), Duration::ZERO);
}

#[test]
fn not_after_duration_days_from_now_adds_offset_and_validity() {
    let spec = X509Spec::self_signed("t")
        .with_not_before(NotBeforeOffset::DaysFromNow(5))
        .with_validity_days(10);
    assert_eq!(
        spec.not_after_duration(),
        Duration::from_secs(15 * DAY_SECS)
    );
}

#[rstest]
#[case(NotBeforeOffset::DaysAgo(0), 100, 100 * DAY_SECS)]
#[case(NotBeforeOffset::DaysAgo(30), 365, 365 * DAY_SECS)]
#[case(NotBeforeOffset::DaysFromNow(0), 365, 365 * DAY_SECS)]
#[case(NotBeforeOffset::DaysFromNow(30), 365, (30 + 365) * DAY_SECS)]
fn not_after_duration_parametric(
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

// ===========================================================================
// X509Spec – stable_bytes binary layout verification
// ===========================================================================

#[test]
fn stable_bytes_version_prefix_is_4() {
    assert_eq!(X509Spec::self_signed("x").stable_bytes()[0], 4);
}

#[test]
fn stable_bytes_encodes_subject_cn_length_prefixed() {
    let spec = X509Spec::self_signed("AB");
    let bytes = spec.stable_bytes();
    // byte 0: version (4)
    // bytes 1..5: subject_cn length as u32 BE = 2
    assert_eq!(&bytes[1..5], &[0, 0, 0, 2]);
    // bytes 5..7: "AB"
    assert_eq!(&bytes[5..7], b"AB");
}

#[test]
fn stable_bytes_encodes_not_before_tag_byte() {
    let spec_ago = X509Spec::self_signed("").with_not_before(NotBeforeOffset::DaysAgo(0));
    let spec_future = X509Spec::self_signed("").with_not_before(NotBeforeOffset::DaysFromNow(0));
    let bytes_ago = spec_ago.stable_bytes();
    let bytes_future = spec_future.stable_bytes();

    // After version(1) + subject_cn len(4) + subject_cn(0) + issuer_cn len(4) + issuer_cn(0)
    // = offset 9 is the not_before tag
    assert_eq!(bytes_ago[9], 0, "DaysAgo tag byte should be 0");
    assert_eq!(bytes_future[9], 1, "DaysFromNow tag byte should be 1");
}

#[test]
fn stable_bytes_san_sorting_and_dedup() {
    let spec = X509Spec::self_signed("t").with_sans(vec![
        "c.test".into(),
        "a.test".into(),
        "b.test".into(),
        "a.test".into(), // duplicate
    ]);
    let bytes_sorted = X509Spec::self_signed("t")
        .with_sans(vec!["a.test".into(), "b.test".into(), "c.test".into()])
        .stable_bytes();
    assert_eq!(spec.stable_bytes(), bytes_sorted);
}

#[test]
fn stable_bytes_empty_sans_vs_no_sans() {
    let no_sans = X509Spec::self_signed("t");
    let empty_sans = X509Spec::self_signed("t").with_sans(vec![]);
    assert_eq!(no_sans.stable_bytes(), empty_sans.stable_bytes());
}

// ===========================================================================
// X509Spec – trait impls
// ===========================================================================

#[test]
fn spec_eq_reflexive() {
    let spec = X509Spec::self_signed("eq");
    assert_eq!(spec, spec.clone());
}

#[test]
fn spec_ne_different_fields() {
    let a = X509Spec::self_signed("a");
    let b = X509Spec::self_signed("b");
    assert_ne!(a, b);
}

#[test]
fn spec_hash_equal_values() {
    let a = X509Spec::self_signed("h");
    let b = X509Spec::self_signed("h");
    assert_eq!(hash_of(&a), hash_of(&b));
}

#[test]
fn spec_hash_different_values() {
    let a = X509Spec::self_signed("h1");
    let b = X509Spec::self_signed("h2");
    assert_ne!(hash_of(&a), hash_of(&b));
}

#[test]
fn spec_debug_contains_all_field_names() {
    let spec = X509Spec::self_signed("debug-test").with_sans(vec!["san.test".into()]);
    let dbg = format!("{spec:?}");
    for field in [
        "subject_cn",
        "issuer_cn",
        "not_before_offset",
        "validity_days",
        "key_usage",
        "is_ca",
        "rsa_bits",
        "sans",
    ] {
        assert!(dbg.contains(field), "Debug output missing field: {field}");
    }
}

#[test]
fn spec_debug_contains_field_values() {
    let spec = X509Spec::self_signed("my-cn").with_validity_days(42);
    let dbg = format!("{spec:?}");
    assert!(dbg.contains("my-cn"));
    assert!(dbg.contains("42"));
}

#[test]
fn spec_can_be_stored_in_hashset() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(X509Spec::self_signed("a"));
    set.insert(X509Spec::self_signed("a"));
    set.insert(X509Spec::self_signed("b"));
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// ChainSpec – construction
// ===========================================================================

#[test]
fn chain_spec_new_accepts_str_and_string() {
    let from_str = ChainSpec::new("host");
    let from_string = ChainSpec::new(String::from("host"));
    assert_eq!(from_str, from_string);
}

#[test]
fn chain_spec_new_auto_derives_ca_names() {
    let spec = ChainSpec::new("app.example.com");
    assert_eq!(spec.root_cn, "app.example.com Root CA");
    assert_eq!(spec.intermediate_cn, "app.example.com Intermediate CA");
}

#[test]
fn chain_spec_new_auto_adds_leaf_cn_to_sans() {
    let spec = ChainSpec::new("auto.test");
    assert_eq!(spec.leaf_sans, vec!["auto.test"]);
}

#[test]
fn chain_spec_with_sans_replaces_auto() {
    let spec = ChainSpec::new("host").with_sans(vec!["other.test".into()]);
    assert_eq!(spec.leaf_sans, vec!["other.test"]);
    assert!(!spec.leaf_sans.contains(&"host".to_string()));
}

#[test]
fn chain_spec_new_empty_cn() {
    let spec = ChainSpec::new("");
    assert_eq!(spec.leaf_cn, "");
    assert_eq!(spec.root_cn, " Root CA");
    assert_eq!(spec.intermediate_cn, " Intermediate CA");
}

#[test]
fn chain_spec_offset_fields_default_none() {
    let spec = ChainSpec::new("t");
    assert!(spec.leaf_not_before_offset_days.is_none());
    assert!(spec.intermediate_not_before_offset_days.is_none());
}

#[test]
fn chain_spec_offset_fields_can_be_set() {
    let mut spec = ChainSpec::new("t");
    spec.leaf_not_before_offset_days = Some(-730);
    spec.intermediate_not_before_offset_days = Some(365);
    assert_eq!(spec.leaf_not_before_offset_days, Some(-730));
    assert_eq!(spec.intermediate_not_before_offset_days, Some(365));
}

// ===========================================================================
// ChainSpec – builder ergonomics
// ===========================================================================

#[test]
fn chain_spec_builder_full_chain() {
    let _spec = ChainSpec::new("t")
        .with_sans(vec![])
        .with_root_cn("R")
        .with_intermediate_cn("I")
        .with_rsa_bits(4096)
        .with_root_validity_days(1)
        .with_intermediate_validity_days(1)
        .with_leaf_validity_days(1);
}

#[rstest]
#[case(512)]
#[case(1024)]
#[case(2048)]
#[case(4096)]
fn chain_spec_rsa_bits_parametric(#[case] bits: usize) {
    let spec = ChainSpec::new("t").with_rsa_bits(bits);
    assert_eq!(spec.rsa_bits, bits);
}

// ===========================================================================
// ChainSpec – stable_bytes binary layout
// ===========================================================================

#[test]
fn chain_stable_bytes_version_prefix_is_2() {
    assert_eq!(ChainSpec::new("x").stable_bytes()[0], 2);
}

#[test]
fn chain_stable_bytes_encodes_leaf_cn_length_prefixed() {
    let spec = ChainSpec::new("XY");
    let bytes = spec.stable_bytes();
    // byte 0: version (2)
    // bytes 1..5: leaf_cn length as u32 BE = 2
    assert_eq!(&bytes[1..5], &[0, 0, 0, 2]);
    // bytes 5..7: "XY"
    assert_eq!(&bytes[5..7], b"XY");
}

#[test]
fn chain_stable_bytes_san_sorting_and_dedup() {
    let a = ChainSpec::new("t").with_sans(vec![
        "z.test".into(),
        "a.test".into(),
        "m.test".into(),
        "a.test".into(),
    ]);
    let b = ChainSpec::new("t").with_sans(vec!["a.test".into(), "m.test".into(), "z.test".into()]);
    assert_eq!(a.stable_bytes(), b.stable_bytes());
}

#[test]
fn chain_stable_bytes_none_offset_single_byte() {
    let base = ChainSpec::new("t");
    let bytes = base.stable_bytes();
    let len = bytes.len();

    // With None offsets, the last two bytes should be tag-only (0, 0).
    // None encodes as just `0` (one byte), while Some encodes as `1` + 8 bytes.
    // Setting one to Some should increase length by 8.
    let mut with_leaf = base.clone();
    with_leaf.leaf_not_before_offset_days = Some(0);
    assert_eq!(with_leaf.stable_bytes().len(), len + 8);
}

#[test]
fn chain_stable_bytes_both_offsets_set() {
    let mut spec = ChainSpec::new("t");
    spec.leaf_not_before_offset_days = Some(100);
    spec.intermediate_not_before_offset_days = Some(200);
    let bytes = spec.stable_bytes();

    let base_len = ChainSpec::new("t").stable_bytes().len();
    // Each Some adds 8 bytes (i64 encoding)
    assert_eq!(bytes.len(), base_len + 16);
}

#[test]
fn chain_stable_bytes_negative_offset() {
    let mut a = ChainSpec::new("t");
    a.leaf_not_before_offset_days = Some(-730);
    let mut b = ChainSpec::new("t");
    b.leaf_not_before_offset_days = Some(730);
    assert_ne!(a.stable_bytes(), b.stable_bytes());
}

// ===========================================================================
// ChainSpec – trait impls
// ===========================================================================

#[test]
fn chain_spec_eq_reflexive() {
    let spec = ChainSpec::new("eq");
    assert_eq!(spec, spec.clone());
}

#[test]
fn chain_spec_ne_different_leaf() {
    assert_ne!(ChainSpec::new("a"), ChainSpec::new("b"));
}

#[test]
fn chain_spec_hash_equal_values() {
    let a = ChainSpec::new("h");
    let b = ChainSpec::new("h");
    assert_eq!(hash_of(&a), hash_of(&b));
}

#[test]
fn chain_spec_hash_different_values() {
    assert_ne!(hash_of(&ChainSpec::new("x")), hash_of(&ChainSpec::new("y")));
}

#[test]
fn chain_spec_debug_contains_field_names() {
    let spec = ChainSpec::new("dbg.test");
    let dbg = format!("{spec:?}");
    for field in [
        "leaf_cn",
        "leaf_sans",
        "root_cn",
        "intermediate_cn",
        "rsa_bits",
        "root_validity_days",
        "intermediate_validity_days",
        "leaf_validity_days",
        "leaf_not_before_offset_days",
        "intermediate_not_before_offset_days",
    ] {
        assert!(dbg.contains(field), "Debug output missing field: {field}");
    }
}

#[test]
fn chain_spec_can_be_stored_in_hashset() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(ChainSpec::new("a"));
    set.insert(ChainSpec::new("a"));
    set.insert(ChainSpec::new("b"));
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// Cross-type: X509Spec vs ChainSpec stable_bytes don't collide
// ===========================================================================

#[test]
fn x509_and_chain_stable_bytes_differ_for_same_cn() {
    let x509_bytes = X509Spec::self_signed("test.example.com").stable_bytes();
    let chain_bytes = ChainSpec::new("test.example.com").stable_bytes();
    // Different version prefixes (4 vs 2) guarantee no collision.
    assert_ne!(x509_bytes[0], chain_bytes[0]);
    assert_ne!(x509_bytes, chain_bytes);
}

// ===========================================================================
// Property tests
// ===========================================================================

proptest! {
    #[test]
    fn x509_stable_bytes_length_positive(
        cn in "[a-z]{0,32}",
        validity in 0u32..10_000,
    ) {
        let spec = X509Spec::self_signed(&cn).with_validity_days(validity);
        prop_assert!(!spec.stable_bytes().is_empty());
    }

    #[test]
    fn x509_clone_preserves_stable_bytes(
        cn in "[a-z]{1,16}",
        validity in 0u32..10_000,
        rsa_bits in prop::sample::select(vec![1024usize, 2048, 4096]),
    ) {
        let spec = X509Spec::self_signed(&cn)
            .with_validity_days(validity)
            .with_rsa_bits(rsa_bits);
        let cloned = spec.clone();
        prop_assert_eq!(spec.stable_bytes(), cloned.stable_bytes());
        prop_assert_eq!(spec, cloned);
    }

    #[test]
    fn x509_debug_roundtrips_subject_cn(cn in "[a-z]{1,16}") {
        let spec = X509Spec::self_signed(&cn);
        let dbg = format!("{spec:?}");
        prop_assert!(dbg.contains(&cn));
    }

    #[test]
    fn x509_different_validity_different_bytes(
        cn in "[a-z]{1,8}",
        v1 in 0u32..5_000,
        v2 in 5_000u32..10_000,
    ) {
        let a = X509Spec::self_signed(&cn).with_validity_days(v1);
        let b = X509Spec::self_signed(&cn).with_validity_days(v2);
        prop_assert_ne!(a.stable_bytes(), b.stable_bytes());
    }

    #[test]
    fn x509_different_rsa_bits_different_bytes(
        cn in "[a-z]{1,8}",
        bits1 in prop::sample::select(vec![1024usize, 2048]),
        bits2 in prop::sample::select(vec![4096usize, 8192]),
    ) {
        let a = X509Spec::self_signed(&cn).with_rsa_bits(bits1);
        let b = X509Spec::self_signed(&cn).with_rsa_bits(bits2);
        prop_assert_ne!(a.stable_bytes(), b.stable_bytes());
    }

    #[test]
    fn x509_not_after_always_gte_validity(
        validity in 0u32..10_000,
        offset in 0u32..10_000,
    ) {
        let spec = X509Spec::self_signed("t")
            .with_not_before(NotBeforeOffset::DaysFromNow(offset))
            .with_validity_days(validity);
        let min = Duration::from_secs(validity as u64 * DAY_SECS);
        prop_assert!(spec.not_after_duration() >= min);
    }

    #[test]
    fn chain_clone_preserves_stable_bytes(
        cn in "[a-z]{1,16}",
        rsa_bits in prop::sample::select(vec![1024usize, 2048, 4096]),
    ) {
        let spec = ChainSpec::new(&cn).with_rsa_bits(rsa_bits);
        let cloned = spec.clone();
        prop_assert_eq!(spec.stable_bytes(), cloned.stable_bytes());
        prop_assert_eq!(spec, cloned);
    }

    #[test]
    fn chain_debug_roundtrips_leaf_cn(cn in "[a-z]{1,16}") {
        let spec = ChainSpec::new(&cn);
        let dbg = format!("{spec:?}");
        prop_assert!(dbg.contains(&cn));
    }

    #[test]
    fn chain_stable_bytes_length_grows_with_cn(
        short in "[a-z]{1,4}",
        long in "[a-z]{20,32}",
    ) {
        let short_bytes = ChainSpec::new(&short).stable_bytes();
        let long_bytes = ChainSpec::new(&long).stable_bytes();
        // Longer CN => longer stable_bytes (CN appears in leaf_cn, root_cn, intermediate_cn, and sans)
        prop_assert!(long_bytes.len() > short_bytes.len());
    }

    #[test]
    fn key_usage_stable_bytes_only_zero_or_one(
        kcs: bool,
        cs: bool,
        ds: bool,
        ke: bool,
    ) {
        let ku = KeyUsage {
            key_cert_sign: kcs,
            crl_sign: cs,
            digital_signature: ds,
            key_encipherment: ke,
        };
        for b in ku.stable_bytes() {
            prop_assert!(b == 0 || b == 1);
        }
    }
}
