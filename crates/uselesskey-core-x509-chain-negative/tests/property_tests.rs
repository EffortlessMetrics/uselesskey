//! Property-based and parameterized tests for X.509 chain negative fixtures.

#![forbid(unsafe_code)]

use proptest::prelude::*;
use rstest::rstest;
use uselesskey_core_x509_chain_negative::ChainNegative;
use uselesskey_core_x509_spec::{ChainSpec, NotBeforeOffset};

// ---------------------------------------------------------------------------
// rstest: parameterized variant_name stability
// ---------------------------------------------------------------------------

#[rstest]
#[case::unknown_ca(ChainNegative::UnknownCa, "unknown_ca")]
#[case::expired_leaf(ChainNegative::ExpiredLeaf, "expired_leaf")]
#[case::expired_intermediate(ChainNegative::ExpiredIntermediate, "expired_intermediate")]
#[case::not_yet_valid_leaf(ChainNegative::NotYetValidLeaf, "not_yet_valid_leaf")]
#[case::not_yet_valid_intermediate(
    ChainNegative::NotYetValidIntermediate,
    "not_yet_valid_intermediate"
)]
#[case::intermediate_not_ca(ChainNegative::IntermediateNotCa, "intermediate_not_ca")]
#[case::intermediate_wrong_key_usage(
    ChainNegative::IntermediateWrongKeyUsage,
    "intermediate_wrong_key_usage"
)]
#[case::revoked_leaf(ChainNegative::RevokedLeaf, "revoked_leaf")]
fn unit_variant_name_is_stable(#[case] variant: ChainNegative, #[case] expected: &str) {
    assert_eq!(variant.variant_name(), expected);
}

// ---------------------------------------------------------------------------
// rstest: each variant preserves unrelated spec fields
// ---------------------------------------------------------------------------

#[rstest]
#[case::unknown_ca(ChainNegative::UnknownCa)]
#[case::expired_leaf(ChainNegative::ExpiredLeaf)]
#[case::expired_intermediate(ChainNegative::ExpiredIntermediate)]
#[case::not_yet_valid_leaf(ChainNegative::NotYetValidLeaf)]
#[case::not_yet_valid_intermediate(ChainNegative::NotYetValidIntermediate)]
#[case::intermediate_not_ca(ChainNegative::IntermediateNotCa)]
#[case::intermediate_wrong_key_usage(ChainNegative::IntermediateWrongKeyUsage)]
#[case::revoked_leaf(ChainNegative::RevokedLeaf)]
fn variant_preserves_rsa_bits(#[case] variant: ChainNegative) {
    let base = ChainSpec::new("test.example.com").with_rsa_bits(4096);
    let modified = variant.apply_to_spec(&base);
    assert_eq!(modified.rsa_bits, 4096);
}

#[rstest]
#[case::unknown_ca(ChainNegative::UnknownCa)]
#[case::expired_leaf(ChainNegative::ExpiredLeaf)]
#[case::expired_intermediate(ChainNegative::ExpiredIntermediate)]
#[case::not_yet_valid_leaf(ChainNegative::NotYetValidLeaf)]
#[case::not_yet_valid_intermediate(ChainNegative::NotYetValidIntermediate)]
#[case::intermediate_not_ca(ChainNegative::IntermediateNotCa)]
#[case::intermediate_wrong_key_usage(ChainNegative::IntermediateWrongKeyUsage)]
#[case::revoked_leaf(ChainNegative::RevokedLeaf)]
#[case::hostname_mismatch(ChainNegative::HostnameMismatch { wrong_hostname: "evil.example.com".to_string() })]
fn apply_to_spec_returns_new_spec(#[case] variant: ChainNegative) {
    let base = ChainSpec::new("test.example.com");
    let original = base.clone();
    let _ = variant.apply_to_spec(&base);
    assert_eq!(base, original, "apply_to_spec must not mutate the input");
}

// ---------------------------------------------------------------------------
// proptest: hostname mismatch variant_name includes arbitrary hostnames
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn hostname_mismatch_variant_name_contains_hostname(hostname in "[a-z]{1,20}\\.[a-z]{2,5}") {
        let neg = ChainNegative::HostnameMismatch {
            wrong_hostname: hostname.clone(),
        };
        let name = neg.variant_name();
        prop_assert!(name.starts_with("hostname_mismatch:"));
        prop_assert!(name.contains(&hostname));
    }

    #[test]
    fn hostname_mismatch_apply_sets_leaf_cn(hostname in "[a-z]{1,20}\\.[a-z]{2,5}") {
        let base = ChainSpec::new("original.example.com");
        let neg = ChainNegative::HostnameMismatch {
            wrong_hostname: hostname.clone(),
        };
        let spec = neg.apply_to_spec(&base);
        prop_assert_eq!(spec.leaf_cn, hostname.clone());
        prop_assert_eq!(spec.leaf_sans, vec![hostname]);
    }

    #[test]
    fn hostname_mismatch_preserves_root_and_intermediate(hostname in "[a-z]{1,20}\\.[a-z]{2,5}") {
        let base = ChainSpec::new("original.example.com");
        let neg = ChainNegative::HostnameMismatch {
            wrong_hostname: hostname,
        };
        let spec = neg.apply_to_spec(&base);
        prop_assert_eq!(spec.root_cn, base.root_cn);
        prop_assert_eq!(spec.intermediate_cn, base.intermediate_cn);
    }
}

// ---------------------------------------------------------------------------
// proptest: expired variants always produce past-dated certs
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn expired_leaf_validity_is_one_day(leaf_cn in "[a-z]{1,15}\\.example\\.com") {
        let base = ChainSpec::new(leaf_cn);
        let spec = ChainNegative::ExpiredLeaf.apply_to_spec(&base);
        prop_assert_eq!(spec.leaf_validity_days, 1);
        prop_assert_eq!(spec.leaf_not_before, Some(NotBeforeOffset::DaysAgo(730)));
    }

    #[test]
    fn expired_intermediate_validity_is_one_day(leaf_cn in "[a-z]{1,15}\\.example\\.com") {
        let base = ChainSpec::new(leaf_cn);
        let spec = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);
        prop_assert_eq!(spec.intermediate_validity_days, 1);
        prop_assert_eq!(
            spec.intermediate_not_before,
            Some(NotBeforeOffset::DaysAgo(730))
        );
    }

    #[test]
    fn not_yet_valid_leaf_has_future_offset(leaf_cn in "[a-z]{1,15}\\.example\\.com") {
        let base = ChainSpec::new(leaf_cn);
        let spec = ChainNegative::NotYetValidLeaf.apply_to_spec(&base);
        prop_assert_eq!(spec.leaf_not_before, Some(NotBeforeOffset::DaysFromNow(730)));
    }

    #[test]
    fn not_yet_valid_intermediate_has_future_offset(leaf_cn in "[a-z]{1,15}\\.example\\.com") {
        let base = ChainSpec::new(leaf_cn);
        let spec = ChainNegative::NotYetValidIntermediate.apply_to_spec(&base);
        prop_assert_eq!(
            spec.intermediate_not_before,
            Some(NotBeforeOffset::DaysFromNow(730))
        );
    }
}

// ---------------------------------------------------------------------------
// Clone and equality for HostnameMismatch with various hostnames
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn hostname_mismatch_clone_eq(hostname in "[a-z]{1,30}") {
        let neg = ChainNegative::HostnameMismatch {
            wrong_hostname: hostname,
        };
        let cloned = neg.clone();
        prop_assert_eq!(neg, cloned);
    }
}

// ---------------------------------------------------------------------------
// Edge cases: empty hostname
// ---------------------------------------------------------------------------

#[test]
fn hostname_mismatch_empty_hostname() {
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: String::new(),
    };
    assert_eq!(neg.variant_name(), "hostname_mismatch:");
}

#[test]
fn hostname_mismatch_empty_hostname_applies() {
    let base = ChainSpec::new("test.example.com");
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: String::new(),
    };
    let spec = neg.apply_to_spec(&base);
    assert_eq!(spec.leaf_cn, "");
    assert_eq!(spec.leaf_sans, vec![String::new()]);
}

// ---------------------------------------------------------------------------
// Unknown CA: root_cn always contains "Unknown"
// ---------------------------------------------------------------------------

#[test]
fn unknown_ca_root_cn_format() {
    let base = ChainSpec::new("myhost.example.com");
    let spec = ChainNegative::UnknownCa.apply_to_spec(&base);
    assert!(
        spec.root_cn.contains("Unknown"),
        "root_cn should contain 'Unknown': {}",
        spec.root_cn
    );
    assert!(
        spec.root_cn.contains(&base.leaf_cn),
        "root_cn should reference leaf_cn: {}",
        spec.root_cn
    );
}

// ---------------------------------------------------------------------------
// Revoked leaf: spec is identical to base
// ---------------------------------------------------------------------------

#[test]
fn revoked_leaf_spec_eq_base_with_custom_spec() {
    let base = ChainSpec::new("revoked.example.com")
        .with_rsa_bits(4096)
        .with_sans(vec![
            "revoked.example.com".to_string(),
            "alt.example.com".to_string(),
        ]);
    let spec = ChainNegative::RevokedLeaf.apply_to_spec(&base);
    assert_eq!(spec, base);
}

// ---------------------------------------------------------------------------
// Expired variants don't touch each other's fields
// ---------------------------------------------------------------------------

#[test]
fn expired_leaf_does_not_change_intermediate_offset() {
    let base = ChainSpec::new("test.example.com");
    let spec = ChainNegative::ExpiredLeaf.apply_to_spec(&base);
    assert_eq!(spec.intermediate_not_before, base.intermediate_not_before);
    assert_eq!(
        spec.intermediate_validity_days,
        base.intermediate_validity_days
    );
}

#[test]
fn expired_intermediate_does_not_change_leaf_offset() {
    let base = ChainSpec::new("test.example.com");
    let spec = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);
    assert_eq!(spec.leaf_not_before, base.leaf_not_before);
    assert_eq!(spec.leaf_validity_days, base.leaf_validity_days);
}

#[test]
fn intermediate_path_negatives_preserve_unrelated_fields() {
    let base = ChainSpec::new("test.example.com").with_rsa_bits(4096);

    let not_ca = ChainNegative::IntermediateNotCa.apply_to_spec(&base);
    assert_eq!(not_ca.rsa_bits, 4096);
    assert_eq!(not_ca.root_cn, base.root_cn);
    assert_eq!(not_ca.leaf_cn, base.leaf_cn);

    let wrong_ku = ChainNegative::IntermediateWrongKeyUsage.apply_to_spec(&base);
    assert_eq!(wrong_ku.rsa_bits, 4096);
    assert_eq!(wrong_ku.root_cn, base.root_cn);
    assert_eq!(wrong_ku.leaf_cn, base.leaf_cn);
    assert_eq!(wrong_ku.intermediate_is_ca, Some(true));
}

// ---------------------------------------------------------------------------
// Hash: HostnameMismatch with different hostnames have different hashes
// ---------------------------------------------------------------------------

#[test]
fn hostname_mismatch_different_hostnames_different_hash() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let a = ChainNegative::HostnameMismatch {
        wrong_hostname: "one.example.com".to_string(),
    };
    let b = ChainNegative::HostnameMismatch {
        wrong_hostname: "two.example.com".to_string(),
    };
    let mut h1 = DefaultHasher::new();
    a.hash(&mut h1);
    let mut h2 = DefaultHasher::new();
    b.hash(&mut h2);
    assert_ne!(h1.finish(), h2.finish());
}
