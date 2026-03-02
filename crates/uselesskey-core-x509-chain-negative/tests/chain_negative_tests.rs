//! Comprehensive tests for `ChainNegative` policy types.
//!
//! Covers:
//! - All variant names are stable and distinct
//! - `apply_to_spec` modifies the correct fields for each variant
//! - Unrelated fields are preserved after applying a negative variant
//! - Edge cases: custom CNs, custom RSA bits, custom validity periods

use std::collections::HashSet;

use uselesskey_core_x509_chain_negative::ChainNegative;
use uselesskey_core_x509_spec::ChainSpec;

// =========================================================================
// variant_name stability
// =========================================================================

#[test]
fn chain_negative_variant_names_are_stable() {
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "wrong.example.com".to_string(),
    };
    assert_eq!(neg.variant_name(), "hostname_mismatch:wrong.example.com");
    assert_eq!(ChainNegative::UnknownCa.variant_name(), "unknown_ca");
    assert_eq!(ChainNegative::ExpiredLeaf.variant_name(), "expired_leaf");
    assert_eq!(
        ChainNegative::ExpiredIntermediate.variant_name(),
        "expired_intermediate"
    );
    assert_eq!(ChainNegative::RevokedLeaf.variant_name(), "revoked_leaf");
}

#[test]
fn all_variant_names_are_distinct() {
    let names: Vec<String> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "x.com".to_string(),
        }
        .variant_name(),
        ChainNegative::UnknownCa.variant_name(),
        ChainNegative::ExpiredLeaf.variant_name(),
        ChainNegative::ExpiredIntermediate.variant_name(),
        ChainNegative::RevokedLeaf.variant_name(),
    ];
    let unique: HashSet<&str> = names.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        unique.len(),
        names.len(),
        "all variant names should be distinct"
    );
}

#[test]
fn different_hostnames_produce_different_variant_names() {
    let neg1 = ChainNegative::HostnameMismatch {
        wrong_hostname: "a.com".to_string(),
    };
    let neg2 = ChainNegative::HostnameMismatch {
        wrong_hostname: "b.com".to_string(),
    };
    assert_ne!(neg1.variant_name(), neg2.variant_name());
}

// =========================================================================
// apply_to_spec: all variants in one test
// =========================================================================

#[test]
fn chain_negative_apply_to_spec_all_variants() {
    let base = ChainSpec::new("neg-test.example.com");

    let hostname_neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "wrong.example.com".to_string(),
    };
    let modified = hostname_neg.apply_to_spec(&base);
    assert_eq!(modified.leaf_cn, "wrong.example.com");
    assert_eq!(modified.leaf_sans, vec!["wrong.example.com".to_string()]);

    let unknown_neg = ChainNegative::UnknownCa;
    let modified = unknown_neg.apply_to_spec(&base);
    assert!(
        modified.root_cn.contains("Unknown"),
        "UnknownCa should modify root_cn"
    );

    let expired_leaf_neg = ChainNegative::ExpiredLeaf;
    let modified = expired_leaf_neg.apply_to_spec(&base);
    assert_eq!(modified.leaf_validity_days, 1);
    assert_eq!(modified.leaf_not_before_offset_days, Some(730));

    let expired_int_neg = ChainNegative::ExpiredIntermediate;
    let modified = expired_int_neg.apply_to_spec(&base);
    assert_eq!(modified.intermediate_validity_days, 1);
    assert_eq!(modified.intermediate_not_before_offset_days, Some(730));

    let revoked_neg = ChainNegative::RevokedLeaf;
    let modified = revoked_neg.apply_to_spec(&base);
    assert_eq!(modified.leaf_cn, base.leaf_cn);
    assert_eq!(modified.leaf_validity_days, base.leaf_validity_days);
}

// =========================================================================
// HostnameMismatch: field preservation
// =========================================================================

#[test]
fn hostname_mismatch_preserves_root_and_intermediate_cn() {
    let base = ChainSpec::new("good.example.com")
        .with_root_cn("My Root CA")
        .with_intermediate_cn("My Int CA");
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.example.com".to_string(),
    };
    let modified = neg.apply_to_spec(&base);

    assert_eq!(modified.root_cn, "My Root CA");
    assert_eq!(modified.intermediate_cn, "My Int CA");
}

#[test]
fn hostname_mismatch_preserves_rsa_bits_and_validity() {
    let base = ChainSpec::new("good.example.com")
        .with_rsa_bits(4096)
        .with_root_validity_days(7300)
        .with_intermediate_validity_days(3650)
        .with_leaf_validity_days(90);
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.example.com".to_string(),
    };
    let modified = neg.apply_to_spec(&base);

    assert_eq!(modified.rsa_bits, 4096);
    assert_eq!(modified.root_validity_days, 7300);
    assert_eq!(modified.intermediate_validity_days, 3650);
    assert_eq!(modified.leaf_validity_days, 90);
}

// =========================================================================
// UnknownCa: field preservation
// =========================================================================

#[test]
fn unknown_ca_preserves_leaf_and_intermediate_fields() {
    let base = ChainSpec::new("test.example.com").with_sans(vec![
        "test.example.com".to_string(),
        "www.example.com".to_string(),
    ]);
    let modified = ChainNegative::UnknownCa.apply_to_spec(&base);

    assert_eq!(modified.leaf_cn, base.leaf_cn);
    assert_eq!(modified.leaf_sans, base.leaf_sans);
    assert_eq!(modified.intermediate_cn, base.intermediate_cn);
    assert_eq!(modified.leaf_validity_days, base.leaf_validity_days);
    assert_eq!(
        modified.intermediate_validity_days,
        base.intermediate_validity_days
    );
}

#[test]
fn unknown_ca_root_cn_includes_leaf_cn() {
    let base = ChainSpec::new("test.example.com");
    let modified = ChainNegative::UnknownCa.apply_to_spec(&base);

    assert!(
        modified.root_cn.contains("test.example.com"),
        "UnknownCa root_cn should reference the leaf_cn"
    );
}

// =========================================================================
// ExpiredLeaf: field preservation
// =========================================================================

#[test]
fn expired_leaf_preserves_root_and_intermediate() {
    let base = ChainSpec::new("test.example.com")
        .with_root_cn("Custom Root")
        .with_intermediate_cn("Custom Int");
    let modified = ChainNegative::ExpiredLeaf.apply_to_spec(&base);

    assert_eq!(modified.root_cn, "Custom Root");
    assert_eq!(modified.root_validity_days, base.root_validity_days);
    assert_eq!(modified.intermediate_cn, "Custom Int");
    assert_eq!(
        modified.intermediate_validity_days,
        base.intermediate_validity_days
    );
    assert_eq!(
        modified.intermediate_not_before_offset_days,
        base.intermediate_not_before_offset_days
    );
}

#[test]
fn expired_leaf_preserves_leaf_cn_and_sans() {
    let base = ChainSpec::new("test.example.com");
    let modified = ChainNegative::ExpiredLeaf.apply_to_spec(&base);

    assert_eq!(modified.leaf_cn, base.leaf_cn);
    assert_eq!(modified.leaf_sans, base.leaf_sans);
}

// =========================================================================
// ExpiredIntermediate: field preservation
// =========================================================================

#[test]
fn expired_intermediate_preserves_leaf_and_root() {
    let base = ChainSpec::new("test.example.com");
    let modified = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);

    assert_eq!(modified.root_cn, base.root_cn);
    assert_eq!(modified.root_validity_days, base.root_validity_days);
    assert_eq!(modified.leaf_cn, base.leaf_cn);
    assert_eq!(modified.leaf_validity_days, base.leaf_validity_days);
    assert_eq!(
        modified.leaf_not_before_offset_days,
        base.leaf_not_before_offset_days
    );
}

// =========================================================================
// RevokedLeaf: full spec preserved
// =========================================================================

#[test]
fn revoked_leaf_does_not_modify_any_field() {
    let base = ChainSpec::new("test.example.com")
        .with_rsa_bits(4096)
        .with_root_cn("Custom Root")
        .with_intermediate_cn("Custom Int")
        .with_root_validity_days(7300)
        .with_intermediate_validity_days(3650)
        .with_leaf_validity_days(365)
        .with_sans(vec![
            "test.example.com".to_string(),
            "www.example.com".to_string(),
        ]);
    let modified = ChainNegative::RevokedLeaf.apply_to_spec(&base);

    assert_eq!(modified, base, "RevokedLeaf should not modify the spec");
}

// =========================================================================
// Trait impls: Clone, Debug, Eq, Hash
// =========================================================================

#[test]
fn clone_and_eq_work_for_all_variants() {
    let variants: Vec<ChainNegative> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "test.com".to_string(),
        },
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
        ChainNegative::RevokedLeaf,
    ];

    for v in &variants {
        let cloned = v.clone();
        assert_eq!(v, &cloned, "clone + eq should work for {:?}", v);
    }
}

#[test]
fn debug_output_is_meaningful() {
    let neg = ChainNegative::ExpiredLeaf;
    let dbg = format!("{:?}", neg);
    assert!(dbg.contains("ExpiredLeaf"));

    let neg_hm = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.example.com".to_string(),
    };
    let dbg_hm = format!("{:?}", neg_hm);
    assert!(dbg_hm.contains("HostnameMismatch"));
    assert!(dbg_hm.contains("evil.example.com"));
}

#[test]
fn hash_works_in_hashset() {
    let mut set = HashSet::new();
    set.insert(ChainNegative::UnknownCa);
    set.insert(ChainNegative::ExpiredLeaf);
    set.insert(ChainNegative::UnknownCa); // duplicate
    assert_eq!(set.len(), 2);
}

// =========================================================================
// Edge case: applying to a spec with custom base
// =========================================================================

#[test]
fn apply_to_customized_spec_preserves_unmodified_fields() {
    let base = ChainSpec::new("custom.example.com")
        .with_rsa_bits(4096)
        .with_root_cn("Custom Root")
        .with_intermediate_cn("Custom Int")
        .with_root_validity_days(7300)
        .with_intermediate_validity_days(3650)
        .with_leaf_validity_days(365);

    // UnknownCa only changes root_cn
    let modified = ChainNegative::UnknownCa.apply_to_spec(&base);
    assert_eq!(modified.rsa_bits, 4096);
    assert_eq!(modified.intermediate_cn, "Custom Int");
    assert_eq!(modified.root_validity_days, 7300);
    assert_eq!(modified.intermediate_validity_days, 3650);
    assert_eq!(modified.leaf_validity_days, 365);
}
