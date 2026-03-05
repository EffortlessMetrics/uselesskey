//! Comprehensive tests for chain-level negative fixtures.
//!
//! Covers:
//! 1. Invalid chain structures (hostname mismatch, unknown CA, etc.)
//! 2. Expired certificate generation for leaf and intermediate
//! 3. Revoked certificate indicators
//! 4. Self-signed vs CA-signed chain structures
//! 5. Determinism verification
//! 6. Stable-bytes sensitivity

use std::collections::HashSet;

use proptest::prelude::*;
use rstest::rstest;
use uselesskey_core_x509_chain_negative::ChainNegative;
use uselesskey_core_x509_spec::ChainSpec;

// =========================================================================
// 1. Invalid chain structures
// =========================================================================

#[test]
fn hostname_mismatch_produces_wrong_leaf_identity() {
    let base = ChainSpec::new("api.example.com");
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.example.com".to_string(),
    };
    let modified = neg.apply_to_spec(&base);

    // The leaf identity is wrong — a TLS verifier should reject this.
    assert_ne!(
        modified.leaf_cn, base.leaf_cn,
        "hostname mismatch must change the leaf CN"
    );
    assert_eq!(modified.leaf_cn, "evil.example.com");
    assert_eq!(
        modified.leaf_sans,
        vec!["evil.example.com".to_string()],
        "SANs must also be replaced"
    );
}

#[test]
fn unknown_ca_produces_unrecognized_root() {
    let base = ChainSpec::new("trusted.example.com");
    let modified = ChainNegative::UnknownCa.apply_to_spec(&base);

    // The root CN changed — a trust store would not recognize this root.
    assert_ne!(
        modified.root_cn, base.root_cn,
        "UnknownCa must change the root CN"
    );
    assert!(
        modified.root_cn.contains("Unknown"),
        "root CN must signal it's an unknown CA"
    );
}

#[test]
fn expired_leaf_produces_past_dated_leaf() {
    let base = ChainSpec::new("fresh.example.com");
    let modified = ChainNegative::ExpiredLeaf.apply_to_spec(&base);

    // Short validity + far-past not_before = expired leaf.
    assert_eq!(modified.leaf_validity_days, 1);
    let offset = modified
        .leaf_not_before_offset_days
        .expect("expired leaf must set not_before_offset");
    assert!(
        offset > modified.leaf_validity_days as i64,
        "offset ({offset}) must exceed validity ({v}) for the leaf to be expired",
        v = modified.leaf_validity_days
    );
}

#[test]
fn expired_intermediate_produces_past_dated_intermediate() {
    let base = ChainSpec::new("fresh.example.com");
    let modified = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);

    assert_eq!(modified.intermediate_validity_days, 1);
    let offset = modified
        .intermediate_not_before_offset_days
        .expect("expired intermediate must set not_before_offset");
    assert!(
        offset > modified.intermediate_validity_days as i64,
        "offset ({offset}) must exceed validity ({v}) for the intermediate to be expired",
        v = modified.intermediate_validity_days
    );
}

#[test]
fn revoked_leaf_chain_is_structurally_valid() {
    let base = ChainSpec::new("revoked.example.com");
    let modified = ChainNegative::RevokedLeaf.apply_to_spec(&base);

    // The spec is unchanged — revocation is signalled via CRL, not spec mutation.
    assert_eq!(modified, base, "RevokedLeaf must not modify the chain spec");
}

// =========================================================================
// 2. Each negative variant modifies the expected stable_bytes
// =========================================================================

#[test]
fn non_revoked_variants_change_stable_bytes() {
    let base = ChainSpec::new("bytes-test.example.com");
    let base_bytes = base.stable_bytes();

    let modifying_variants: Vec<ChainNegative> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "wrong.example.com".to_string(),
        },
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
    ];

    for variant in &modifying_variants {
        let modified = variant.apply_to_spec(&base);
        assert_ne!(
            modified.stable_bytes(),
            base_bytes,
            "{variant:?} must change stable_bytes"
        );
    }
}

#[test]
fn revoked_leaf_does_not_change_stable_bytes() {
    let base = ChainSpec::new("revoked-bytes.example.com");
    let modified = ChainNegative::RevokedLeaf.apply_to_spec(&base);
    assert_eq!(
        modified.stable_bytes(),
        base.stable_bytes(),
        "RevokedLeaf must not change stable_bytes"
    );
}

#[test]
fn all_modifying_variants_produce_distinct_stable_bytes() {
    let base = ChainSpec::new("distinct-bytes.example.com");
    let variants: Vec<ChainNegative> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "wrong.example.com".to_string(),
        },
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
    ];

    let bytes: Vec<Vec<u8>> = variants
        .iter()
        .map(|v| v.apply_to_spec(&base).stable_bytes())
        .collect();

    for i in 0..bytes.len() {
        for j in (i + 1)..bytes.len() {
            assert_ne!(
                bytes[i], bytes[j],
                "{:?} and {:?} must produce different stable_bytes",
                variants[i], variants[j]
            );
        }
    }
}

// =========================================================================
// 3. Self-signed vs CA-signed chain structures
// =========================================================================

#[test]
fn chain_spec_default_has_three_distinct_identities() {
    let spec = ChainSpec::new("leaf.example.com");

    let identities: HashSet<&str> = [
        spec.root_cn.as_str(),
        spec.intermediate_cn.as_str(),
        spec.leaf_cn.as_str(),
    ]
    .into_iter()
    .collect();

    assert_eq!(
        identities.len(),
        3,
        "chain must have three distinct CN identities"
    );
}

#[test]
fn chain_spec_root_identity_includes_root_ca() {
    let spec = ChainSpec::new("myapp.example.com");
    assert!(
        spec.root_cn.contains("Root CA"),
        "root CN should contain 'Root CA': {}",
        spec.root_cn
    );
}

#[test]
fn chain_spec_intermediate_identity_includes_intermediate_ca() {
    let spec = ChainSpec::new("myapp.example.com");
    assert!(
        spec.intermediate_cn.contains("Intermediate CA"),
        "intermediate CN should contain 'Intermediate CA': {}",
        spec.intermediate_cn
    );
}

#[test]
fn unknown_ca_maintains_three_level_structure() {
    let base = ChainSpec::new("structure.example.com");
    let modified = ChainNegative::UnknownCa.apply_to_spec(&base);

    // Still three distinct identities after applying UnknownCa
    let identities: HashSet<&str> = [
        modified.root_cn.as_str(),
        modified.intermediate_cn.as_str(),
        modified.leaf_cn.as_str(),
    ]
    .into_iter()
    .collect();

    assert_eq!(identities.len(), 3);
}

#[test]
fn hostname_mismatch_maintains_ca_hierarchy() {
    let base = ChainSpec::new("hierarchy.example.com");
    let modified = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.example.com".to_string(),
    }
    .apply_to_spec(&base);

    // CA hierarchy unchanged
    assert_eq!(modified.root_cn, base.root_cn);
    assert_eq!(modified.intermediate_cn, base.intermediate_cn);
    // Only leaf changed
    assert_ne!(modified.leaf_cn, base.leaf_cn);
}

// =========================================================================
// 4. Determinism verification
// =========================================================================

#[rstest]
#[case::unknown_ca(ChainNegative::UnknownCa)]
#[case::expired_leaf(ChainNegative::ExpiredLeaf)]
#[case::expired_intermediate(ChainNegative::ExpiredIntermediate)]
#[case::revoked_leaf(ChainNegative::RevokedLeaf)]
fn unit_variant_apply_is_deterministic(#[case] variant: ChainNegative) {
    let base = ChainSpec::new("deterministic.example.com")
        .with_rsa_bits(4096)
        .with_root_cn("Stable Root CA")
        .with_intermediate_cn("Stable Int CA")
        .with_root_validity_days(7300)
        .with_leaf_validity_days(365);

    let first = variant.apply_to_spec(&base);
    let second = variant.apply_to_spec(&base);

    assert_eq!(first, second, "{variant:?} must be deterministic");
    assert_eq!(first.stable_bytes(), second.stable_bytes());
}

#[test]
fn hostname_mismatch_apply_is_deterministic() {
    let base = ChainSpec::new("deterministic.example.com");
    let variant = ChainNegative::HostnameMismatch {
        wrong_hostname: "wrong.example.com".to_string(),
    };

    let first = variant.apply_to_spec(&base);
    let second = variant.apply_to_spec(&base);

    assert_eq!(first, second);
    assert_eq!(first.stable_bytes(), second.stable_bytes());
}

#[test]
fn variant_name_is_deterministic() {
    let variants: Vec<ChainNegative> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "test.com".to_string(),
        },
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
        ChainNegative::RevokedLeaf,
    ];

    for variant in &variants {
        let name1 = variant.variant_name();
        let name2 = variant.variant_name();
        assert_eq!(name1, name2, "{variant:?} variant_name must be stable");
    }
}

// =========================================================================
// 5. Expired cert timing specifics
// =========================================================================

#[test]
fn expired_leaf_exact_values() {
    let base = ChainSpec::new("exact.example.com");
    let modified = ChainNegative::ExpiredLeaf.apply_to_spec(&base);

    assert_eq!(modified.leaf_validity_days, 1);
    assert_eq!(modified.leaf_not_before_offset_days, Some(730));

    // 730 days ago + 1 day validity = expired 729 days ago
    let days_since_expired =
        modified.leaf_not_before_offset_days.unwrap() - modified.leaf_validity_days as i64;
    assert_eq!(days_since_expired, 729);
}

#[test]
fn expired_intermediate_exact_values() {
    let base = ChainSpec::new("exact.example.com");
    let modified = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);

    assert_eq!(modified.intermediate_validity_days, 1);
    assert_eq!(modified.intermediate_not_before_offset_days, Some(730));

    let days_since_expired = modified.intermediate_not_before_offset_days.unwrap()
        - modified.intermediate_validity_days as i64;
    assert_eq!(days_since_expired, 729);
}

// =========================================================================
// 6. Field isolation across variants
// =========================================================================

#[test]
fn expired_leaf_does_not_touch_root_or_intermediate_timing() {
    let base = ChainSpec::new("isolated.example.com")
        .with_root_validity_days(7300)
        .with_intermediate_validity_days(3650);
    let modified = ChainNegative::ExpiredLeaf.apply_to_spec(&base);

    assert_eq!(modified.root_validity_days, 7300);
    assert_eq!(modified.intermediate_validity_days, 3650);
    assert_eq!(
        modified.intermediate_not_before_offset_days,
        base.intermediate_not_before_offset_days
    );
}

#[test]
fn expired_intermediate_does_not_touch_root_or_leaf_timing() {
    let base = ChainSpec::new("isolated.example.com")
        .with_root_validity_days(7300)
        .with_leaf_validity_days(365);
    let modified = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);

    assert_eq!(modified.root_validity_days, 7300);
    assert_eq!(modified.leaf_validity_days, 365);
    assert_eq!(
        modified.leaf_not_before_offset_days,
        base.leaf_not_before_offset_days
    );
}

#[test]
fn unknown_ca_does_not_touch_timing_fields() {
    let base = ChainSpec::new("timing-iso.example.com")
        .with_root_validity_days(7300)
        .with_intermediate_validity_days(3650)
        .with_leaf_validity_days(365);
    let modified = ChainNegative::UnknownCa.apply_to_spec(&base);

    assert_eq!(modified.root_validity_days, 7300);
    assert_eq!(modified.intermediate_validity_days, 3650);
    assert_eq!(modified.leaf_validity_days, 365);
    assert_eq!(
        modified.leaf_not_before_offset_days,
        base.leaf_not_before_offset_days
    );
    assert_eq!(
        modified.intermediate_not_before_offset_days,
        base.intermediate_not_before_offset_days
    );
}

#[test]
fn hostname_mismatch_does_not_touch_timing_or_rsa_fields() {
    let base = ChainSpec::new("timing-iso.example.com")
        .with_rsa_bits(4096)
        .with_root_validity_days(7300)
        .with_intermediate_validity_days(3650)
        .with_leaf_validity_days(365);

    let modified = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.example.com".to_string(),
    }
    .apply_to_spec(&base);

    assert_eq!(modified.rsa_bits, 4096);
    assert_eq!(modified.root_validity_days, 7300);
    assert_eq!(modified.intermediate_validity_days, 3650);
    assert_eq!(modified.leaf_validity_days, 365);
}

// =========================================================================
// Property-based tests
// =========================================================================

proptest! {
    #[test]
    fn all_unit_variants_deterministic(leaf in "[a-z]{1,15}\\.example\\.com") {
        let base = ChainSpec::new(&leaf);
        let variants = [
            ChainNegative::UnknownCa,
            ChainNegative::ExpiredLeaf,
            ChainNegative::ExpiredIntermediate,
            ChainNegative::RevokedLeaf,
        ];
        for v in &variants {
            let a = v.apply_to_spec(&base);
            let b = v.apply_to_spec(&base);
            prop_assert_eq!(&a, &b);
            prop_assert_eq!(a.stable_bytes(), b.stable_bytes());
        }
    }

    #[test]
    fn hostname_mismatch_deterministic(
        leaf in "[a-z]{1,15}\\.example\\.com",
        wrong in "[a-z]{1,15}\\.evil\\.com",
    ) {
        let base = ChainSpec::new(&leaf);
        let v = ChainNegative::HostnameMismatch {
            wrong_hostname: wrong,
        };
        let a = v.apply_to_spec(&base);
        let b = v.apply_to_spec(&base);
        prop_assert_eq!(&a, &b);
    }

    #[test]
    fn expired_leaf_always_past(leaf in "[a-z]{1,15}\\.example\\.com") {
        let base = ChainSpec::new(&leaf);
        let modified = ChainNegative::ExpiredLeaf.apply_to_spec(&base);
        let offset = modified.leaf_not_before_offset_days.unwrap();
        let validity = modified.leaf_validity_days as i64;
        prop_assert!(offset > validity);
    }

    #[test]
    fn expired_intermediate_always_past(leaf in "[a-z]{1,15}\\.example\\.com") {
        let base = ChainSpec::new(&leaf);
        let modified = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);
        let offset = modified.intermediate_not_before_offset_days.unwrap();
        let validity = modified.intermediate_validity_days as i64;
        prop_assert!(offset > validity);
    }

    #[test]
    fn revoked_leaf_is_identity_for_any_spec(
        leaf in "[a-z]{1,15}\\.example\\.com",
        rsa_bits in prop::sample::select(vec![2048usize, 3072, 4096]),
    ) {
        let base = ChainSpec::new(&leaf).with_rsa_bits(rsa_bits);
        let modified = ChainNegative::RevokedLeaf.apply_to_spec(&base);
        prop_assert_eq!(modified, base);
    }

    #[test]
    fn unknown_ca_always_changes_root_cn(leaf in "[a-z]{1,15}\\.example\\.com") {
        let base = ChainSpec::new(&leaf);
        let modified = ChainNegative::UnknownCa.apply_to_spec(&base);
        prop_assert_ne!(&modified.root_cn, &base.root_cn);
        prop_assert!(modified.root_cn.contains("Unknown"));
    }

    #[test]
    fn hostname_mismatch_replaces_leaf_identity(
        leaf in "[a-z]{1,15}\\.example\\.com",
        wrong in "[a-z]{1,15}\\.evil\\.com",
    ) {
        let base = ChainSpec::new(&leaf);
        let v = ChainNegative::HostnameMismatch {
            wrong_hostname: wrong.clone(),
        };
        let modified = v.apply_to_spec(&base);
        prop_assert_eq!(&modified.leaf_cn, &wrong);
        prop_assert_eq!(modified.leaf_sans, vec![wrong]);
        // CA hierarchy preserved
        prop_assert_eq!(&modified.root_cn, &base.root_cn);
        prop_assert_eq!(&modified.intermediate_cn, &base.intermediate_cn);
    }
}
