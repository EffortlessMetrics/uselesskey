//! Comprehensive tests for `uselesskey-core-x509-negative`.

use std::collections::HashSet;

use proptest::prelude::*;
use rstest::rstest;
use uselesskey_core_x509_negative::{ChainNegative, X509Negative};
use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

// ---------------------------------------------------------------------------
// 1. Construction of each variant
// ---------------------------------------------------------------------------

#[test]
fn x509_negative_all_variants_construct() {
    let variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];
    assert_eq!(variants.len(), 4, "update test if new variants are added");
}

#[test]
fn chain_negative_all_variants_construct() {
    let variants: Vec<ChainNegative> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "evil.example.com".into(),
        },
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
        ChainNegative::RevokedLeaf,
    ];
    assert_eq!(variants.len(), 5, "update test if new variants are added");
}

// ---------------------------------------------------------------------------
// 2. Debug formatting is meaningful
// ---------------------------------------------------------------------------

#[rstest]
#[case(X509Negative::Expired, "Expired")]
#[case(X509Negative::NotYetValid, "NotYetValid")]
#[case(X509Negative::WrongKeyUsage, "WrongKeyUsage")]
#[case(X509Negative::SelfSignedButClaimsCA, "SelfSignedButClaimsCA")]
fn x509_negative_debug_contains_variant_name(
    #[case] variant: X509Negative,
    #[case] expected_substr: &str,
) {
    let debug = format!("{variant:?}");
    assert!(
        debug.contains(expected_substr),
        "Debug output '{debug}' should contain '{expected_substr}'"
    );
}

#[test]
fn chain_negative_debug_contains_variant_info() {
    let hostname = ChainNegative::HostnameMismatch {
        wrong_hostname: "bad.example.com".into(),
    };
    let debug = format!("{hostname:?}");
    assert!(debug.contains("HostnameMismatch"));
    assert!(debug.contains("bad.example.com"));

    assert!(format!("{:?}", ChainNegative::UnknownCa).contains("UnknownCa"));
    assert!(format!("{:?}", ChainNegative::ExpiredLeaf).contains("ExpiredLeaf"));
    assert!(
        format!("{:?}", ChainNegative::ExpiredIntermediate).contains("ExpiredIntermediate")
    );
    assert!(format!("{:?}", ChainNegative::RevokedLeaf).contains("RevokedLeaf"));
}

#[test]
fn x509_negative_descriptions_are_nonempty_and_distinct() {
    let variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];
    let descriptions: HashSet<&str> = variants.iter().map(|v| v.description()).collect();
    assert_eq!(
        descriptions.len(),
        variants.len(),
        "each variant must have a unique description"
    );
    for desc in &descriptions {
        assert!(!desc.is_empty());
    }
}

// ---------------------------------------------------------------------------
// 3. Different negative policies produce different specs
// ---------------------------------------------------------------------------

#[test]
fn x509_negative_variants_produce_pairwise_distinct_specs() {
    let base = X509Spec::self_signed("distinct-test");
    let variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];
    let specs: Vec<X509Spec> = variants.iter().map(|v| v.apply_to_spec(&base)).collect();

    for i in 0..specs.len() {
        for j in (i + 1)..specs.len() {
            assert_ne!(
                specs[i], specs[j],
                "{:?} and {:?} should produce different specs",
                variants[i], variants[j]
            );
        }
    }
}

#[test]
fn x509_negative_variant_names_are_pairwise_distinct() {
    let variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];
    let names: HashSet<&str> = variants.iter().map(|v| v.variant_name()).collect();
    assert_eq!(names.len(), variants.len());
}

#[test]
fn chain_negative_variant_names_are_pairwise_distinct() {
    let variants: Vec<ChainNegative> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "wrong.example.com".into(),
        },
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
        ChainNegative::RevokedLeaf,
    ];
    let names: HashSet<String> = variants.iter().map(|v| v.variant_name()).collect();
    assert_eq!(names.len(), variants.len());
}

#[test]
fn chain_negative_variants_produce_pairwise_distinct_specs() {
    let base = ChainSpec::new("distinct-chain.example.com");
    let variants: Vec<ChainNegative> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "wrong.example.com".into(),
        },
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
        // RevokedLeaf is excluded: it intentionally leaves the spec unchanged.
    ];
    let specs: Vec<ChainSpec> = variants.iter().map(|v| v.apply_to_spec(&base)).collect();

    for i in 0..specs.len() {
        for j in (i + 1)..specs.len() {
            assert_ne!(
                specs[i], specs[j],
                "{:?} and {:?} should produce different chain specs",
                variants[i], variants[j]
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Policy application changes relevant fields only
// ---------------------------------------------------------------------------

#[test]
fn expired_preserves_unrelated_fields() {
    let base = X509Spec::self_signed("preserve-test")
        .with_rsa_bits(4096)
        .with_sans(vec!["alt.example.com".into()]);
    let modified = X509Negative::Expired.apply_to_spec(&base);

    assert_eq!(modified.subject_cn, base.subject_cn);
    assert_eq!(modified.issuer_cn, base.issuer_cn);
    assert_eq!(modified.rsa_bits, base.rsa_bits);
    assert_eq!(modified.sans, base.sans);
    assert_eq!(modified.is_ca, base.is_ca);
    assert_eq!(modified.key_usage, base.key_usage);
}

#[test]
fn not_yet_valid_preserves_unrelated_fields() {
    let base = X509Spec::self_signed_ca("preserve-ca")
        .with_rsa_bits(4096)
        .with_sans(vec!["san.example.com".into()]);
    let modified = X509Negative::NotYetValid.apply_to_spec(&base);

    assert_eq!(modified.subject_cn, base.subject_cn);
    assert_eq!(modified.issuer_cn, base.issuer_cn);
    assert_eq!(modified.rsa_bits, base.rsa_bits);
    assert_eq!(modified.sans, base.sans);
    // NotYetValid only changes time fields, not CA/key_usage.
    assert_eq!(modified.is_ca, base.is_ca);
    assert_eq!(modified.key_usage, base.key_usage);
}

#[test]
fn wrong_key_usage_preserves_unrelated_fields() {
    let base = X509Spec::self_signed("ku-test")
        .with_rsa_bits(4096)
        .with_validity_days(90);
    let modified = X509Negative::WrongKeyUsage.apply_to_spec(&base);

    assert_eq!(modified.subject_cn, base.subject_cn);
    assert_eq!(modified.issuer_cn, base.issuer_cn);
    assert_eq!(modified.rsa_bits, base.rsa_bits);
    assert_eq!(modified.validity_days, base.validity_days);
    assert_eq!(modified.not_before_offset, base.not_before_offset);
    assert_eq!(modified.sans, base.sans);
}

#[test]
fn self_signed_ca_preserves_unrelated_fields() {
    let base = X509Spec::self_signed("ca-test")
        .with_rsa_bits(4096)
        .with_validity_days(90);
    let modified = X509Negative::SelfSignedButClaimsCA.apply_to_spec(&base);

    assert_eq!(modified.subject_cn, base.subject_cn);
    assert_eq!(modified.issuer_cn, base.issuer_cn);
    assert_eq!(modified.rsa_bits, base.rsa_bits);
    assert_eq!(modified.validity_days, base.validity_days);
    assert_eq!(modified.not_before_offset, base.not_before_offset);
    assert_eq!(modified.sans, base.sans);
}

// ---------------------------------------------------------------------------
// 5. Expired policy creates certificates with past expiry dates
// ---------------------------------------------------------------------------

#[test]
fn expired_spec_not_before_plus_validity_is_in_the_past() {
    let base = X509Spec::self_signed("expired-check");
    let expired = X509Negative::Expired.apply_to_spec(&base);

    // not_before_offset = DaysAgo(395), validity_days = 365
    // not_after = now - 395 + 365 = now - 30 days -> in the past
    match expired.not_before_offset {
        NotBeforeOffset::DaysAgo(days_ago) => {
            assert!(
                days_ago > expired.validity_days,
                "DaysAgo({days_ago}) must exceed validity_days({}) for expiry to be in the past",
                expired.validity_days
            );
        }
        other => panic!("Expected DaysAgo, got {other:?}"),
    }
}

#[test]
fn not_yet_valid_spec_not_before_is_in_the_future() {
    let base = X509Spec::self_signed("future-check");
    let nyv = X509Negative::NotYetValid.apply_to_spec(&base);

    match nyv.not_before_offset {
        NotBeforeOffset::DaysFromNow(days) => {
            assert!(days > 0, "DaysFromNow must be positive for not-yet-valid");
        }
        other => panic!("Expected DaysFromNow, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 6. HostnameMismatch (wrong CN) changes the common name
// ---------------------------------------------------------------------------

#[test]
fn hostname_mismatch_changes_leaf_cn_and_sans() {
    let base = ChainSpec::new("correct.example.com");
    let wrong = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.example.com".into(),
    };
    let modified = wrong.apply_to_spec(&base);

    assert_eq!(modified.leaf_cn, "evil.example.com");
    assert_eq!(modified.leaf_sans, vec!["evil.example.com".to_string()]);
    // Other chain fields remain unchanged.
    assert_eq!(modified.root_cn, base.root_cn);
    assert_eq!(modified.intermediate_cn, base.intermediate_cn);
    assert_eq!(modified.rsa_bits, base.rsa_bits);
    assert_eq!(modified.root_validity_days, base.root_validity_days);
    assert_eq!(modified.leaf_validity_days, base.leaf_validity_days);
}

#[test]
fn unknown_ca_changes_only_root_cn() {
    let base = ChainSpec::new("leaf.example.com");
    let modified = ChainNegative::UnknownCa.apply_to_spec(&base);

    assert_ne!(modified.root_cn, base.root_cn);
    assert!(modified.root_cn.contains("Unknown"));
    // Leaf and intermediate are unchanged.
    assert_eq!(modified.leaf_cn, base.leaf_cn);
    assert_eq!(modified.leaf_sans, base.leaf_sans);
    assert_eq!(modified.intermediate_cn, base.intermediate_cn);
}

// ---------------------------------------------------------------------------
// 7. Self-signed vs CA-signed negative fixtures
// ---------------------------------------------------------------------------

#[test]
fn wrong_key_usage_turns_leaf_into_ca_without_cert_sign() {
    let leaf = X509Spec::self_signed("leaf");
    assert!(!leaf.is_ca);

    let modified = X509Negative::WrongKeyUsage.apply_to_spec(&leaf);
    assert!(modified.is_ca, "WrongKeyUsage should set is_ca = true");
    assert!(
        !modified.key_usage.key_cert_sign,
        "WrongKeyUsage must NOT grant key_cert_sign"
    );
    assert!(
        !modified.key_usage.crl_sign,
        "WrongKeyUsage must NOT grant crl_sign"
    );
}

#[test]
fn self_signed_but_claims_ca_grants_ca_key_usage() {
    let leaf = X509Spec::self_signed("leaf");
    let modified = X509Negative::SelfSignedButClaimsCA.apply_to_spec(&leaf);

    assert!(modified.is_ca);
    assert_eq!(modified.key_usage, KeyUsage::ca());
    assert!(modified.key_usage.key_cert_sign);
    assert!(modified.key_usage.crl_sign);
}

#[test]
fn wrong_key_usage_on_ca_base_still_removes_cert_sign() {
    let ca = X509Spec::self_signed_ca("My CA");
    assert!(ca.is_ca);
    assert!(ca.key_usage.key_cert_sign);

    let modified = X509Negative::WrongKeyUsage.apply_to_spec(&ca);
    assert!(modified.is_ca);
    assert!(
        !modified.key_usage.key_cert_sign,
        "WrongKeyUsage must strip key_cert_sign even from a CA base"
    );
}

#[test]
fn expired_on_ca_base_preserves_ca_flag() {
    let ca = X509Spec::self_signed_ca("CA-Expired");
    let modified = X509Negative::Expired.apply_to_spec(&ca);

    assert!(modified.is_ca, "Expired should not change is_ca");
    assert_eq!(
        modified.key_usage, ca.key_usage,
        "Expired should not change key_usage"
    );
}

// ---------------------------------------------------------------------------
// Chain negative: expired leaf vs expired intermediate
// ---------------------------------------------------------------------------

#[test]
fn expired_leaf_only_affects_leaf_fields() {
    let base = ChainSpec::new("chain.example.com");
    let modified = ChainNegative::ExpiredLeaf.apply_to_spec(&base);

    assert_eq!(modified.leaf_validity_days, 1);
    assert_eq!(modified.leaf_not_before_offset_days, Some(730));
    // Intermediate untouched.
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
fn expired_intermediate_only_affects_intermediate_fields() {
    let base = ChainSpec::new("chain.example.com");
    let modified = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);

    assert_eq!(modified.intermediate_validity_days, 1);
    assert_eq!(modified.intermediate_not_before_offset_days, Some(730));
    // Leaf untouched.
    assert_eq!(modified.leaf_validity_days, base.leaf_validity_days);
    assert_eq!(
        modified.leaf_not_before_offset_days,
        base.leaf_not_before_offset_days
    );
}

#[test]
fn revoked_leaf_does_not_change_spec() {
    let base = ChainSpec::new("revoked.example.com");
    let modified = ChainNegative::RevokedLeaf.apply_to_spec(&base);
    assert_eq!(modified, base);
}

// ---------------------------------------------------------------------------
// Trait derivations: Clone, Eq, Hash
// ---------------------------------------------------------------------------

#[test]
fn x509_negative_clone_and_eq() {
    let a = X509Negative::Expired;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn x509_negative_hash_consistency() {
    let mut set = HashSet::new();
    set.insert(X509Negative::Expired);
    set.insert(X509Negative::Expired);
    assert_eq!(set.len(), 1);
    set.insert(X509Negative::NotYetValid);
    assert_eq!(set.len(), 2);
}

#[test]
fn chain_negative_clone_and_eq() {
    let a = ChainNegative::ExpiredLeaf;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn chain_negative_hash_consistency() {
    let mut set = HashSet::new();
    set.insert(ChainNegative::UnknownCa);
    set.insert(ChainNegative::UnknownCa);
    assert_eq!(set.len(), 1);
    set.insert(ChainNegative::RevokedLeaf);
    assert_eq!(set.len(), 2);
}

#[test]
fn hostname_mismatch_eq_depends_on_hostname() {
    let a = ChainNegative::HostnameMismatch {
        wrong_hostname: "a.example.com".into(),
    };
    let b = ChainNegative::HostnameMismatch {
        wrong_hostname: "b.example.com".into(),
    };
    assert_ne!(a, b);

    let a2 = ChainNegative::HostnameMismatch {
        wrong_hostname: "a.example.com".into(),
    };
    assert_eq!(a, a2);
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn x509_all_variants_produce_different_specs_for_any_base(
        cn in "[a-z]{1,20}",
        validity in 1u32..5000,
        rsa_bits in prop::sample::select(vec![2048usize, 3072, 4096]),
    ) {
        let base = X509Spec::self_signed(&cn)
            .with_validity_days(validity)
            .with_rsa_bits(rsa_bits);

        let specs: Vec<X509Spec> = [
            X509Negative::Expired,
            X509Negative::NotYetValid,
            X509Negative::WrongKeyUsage,
            X509Negative::SelfSignedButClaimsCA,
        ]
        .iter()
        .map(|v| v.apply_to_spec(&base))
        .collect();

        // All four specs must be pairwise distinct.
        for i in 0..specs.len() {
            for j in (i + 1)..specs.len() {
                prop_assert_ne!(&specs[i], &specs[j]);
            }
        }
    }

    #[test]
    fn expired_always_in_past(cn in "[a-z]{1,20}") {
        let base = X509Spec::self_signed(&cn);
        let expired = X509Negative::Expired.apply_to_spec(&base);

        if let NotBeforeOffset::DaysAgo(ago) = expired.not_before_offset {
            prop_assert!(
                ago > expired.validity_days,
                "not_after must be in the past: DaysAgo({ago}) > validity({v})",
                v = expired.validity_days
            );
        } else {
            panic!("Expired must use DaysAgo");
        }
    }

    #[test]
    fn not_yet_valid_always_future(cn in "[a-z]{1,20}") {
        let base = X509Spec::self_signed(&cn);
        let nyv = X509Negative::NotYetValid.apply_to_spec(&base);

        if let NotBeforeOffset::DaysFromNow(days) = nyv.not_before_offset {
            prop_assert!(days > 0);
        } else {
            panic!("NotYetValid must use DaysFromNow");
        }
    }

    #[test]
    fn chain_hostname_mismatch_replaces_cn(
        leaf in "[a-z]{1,16}\\.[a-z]{1,8}",
        wrong in "[a-z]{1,16}\\.[a-z]{1,8}",
    ) {
        let base = ChainSpec::new(&leaf);
        let neg = ChainNegative::HostnameMismatch {
            wrong_hostname: wrong.clone(),
        };
        let modified = neg.apply_to_spec(&base);

        prop_assert_eq!(&modified.leaf_cn, &wrong);
        prop_assert_eq!(modified.leaf_sans, vec![wrong]);
    }

    #[test]
    fn chain_unknown_ca_always_mutates_root_cn(leaf in "[a-z]{1,20}") {
        let base = ChainSpec::new(&leaf);
        let modified = ChainNegative::UnknownCa.apply_to_spec(&base);

        prop_assert_ne!(&modified.root_cn, &base.root_cn);
        prop_assert!(modified.root_cn.contains("Unknown"));
    }

    #[test]
    fn chain_expired_leaf_offsets_are_consistent(leaf in "[a-z]{1,20}") {
        let base = ChainSpec::new(&leaf);
        let modified = ChainNegative::ExpiredLeaf.apply_to_spec(&base);

        let offset = modified.leaf_not_before_offset_days.unwrap();
        let validity = modified.leaf_validity_days as i64;
        // not_after = base_time - offset + validity; must be well in the past.
        prop_assert!(offset > validity, "offset({offset}) must exceed validity({validity})");
    }

    #[test]
    fn chain_expired_intermediate_offsets_are_consistent(leaf in "[a-z]{1,20}") {
        let base = ChainSpec::new(&leaf);
        let modified = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);

        let offset = modified.intermediate_not_before_offset_days.unwrap();
        let validity = modified.intermediate_validity_days as i64;
        prop_assert!(offset > validity, "offset({offset}) must exceed validity({validity})");
    }

    #[test]
    fn revoked_leaf_is_identity_transform(leaf in "[a-z]{1,20}") {
        let base = ChainSpec::new(&leaf);
        let modified = ChainNegative::RevokedLeaf.apply_to_spec(&base);
        prop_assert_eq!(modified, base);
    }
}
