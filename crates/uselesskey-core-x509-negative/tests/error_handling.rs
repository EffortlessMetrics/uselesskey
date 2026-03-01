//! Error handling and edge case tests for `uselesskey-core-x509-negative`.

use rstest::rstest;
use uselesskey_core_x509_negative::{ChainNegative, X509Negative};
use uselesskey_core_x509_spec::{ChainSpec, NotBeforeOffset, X509Spec};

// ---------------------------------------------------------------------------
// 1. Debug impls: meaningful output, no key material leakage
// ---------------------------------------------------------------------------

#[rstest]
#[case(X509Negative::Expired, "Expired")]
#[case(X509Negative::NotYetValid, "NotYetValid")]
#[case(X509Negative::WrongKeyUsage, "WrongKeyUsage")]
#[case(X509Negative::SelfSignedButClaimsCA, "SelfSignedButClaimsCA")]
fn x509_negative_debug_is_meaningful(#[case] variant: X509Negative, #[case] expected: &str) {
    let dbg = format!("{variant:?}");
    assert!(
        dbg.contains(expected),
        "Debug '{dbg}' should contain '{expected}'"
    );
    // Should not contain any PEM or key-like markers
    assert!(!dbg.contains("BEGIN"));
    assert!(!dbg.contains("PRIVATE"));
}

#[rstest]
#[case(ChainNegative::UnknownCa, "UnknownCa")]
#[case(ChainNegative::ExpiredLeaf, "ExpiredLeaf")]
#[case(ChainNegative::ExpiredIntermediate, "ExpiredIntermediate")]
#[case(ChainNegative::RevokedLeaf, "RevokedLeaf")]
fn chain_negative_debug_is_meaningful(#[case] variant: ChainNegative, #[case] expected: &str) {
    let dbg = format!("{variant:?}");
    assert!(
        dbg.contains(expected),
        "Debug '{dbg}' should contain '{expected}'"
    );
}

#[test]
fn chain_negative_hostname_mismatch_debug_shows_hostname() {
    let v = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.example.com".into(),
    };
    let dbg = format!("{v:?}");
    assert!(dbg.contains("evil.example.com"));
    assert!(dbg.contains("HostnameMismatch"));
}

// ---------------------------------------------------------------------------
// 2. Clone / Copy / Eq / Hash consistency
// ---------------------------------------------------------------------------

#[test]
fn x509_negative_copy_semantics() {
    let a = X509Negative::Expired;
    let b = a; // Copy
    let c = a; // Still usable
    assert_eq!(b, c);
}

#[test]
fn chain_negative_clone_produces_equal_variant() {
    let variants: Vec<ChainNegative> = vec![
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
        ChainNegative::RevokedLeaf,
        ChainNegative::HostnameMismatch {
            wrong_hostname: "test.example.com".into(),
        },
    ];
    for v in &variants {
        let cloned = v.clone();
        assert_eq!(v, &cloned);
        assert_eq!(v.variant_name(), cloned.variant_name());
    }
}

#[test]
fn x509_negative_ne_between_variants() {
    assert_ne!(X509Negative::Expired, X509Negative::NotYetValid);
    assert_ne!(
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA
    );
    assert_ne!(X509Negative::Expired, X509Negative::WrongKeyUsage);
}

// ---------------------------------------------------------------------------
// 3. Edge case: apply_to_spec preserves subject_cn across all variants
// ---------------------------------------------------------------------------

#[rstest]
#[case(X509Negative::Expired)]
#[case(X509Negative::NotYetValid)]
#[case(X509Negative::WrongKeyUsage)]
#[case(X509Negative::SelfSignedButClaimsCA)]
fn apply_to_spec_preserves_subject_cn(#[case] variant: X509Negative) {
    let base = X509Spec::self_signed("my-test-cn");
    let modified = variant.apply_to_spec(&base);
    assert_eq!(modified.subject_cn, base.subject_cn);
}

#[rstest]
#[case(X509Negative::Expired)]
#[case(X509Negative::NotYetValid)]
#[case(X509Negative::WrongKeyUsage)]
#[case(X509Negative::SelfSignedButClaimsCA)]
fn apply_to_spec_preserves_rsa_bits(#[case] variant: X509Negative) {
    let base = X509Spec::self_signed("bits-test").with_rsa_bits(4096);
    let modified = variant.apply_to_spec(&base);
    assert_eq!(modified.rsa_bits, 4096);
}

// ---------------------------------------------------------------------------
// 4. Expired: verify the math ensures expiry in the past
// ---------------------------------------------------------------------------

#[test]
fn expired_days_ago_exceeds_validity() {
    let base = X509Spec::self_signed("expiry-math");
    let expired = X509Negative::Expired.apply_to_spec(&base);
    if let NotBeforeOffset::DaysAgo(ago) = expired.not_before_offset {
        assert!(
            ago > expired.validity_days,
            "DaysAgo({ago}) must exceed validity({}) for cert to be expired",
            expired.validity_days,
        );
    } else {
        panic!("Expired should produce DaysAgo offset");
    }
}

// ---------------------------------------------------------------------------
// 5. NotYetValid: verify not_before is in the future
// ---------------------------------------------------------------------------

#[test]
fn not_yet_valid_offset_is_positive() {
    let base = X509Spec::self_signed("future-test");
    let nyv = X509Negative::NotYetValid.apply_to_spec(&base);
    match nyv.not_before_offset {
        NotBeforeOffset::DaysFromNow(days) => assert!(days > 0),
        other => panic!("Expected DaysFromNow, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 6. WrongKeyUsage: contradictory CA + no keyCertSign
// ---------------------------------------------------------------------------

#[test]
fn wrong_key_usage_creates_contradictory_state() {
    let base = X509Spec::self_signed("contradiction");
    let modified = X509Negative::WrongKeyUsage.apply_to_spec(&base);
    // The contradiction: is_ca is true but key_cert_sign is false
    assert!(modified.is_ca);
    assert!(!modified.key_usage.key_cert_sign);
    assert!(!modified.key_usage.crl_sign);
}

// ---------------------------------------------------------------------------
// 7. ChainNegative edge cases
// ---------------------------------------------------------------------------

#[test]
fn hostname_mismatch_empty_hostname() {
    let base = ChainSpec::new("real.example.com");
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: String::new(),
    };
    let modified = neg.apply_to_spec(&base);
    assert_eq!(modified.leaf_cn, "");
    assert_eq!(modified.leaf_sans, vec![String::new()]);
}

#[test]
fn hostname_mismatch_variant_name_includes_hostname() {
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "evil.test".into(),
    };
    let name = neg.variant_name();
    assert!(
        name.contains("evil.test"),
        "variant_name '{name}' should include the hostname"
    );
    assert!(name.starts_with("hostname_mismatch:"));
}

#[test]
fn unknown_ca_root_cn_contains_leaf_name() {
    let base = ChainSpec::new("my-service.example.com");
    let modified = ChainNegative::UnknownCa.apply_to_spec(&base);
    assert!(
        modified.root_cn.contains("my-service.example.com"),
        "root_cn '{}' should reference the leaf CN",
        modified.root_cn
    );
}

#[test]
fn expired_leaf_ensures_past_expiry() {
    let base = ChainSpec::new("expired-leaf.test");
    let modified = ChainNegative::ExpiredLeaf.apply_to_spec(&base);
    let offset = modified.leaf_not_before_offset_days.unwrap();
    let validity = modified.leaf_validity_days;
    assert!(
        offset as u64 > validity as u64,
        "offset({offset}) must exceed validity({validity}) for leaf to be expired"
    );
}

#[test]
fn expired_intermediate_ensures_past_expiry() {
    let base = ChainSpec::new("expired-int.test");
    let modified = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);
    let offset = modified.intermediate_not_before_offset_days.unwrap();
    let validity = modified.intermediate_validity_days;
    assert!(
        offset as u64 > validity as u64,
        "offset({offset}) must exceed validity({validity}) for intermediate to be expired"
    );
}

#[test]
fn revoked_leaf_produces_identical_spec() {
    let base = ChainSpec::new("revoked.test");
    let modified = ChainNegative::RevokedLeaf.apply_to_spec(&base);
    assert_eq!(base, modified, "RevokedLeaf must be an identity transform");
}

// ---------------------------------------------------------------------------
// 8. All X509Negative descriptions are non-empty and unique
// ---------------------------------------------------------------------------

#[test]
fn all_descriptions_non_empty() {
    let variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];
    for v in variants {
        assert!(!v.description().is_empty(), "{v:?} has empty description");
    }
}

#[test]
fn all_variant_names_non_empty() {
    let variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];
    for v in variants {
        assert!(!v.variant_name().is_empty(), "{v:?} has empty variant_name");
    }
}

// ---------------------------------------------------------------------------
// 9. apply_to_spec idempotence: applying twice is same as once
// ---------------------------------------------------------------------------

#[rstest]
#[case(X509Negative::Expired)]
#[case(X509Negative::NotYetValid)]
#[case(X509Negative::WrongKeyUsage)]
#[case(X509Negative::SelfSignedButClaimsCA)]
fn apply_to_spec_is_idempotent(#[case] variant: X509Negative) {
    let base = X509Spec::self_signed("idempotent-test");
    let once = variant.apply_to_spec(&base);
    let twice = variant.apply_to_spec(&once);
    assert_eq!(once, twice, "{variant:?} should be idempotent");
}

// ---------------------------------------------------------------------------
// 10. Chain variants preserve unrelated fields
// ---------------------------------------------------------------------------

#[test]
fn hostname_mismatch_preserves_root_and_intermediate() {
    let base = ChainSpec::new("preserve.test");
    let neg = ChainNegative::HostnameMismatch {
        wrong_hostname: "wrong.test".into(),
    };
    let modified = neg.apply_to_spec(&base);
    assert_eq!(modified.root_cn, base.root_cn);
    assert_eq!(modified.intermediate_cn, base.intermediate_cn);
    assert_eq!(modified.rsa_bits, base.rsa_bits);
    assert_eq!(modified.root_validity_days, base.root_validity_days);
    assert_eq!(
        modified.intermediate_validity_days,
        base.intermediate_validity_days
    );
}

#[test]
fn expired_leaf_preserves_root_and_intermediate() {
    let base = ChainSpec::new("preserve-leaf.test");
    let modified = ChainNegative::ExpiredLeaf.apply_to_spec(&base);
    assert_eq!(modified.root_cn, base.root_cn);
    assert_eq!(modified.intermediate_cn, base.intermediate_cn);
    assert_eq!(modified.root_validity_days, base.root_validity_days);
    assert_eq!(
        modified.intermediate_validity_days,
        base.intermediate_validity_days
    );
}

#[test]
fn expired_intermediate_preserves_root_and_leaf() {
    let base = ChainSpec::new("preserve-int.test");
    let modified = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);
    assert_eq!(modified.root_cn, base.root_cn);
    assert_eq!(modified.leaf_cn, base.leaf_cn);
    assert_eq!(modified.leaf_sans, base.leaf_sans);
    assert_eq!(modified.root_validity_days, base.root_validity_days);
    assert_eq!(modified.leaf_validity_days, base.leaf_validity_days);
}
