//! Comprehensive tests for X.509 negative-policy types via the facade crate.
//!
//! Covers:
//! 1. X509Negative policy types are correctly constructed
//! 2. Expired certificate generation with timing math
//! 3. Self-signed vs CA-signed chain structures
//! 4. Determinism verification (same inputs → same outputs)
//! 5. Revoked certificate indicators
//! 6. Cross-variant interference (each variant modifies only its fields)

use std::collections::HashSet;

use proptest::prelude::*;
use rstest::rstest;
use uselesskey_core_x509::{
    ChainNegative, ChainSpec, KeyUsage, NotBeforeOffset, X509Negative, X509Spec,
};

// =========================================================================
// 1. X509Negative: construction and exhaustiveness
// =========================================================================

#[test]
fn x509_negative_all_variants_constructible() {
    let variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];
    assert_eq!(variants.len(), 4);
}

#[test]
fn x509_negative_exhaustive_match() {
    // Ensures a compile error if a new variant is added without updating tests.
    fn check(v: X509Negative) -> &'static str {
        match v {
            X509Negative::Expired => "expired",
            X509Negative::NotYetValid => "not_yet_valid",
            X509Negative::WrongKeyUsage => "wrong_key_usage",
            X509Negative::SelfSignedButClaimsCA => "self_signed_ca",
        }
    }
    assert_eq!(check(X509Negative::Expired), "expired");
    assert_eq!(check(X509Negative::NotYetValid), "not_yet_valid");
    assert_eq!(check(X509Negative::WrongKeyUsage), "wrong_key_usage");
    assert_eq!(check(X509Negative::SelfSignedButClaimsCA), "self_signed_ca");
}

#[test]
fn chain_negative_exhaustive_match() {
    fn check(v: &ChainNegative) -> &'static str {
        match v {
            ChainNegative::HostnameMismatch { .. } => "hostname_mismatch",
            ChainNegative::UnknownCa => "unknown_ca",
            ChainNegative::ExpiredLeaf => "expired_leaf",
            ChainNegative::ExpiredIntermediate => "expired_intermediate",
            ChainNegative::RevokedLeaf => "revoked_leaf",
        }
    }
    assert_eq!(check(&ChainNegative::UnknownCa), "unknown_ca");
    assert_eq!(check(&ChainNegative::ExpiredLeaf), "expired_leaf");
}

// =========================================================================
// 2. Expired certificate generation — timing math
// =========================================================================

#[test]
fn expired_spec_not_after_is_in_the_past() {
    let base = X509Spec::self_signed("expired-math.example.com");
    let expired = X509Negative::Expired.apply_to_spec(&base);

    // not_before_offset = DaysAgo(395), validity_days = 365
    // Effective not_after = now - 395 + 365 = now - 30 days (in the past)
    assert_eq!(expired.not_before_offset, NotBeforeOffset::DaysAgo(395));
    assert_eq!(expired.validity_days, 365);

    match expired.not_before_offset {
        NotBeforeOffset::DaysAgo(ago) => {
            let days_since_expired = ago - expired.validity_days;
            assert_eq!(
                days_since_expired, 30,
                "certificate should have expired 30 days ago"
            );
        }
        _ => panic!("Expired variant must use DaysAgo"),
    }
}

#[test]
fn not_yet_valid_spec_not_before_is_30_days_future() {
    let base = X509Spec::self_signed("future.example.com");
    let nyv = X509Negative::NotYetValid.apply_to_spec(&base);

    assert_eq!(nyv.not_before_offset, NotBeforeOffset::DaysFromNow(30));
    assert_eq!(nyv.validity_days, 365);
}

#[test]
fn expired_chain_leaf_offset_exceeds_validity() {
    let base = ChainSpec::new("chain-expired.example.com");
    let modified = ChainNegative::ExpiredLeaf.apply_to_spec(&base);

    let offset = modified.leaf_not_before_offset_days.unwrap();
    let validity = modified.leaf_validity_days as i64;
    assert!(
        offset > validity,
        "offset ({offset}) must exceed validity ({validity}) for the cert to be expired"
    );
}

#[test]
fn expired_chain_intermediate_offset_exceeds_validity() {
    let base = ChainSpec::new("chain-expired.example.com");
    let modified = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);

    let offset = modified.intermediate_not_before_offset_days.unwrap();
    let validity = modified.intermediate_validity_days as i64;
    assert!(
        offset > validity,
        "offset ({offset}) must exceed validity ({validity}) for the cert to be expired"
    );
}

// =========================================================================
// 3. Self-signed vs CA-signed chain structures
// =========================================================================

#[test]
fn self_signed_spec_has_matching_subject_and_issuer() {
    let spec = X509Spec::self_signed("self-signed.example.com");
    assert_eq!(
        spec.subject_cn, spec.issuer_cn,
        "self-signed cert must have matching subject and issuer CN"
    );
}

#[test]
fn self_signed_leaf_is_not_ca() {
    let spec = X509Spec::self_signed("leaf.example.com");
    assert!(!spec.is_ca);
    assert_eq!(spec.key_usage, KeyUsage::leaf());
    assert!(!spec.key_usage.key_cert_sign);
}

#[test]
fn self_signed_ca_is_ca_with_proper_usage() {
    let spec = X509Spec::self_signed_ca("My Test CA");
    assert!(spec.is_ca);
    assert_eq!(spec.key_usage, KeyUsage::ca());
    assert!(spec.key_usage.key_cert_sign);
    assert!(spec.key_usage.crl_sign);
    assert_eq!(spec.subject_cn, spec.issuer_cn);
}

#[test]
fn chain_spec_has_three_level_hierarchy() {
    let spec = ChainSpec::new("leaf.example.com");

    // Root
    assert!(spec.root_cn.contains("Root CA"));
    assert_ne!(spec.root_cn, spec.leaf_cn);

    // Intermediate
    assert!(spec.intermediate_cn.contains("Intermediate CA"));
    assert_ne!(spec.intermediate_cn, spec.leaf_cn);
    assert_ne!(spec.intermediate_cn, spec.root_cn);

    // Leaf
    assert_eq!(spec.leaf_cn, "leaf.example.com");
    assert_eq!(spec.leaf_sans, vec!["leaf.example.com"]);
}

#[test]
fn chain_spec_root_has_longest_validity() {
    let spec = ChainSpec::new("chain.example.com");
    assert!(
        spec.root_validity_days >= spec.intermediate_validity_days,
        "root should have longer validity than intermediate"
    );
}

#[test]
fn wrong_key_usage_creates_inconsistent_ca() {
    let leaf = X509Spec::self_signed("inconsistent-ca.example.com");
    let modified = X509Negative::WrongKeyUsage.apply_to_spec(&leaf);

    // Claims to be CA but lacks key_cert_sign — this is the inconsistency
    assert!(modified.is_ca);
    assert!(!modified.key_usage.key_cert_sign);
    assert!(!modified.key_usage.crl_sign);
}

#[test]
fn self_signed_but_claims_ca_creates_self_signed_with_ca_flags() {
    let leaf = X509Spec::self_signed("self-ca.example.com");
    let modified = X509Negative::SelfSignedButClaimsCA.apply_to_spec(&leaf);

    // Still self-signed (issuer == subject)
    assert_eq!(modified.subject_cn, modified.issuer_cn);
    // But claims CA
    assert!(modified.is_ca);
    assert_eq!(modified.key_usage, KeyUsage::ca());
}

// =========================================================================
// 4. Determinism verification
// =========================================================================

#[rstest]
#[case::expired(X509Negative::Expired)]
#[case::not_yet_valid(X509Negative::NotYetValid)]
#[case::wrong_key_usage(X509Negative::WrongKeyUsage)]
#[case::self_signed_ca(X509Negative::SelfSignedButClaimsCA)]
fn x509_negative_apply_is_deterministic(#[case] variant: X509Negative) {
    let base = X509Spec::self_signed("deterministic.example.com")
        .with_rsa_bits(4096)
        .with_validity_days(730);

    let first = variant.apply_to_spec(&base);
    let second = variant.apply_to_spec(&base);
    assert_eq!(first, second, "{variant:?} must be deterministic");
    assert_eq!(
        first.stable_bytes(),
        second.stable_bytes(),
        "stable_bytes must match for deterministic variant {variant:?}"
    );
}

#[test]
fn chain_negative_all_variants_deterministic() {
    let base = ChainSpec::new("deterministic-chain.example.com")
        .with_rsa_bits(4096)
        .with_root_cn("Deterministic Root CA")
        .with_intermediate_cn("Deterministic Int CA");

    let variants: Vec<ChainNegative> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "wrong.example.com".to_string(),
        },
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
        ChainNegative::RevokedLeaf,
    ];

    for variant in &variants {
        let first = variant.apply_to_spec(&base);
        let second = variant.apply_to_spec(&base);
        assert_eq!(first, second, "{variant:?} must be deterministic");
        assert_eq!(
            first.stable_bytes(),
            second.stable_bytes(),
            "stable_bytes must match for deterministic chain variant {variant:?}"
        );
    }
}

#[test]
fn x509_negative_stable_bytes_differ_across_variants() {
    let base = X509Spec::self_signed("bytes-test.example.com");
    let variants = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
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
// 5. Revoked certificate indicators
// =========================================================================

#[test]
fn revoked_leaf_chain_spec_is_structurally_unchanged() {
    let base = ChainSpec::new("revoked.example.com")
        .with_rsa_bits(4096)
        .with_root_cn("Revoked Root CA")
        .with_intermediate_cn("Revoked Int CA")
        .with_root_validity_days(7300)
        .with_intermediate_validity_days(3650)
        .with_leaf_validity_days(365)
        .with_sans(vec![
            "revoked.example.com".to_string(),
            "alt.example.com".to_string(),
        ]);

    let modified = ChainNegative::RevokedLeaf.apply_to_spec(&base);

    // RevokedLeaf must not change any spec field — revocation is signalled
    // through CRL generation, not spec mutation.
    assert_eq!(modified, base);
    assert_eq!(modified.stable_bytes(), base.stable_bytes());
}

#[test]
fn revoked_leaf_variant_name_is_stable() {
    assert_eq!(ChainNegative::RevokedLeaf.variant_name(), "revoked_leaf");
}

// =========================================================================
// 6. Cross-variant field isolation
// =========================================================================

#[test]
fn expired_does_not_change_ca_or_key_usage() {
    let base = X509Spec::self_signed("isolation.example.com");
    let modified = X509Negative::Expired.apply_to_spec(&base);

    assert_eq!(modified.is_ca, base.is_ca);
    assert_eq!(modified.key_usage, base.key_usage);
    assert_eq!(modified.rsa_bits, base.rsa_bits);
    assert_eq!(modified.subject_cn, base.subject_cn);
    assert_eq!(modified.issuer_cn, base.issuer_cn);
    assert_eq!(modified.sans, base.sans);
}

#[test]
fn not_yet_valid_does_not_change_ca_or_key_usage() {
    let base = X509Spec::self_signed("isolation.example.com");
    let modified = X509Negative::NotYetValid.apply_to_spec(&base);

    assert_eq!(modified.is_ca, base.is_ca);
    assert_eq!(modified.key_usage, base.key_usage);
    assert_eq!(modified.rsa_bits, base.rsa_bits);
    assert_eq!(modified.subject_cn, base.subject_cn);
    assert_eq!(modified.issuer_cn, base.issuer_cn);
    assert_eq!(modified.sans, base.sans);
}

#[test]
fn wrong_key_usage_does_not_change_timing() {
    let base = X509Spec::self_signed("isolation.example.com");
    let modified = X509Negative::WrongKeyUsage.apply_to_spec(&base);

    assert_eq!(modified.not_before_offset, base.not_before_offset);
    assert_eq!(modified.validity_days, base.validity_days);
    assert_eq!(modified.rsa_bits, base.rsa_bits);
    assert_eq!(modified.subject_cn, base.subject_cn);
}

#[test]
fn self_signed_ca_does_not_change_timing() {
    let base = X509Spec::self_signed("isolation.example.com");
    let modified = X509Negative::SelfSignedButClaimsCA.apply_to_spec(&base);

    assert_eq!(modified.not_before_offset, base.not_before_offset);
    assert_eq!(modified.validity_days, base.validity_days);
    assert_eq!(modified.rsa_bits, base.rsa_bits);
    assert_eq!(modified.subject_cn, base.subject_cn);
}

// =========================================================================
// Variant names and descriptions
// =========================================================================

#[test]
fn variant_names_are_distinct_and_stable() {
    let names: Vec<&str> = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ]
    .iter()
    .map(|v| v.variant_name())
    .collect();

    let unique: HashSet<&&str> = names.iter().collect();
    assert_eq!(unique.len(), names.len(), "variant names must be distinct");

    // Verify exact values for stability
    assert_eq!(names[0], "expired");
    assert_eq!(names[1], "not_yet_valid");
    assert_eq!(names[2], "wrong_key_usage");
    assert_eq!(names[3], "self_signed_ca");
}

#[test]
fn descriptions_are_non_empty_and_distinct() {
    let descs: Vec<&str> = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ]
    .iter()
    .map(|v| v.description())
    .collect();

    let unique: HashSet<&&str> = descs.iter().collect();
    assert_eq!(unique.len(), descs.len(), "descriptions must be distinct");
    for d in &descs {
        assert!(!d.is_empty());
    }
}

// =========================================================================
// apply_to_spec does not mutate the base
// =========================================================================

#[test]
fn apply_does_not_mutate_base_x509_spec() {
    let base = X509Spec::self_signed("immutable.example.com")
        .with_rsa_bits(4096)
        .with_validity_days(730);
    let original = base.clone();

    for variant in [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ] {
        let _ = variant.apply_to_spec(&base);
        assert_eq!(base, original, "{variant:?} must not mutate the base spec");
    }
}

#[test]
fn apply_does_not_mutate_base_chain_spec() {
    let base = ChainSpec::new("immutable.example.com")
        .with_rsa_bits(4096)
        .with_root_cn("Immutable Root CA");
    let original = base.clone();

    let variants: Vec<ChainNegative> = vec![
        ChainNegative::HostnameMismatch {
            wrong_hostname: "evil.example.com".to_string(),
        },
        ChainNegative::UnknownCa,
        ChainNegative::ExpiredLeaf,
        ChainNegative::ExpiredIntermediate,
        ChainNegative::RevokedLeaf,
    ];

    for variant in &variants {
        let _ = variant.apply_to_spec(&base);
        assert_eq!(base, original, "{variant:?} must not mutate the base spec");
    }
}

// =========================================================================
// Property-based tests
// =========================================================================

proptest! {
    #[test]
    fn expired_always_has_not_after_in_past(cn in "[a-z]{1,20}") {
        let base = X509Spec::self_signed(&cn);
        let expired = X509Negative::Expired.apply_to_spec(&base);

        match expired.not_before_offset {
            NotBeforeOffset::DaysAgo(ago) => {
                prop_assert!(
                    ago > expired.validity_days,
                    "DaysAgo({ago}) must exceed validity({v}) for expiry",
                    v = expired.validity_days,
                );
            }
            other => panic!("Expected DaysAgo, got {other:?}"),
        }
    }

    #[test]
    fn not_yet_valid_always_future(cn in "[a-z]{1,20}") {
        let base = X509Spec::self_signed(&cn);
        let nyv = X509Negative::NotYetValid.apply_to_spec(&base);

        match nyv.not_before_offset {
            NotBeforeOffset::DaysFromNow(days) => {
                prop_assert!(days > 0, "DaysFromNow must be positive");
            }
            other => panic!("Expected DaysFromNow, got {other:?}"),
        }
    }

    #[test]
    fn all_x509_variants_deterministic(cn in "[a-z]{1,20}") {
        let base = X509Spec::self_signed(&cn);
        for variant in [
            X509Negative::Expired,
            X509Negative::NotYetValid,
            X509Negative::WrongKeyUsage,
            X509Negative::SelfSignedButClaimsCA,
        ] {
            let a = variant.apply_to_spec(&base);
            let b = variant.apply_to_spec(&base);
            prop_assert_eq!(a, b);
        }
    }

    #[test]
    fn chain_negative_deterministic_for_any_hostname(
        leaf in "[a-z]{1,15}\\.example\\.com",
    ) {
        let base = ChainSpec::new(&leaf);
        let variants: Vec<ChainNegative> = vec![
            ChainNegative::HostnameMismatch {
                wrong_hostname: format!("wrong-{leaf}"),
            },
            ChainNegative::UnknownCa,
            ChainNegative::ExpiredLeaf,
            ChainNegative::ExpiredIntermediate,
            ChainNegative::RevokedLeaf,
        ];
        for v in &variants {
            let a = v.apply_to_spec(&base);
            let b = v.apply_to_spec(&base);
            prop_assert_eq!(a, b);
        }
    }
}

// =========================================================================
// Derive helper constants are accessible via re-exports
// =========================================================================

#[test]
fn derive_constants_are_nonzero() {
    use uselesskey_core_x509::{BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, SERIAL_NUMBER_BYTES};
    const {
        assert!(BASE_TIME_EPOCH_UNIX > 0);
    }
    const {
        assert!(BASE_TIME_WINDOW_DAYS > 0);
    }
    const {
        assert!(SERIAL_NUMBER_BYTES > 0);
    }
}

#[test]
fn deterministic_base_time_from_parts_is_stable() {
    use uselesskey_core_x509::deterministic_base_time_from_parts;

    let t1 = deterministic_base_time_from_parts(&[b"label-a", b"leaf"]);
    let t2 = deterministic_base_time_from_parts(&[b"label-a", b"leaf"]);
    assert_eq!(t1, t2);

    let t3 = deterministic_base_time_from_parts(&[b"label-b", b"leaf"]);
    assert_ne!(t1, t3, "different labels must produce different base times");
}

#[test]
fn deterministic_serial_number_is_positive_and_stable() {
    use uselesskey_core_seed::Seed;
    use uselesskey_core_x509::{SERIAL_NUMBER_BYTES, deterministic_serial_number};

    let rng1 = Seed::new([99u8; 32]);
    let rng2 = Seed::new([99u8; 32]);

    let s1 = deterministic_serial_number(rng1);
    let s2 = deterministic_serial_number(rng2);

    assert_eq!(s1.to_bytes(), s2.to_bytes());
    assert_eq!(s1.to_bytes().len(), SERIAL_NUMBER_BYTES);
    assert_eq!(s1.to_bytes()[0] & 0x80, 0, "high bit must be cleared");
}
