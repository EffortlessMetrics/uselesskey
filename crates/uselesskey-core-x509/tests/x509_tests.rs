//! Integration tests for `uselesskey-core-x509`.
//!
//! Covers public types, negative-policy types, re-exports, trait impls,
//! and property-based invariants.

use uselesskey_core_x509::{
    // Derive re-exports
    BASE_TIME_EPOCH_UNIX,
    BASE_TIME_WINDOW_DAYS,
    // Negative policy re-exports
    ChainNegative,
    // Spec re-exports
    ChainSpec,
    KeyUsage,
    NotBeforeOffset,
    SERIAL_NUMBER_BYTES,
    X509Negative,
    X509Spec,
    deterministic_base_time_from_parts,
};

// ── Re-export accessibility ──────────────────────────────────────────

#[test]
fn reexported_constants_are_accessible() {
    assert_eq!(BASE_TIME_EPOCH_UNIX, 1_735_689_600);
    assert_eq!(BASE_TIME_WINDOW_DAYS, 365);
    assert_eq!(SERIAL_NUMBER_BYTES, 16);
}

#[test]
fn reexported_functions_are_callable() {
    // deterministic_base_time_from_parts (exercises write_len_prefixed internally)
    let t1 = deterministic_base_time_from_parts(&[b"hello"]);
    let t2 = deterministic_base_time_from_parts(&[b"hello"]);
    assert_eq!(
        t1, t2,
        "deterministic_base_time_from_parts must be deterministic"
    );
}

// ── X509Negative ─────────────────────────────────────────────────────

mod x509_negative {
    use super::*;

    const ALL_VARIANTS: [X509Negative; 4] = [
        X509Negative::Expired,
        X509Negative::NotYetValid,
        X509Negative::WrongKeyUsage,
        X509Negative::SelfSignedButClaimsCA,
    ];

    #[test]
    fn clone_and_eq() {
        for variant in &ALL_VARIANTS {
            let cloned = variant.clone();
            assert_eq!(*variant, cloned);
        }
    }

    #[test]
    fn debug_impl_is_non_empty() {
        for variant in &ALL_VARIANTS {
            let dbg = format!("{variant:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn hash_is_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        for variant in &ALL_VARIANTS {
            let mut h1 = DefaultHasher::new();
            variant.hash(&mut h1);
            let mut h2 = DefaultHasher::new();
            variant.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    #[test]
    fn variant_names_are_unique() {
        let names: Vec<&str> = ALL_VARIANTS.iter().map(|v| v.variant_name()).collect();
        let mut deduped = names.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(names.len(), deduped.len(), "variant names must be unique");
    }

    #[test]
    fn descriptions_are_unique_and_non_empty() {
        let descs: Vec<&str> = ALL_VARIANTS.iter().map(|v| v.description()).collect();
        for d in &descs {
            assert!(!d.is_empty());
        }
        let mut deduped = descs.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(descs.len(), deduped.len(), "descriptions must be unique");
    }

    #[test]
    fn apply_preserves_unrelated_fields() {
        let base = X509Spec::self_signed("preserve-test")
            .with_sans(vec!["a.example.com".into()])
            .with_rsa_bits(4096);

        for variant in &ALL_VARIANTS {
            let modified = variant.apply_to_spec(&base);
            // subject_cn and issuer_cn are never changed by negatives
            assert_eq!(modified.subject_cn, base.subject_cn);
            assert_eq!(modified.issuer_cn, base.issuer_cn);
            // rsa_bits is never changed
            assert_eq!(modified.rsa_bits, base.rsa_bits);
            // SANs are never changed
            assert_eq!(modified.sans, base.sans);
        }
    }

    #[test]
    fn expired_produces_past_validity() {
        let base = X509Spec::self_signed("expired-test");
        let modified = X509Negative::Expired.apply_to_spec(&base);

        assert_eq!(modified.not_before_offset, NotBeforeOffset::DaysAgo(395));
        assert_eq!(modified.validity_days, 365);
        // 395 - 365 = 30 days expired
    }

    #[test]
    fn not_yet_valid_produces_future_not_before() {
        let base = X509Spec::self_signed("future-test");
        let modified = X509Negative::NotYetValid.apply_to_spec(&base);

        assert_eq!(modified.not_before_offset, NotBeforeOffset::DaysFromNow(30));
    }

    #[test]
    fn wrong_key_usage_has_ca_without_cert_sign() {
        let base = X509Spec::self_signed("ku-test");
        let modified = X509Negative::WrongKeyUsage.apply_to_spec(&base);

        assert!(modified.is_ca);
        assert!(!modified.key_usage.key_cert_sign, "CA without keyCertSign");
        assert!(!modified.key_usage.crl_sign, "CA without crlSign");
    }

    #[test]
    fn self_signed_ca_has_proper_ca_flags() {
        let base = X509Spec::self_signed("ca-test");
        let modified = X509Negative::SelfSignedButClaimsCA.apply_to_spec(&base);

        assert!(modified.is_ca);
        assert_eq!(modified.key_usage, KeyUsage::ca());
    }

    #[test]
    fn apply_does_not_mutate_base() {
        let base = X509Spec::self_signed("immutable-test");
        let base_clone = base.clone();

        for variant in &ALL_VARIANTS {
            let _ = variant.apply_to_spec(&base);
        }

        assert_eq!(base, base_clone, "apply_to_spec must not mutate the base");
    }
}

// ── ChainNegative ────────────────────────────────────────────────────

mod chain_negative {
    use super::*;

    fn all_variants() -> Vec<ChainNegative> {
        vec![
            ChainNegative::HostnameMismatch {
                wrong_hostname: "evil.example.com".into(),
            },
            ChainNegative::UnknownCa,
            ChainNegative::ExpiredLeaf,
            ChainNegative::ExpiredIntermediate,
            ChainNegative::RevokedLeaf,
        ]
    }

    #[test]
    fn clone_and_eq() {
        for variant in &all_variants() {
            let cloned = variant.clone();
            assert_eq!(*variant, cloned);
        }
    }

    #[test]
    fn debug_impl_is_non_empty() {
        for variant in &all_variants() {
            let dbg = format!("{variant:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn hash_is_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        for variant in &all_variants() {
            let mut h1 = DefaultHasher::new();
            variant.hash(&mut h1);
            let mut h2 = DefaultHasher::new();
            variant.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    #[test]
    fn variant_names_are_unique_across_simple_variants() {
        let simple = vec![
            ChainNegative::UnknownCa,
            ChainNegative::ExpiredLeaf,
            ChainNegative::ExpiredIntermediate,
            ChainNegative::RevokedLeaf,
        ];
        let names: Vec<String> = simple.iter().map(|v| v.variant_name()).collect();
        let mut deduped = names.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(names.len(), deduped.len());
    }

    #[test]
    fn hostname_mismatch_variant_name_includes_hostname() {
        let neg = ChainNegative::HostnameMismatch {
            wrong_hostname: "bad.example.com".into(),
        };
        let name = neg.variant_name();
        assert!(name.starts_with("hostname_mismatch:"));
        assert!(name.contains("bad.example.com"));
    }

    #[test]
    fn hostname_mismatch_replaces_leaf_cn_and_sans() {
        let base = ChainSpec::new("good.example.com");
        let neg = ChainNegative::HostnameMismatch {
            wrong_hostname: "wrong.example.com".into(),
        };
        let modified = neg.apply_to_spec(&base);

        assert_eq!(modified.leaf_cn, "wrong.example.com");
        assert_eq!(modified.leaf_sans, vec!["wrong.example.com".to_string()]);
        // Other fields unchanged
        assert_eq!(modified.root_cn, base.root_cn);
        assert_eq!(modified.intermediate_cn, base.intermediate_cn);
    }

    #[test]
    fn unknown_ca_modifies_root_cn() {
        let base = ChainSpec::new("test.example.com");
        let modified = ChainNegative::UnknownCa.apply_to_spec(&base);

        assert_ne!(modified.root_cn, base.root_cn);
        assert!(modified.root_cn.contains("Unknown"));
        // Leaf stays the same
        assert_eq!(modified.leaf_cn, base.leaf_cn);
    }

    #[test]
    fn expired_leaf_sets_short_validity_and_past_offset() {
        let base = ChainSpec::new("test.example.com");
        let modified = ChainNegative::ExpiredLeaf.apply_to_spec(&base);

        assert_eq!(modified.leaf_validity_days, 1);
        assert_eq!(modified.leaf_not_before_offset_days, Some(730));
        // Intermediate is untouched
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
    fn expired_intermediate_sets_short_validity_and_past_offset() {
        let base = ChainSpec::new("test.example.com");
        let modified = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);

        assert_eq!(modified.intermediate_validity_days, 1);
        assert_eq!(modified.intermediate_not_before_offset_days, Some(730));
        // Leaf is untouched
        assert_eq!(modified.leaf_validity_days, base.leaf_validity_days);
        assert_eq!(
            modified.leaf_not_before_offset_days,
            base.leaf_not_before_offset_days
        );
    }

    #[test]
    fn revoked_leaf_does_not_change_spec() {
        let base = ChainSpec::new("test.example.com");
        let modified = ChainNegative::RevokedLeaf.apply_to_spec(&base);

        assert_eq!(modified, base);
    }

    #[test]
    fn apply_does_not_mutate_base() {
        let base = ChainSpec::new("immutable-test.example.com");
        let base_clone = base.clone();

        for variant in &all_variants() {
            let _ = variant.apply_to_spec(&base);
        }

        assert_eq!(base, base_clone);
    }
}

// ── KeyUsage ─────────────────────────────────────────────────────────

mod key_usage_tests {
    use super::*;

    #[test]
    fn leaf_values() {
        let ku = KeyUsage::leaf();
        assert!(!ku.key_cert_sign);
        assert!(!ku.crl_sign);
        assert!(ku.digital_signature);
        assert!(ku.key_encipherment);
    }

    #[test]
    fn ca_values() {
        let ku = KeyUsage::ca();
        assert!(ku.key_cert_sign);
        assert!(ku.crl_sign);
        assert!(ku.digital_signature);
        assert!(!ku.key_encipherment);
    }

    #[test]
    fn default_is_leaf() {
        assert_eq!(KeyUsage::default(), KeyUsage::leaf());
    }

    #[test]
    fn leaf_and_ca_differ() {
        assert_ne!(KeyUsage::leaf(), KeyUsage::ca());
    }

    #[test]
    fn stable_bytes_differ_for_leaf_and_ca() {
        assert_ne!(
            KeyUsage::leaf().stable_bytes(),
            KeyUsage::ca().stable_bytes()
        );
    }

    #[test]
    fn stable_bytes_is_deterministic() {
        let ku = KeyUsage::ca();
        assert_eq!(ku.stable_bytes(), ku.stable_bytes());
    }

    #[test]
    fn stable_bytes_encodes_flags_correctly() {
        let ku = KeyUsage {
            key_cert_sign: true,
            crl_sign: false,
            digital_signature: true,
            key_encipherment: false,
        };
        assert_eq!(ku.stable_bytes(), [1, 0, 1, 0]);
    }

    #[test]
    fn copy_semantics() {
        let ku = KeyUsage::leaf();
        let ku2 = ku; // Copy
        assert_eq!(ku, ku2);
    }

    #[test]
    fn hash_in_set() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(KeyUsage::leaf());
        set.insert(KeyUsage::ca());
        set.insert(KeyUsage::leaf()); // duplicate
        assert_eq!(set.len(), 2);
    }
}

// ── X509Spec via re-export ───────────────────────────────────────────

mod x509_spec_tests {
    use super::*;

    #[test]
    fn self_signed_sets_matching_cn() {
        let spec = X509Spec::self_signed("myhost.example.com");
        assert_eq!(spec.subject_cn, "myhost.example.com");
        assert_eq!(spec.issuer_cn, "myhost.example.com");
    }

    #[test]
    fn self_signed_ca_flags() {
        let spec = X509Spec::self_signed_ca("Root CA");
        assert!(spec.is_ca);
        assert_eq!(spec.key_usage, KeyUsage::ca());
    }

    #[test]
    fn builder_chain() {
        let spec = X509Spec::self_signed("chain-test")
            .with_validity_days(30)
            .with_not_before(NotBeforeOffset::DaysFromNow(5))
            .with_rsa_bits(4096)
            .with_key_usage(KeyUsage::ca())
            .with_is_ca(true)
            .with_sans(vec!["a.com".into(), "b.com".into()]);

        assert_eq!(spec.validity_days, 30);
        assert_eq!(spec.not_before_offset, NotBeforeOffset::DaysFromNow(5));
        assert_eq!(spec.rsa_bits, 4096);
        assert!(spec.is_ca);
        assert_eq!(spec.sans.len(), 2);
    }

    #[test]
    fn clone_eq() {
        let spec = X509Spec::self_signed("clone-test");
        let cloned = spec.clone();
        assert_eq!(spec, cloned);
    }

    #[test]
    fn debug_does_not_panic() {
        let spec = X509Spec::self_signed("debug-test");
        let _ = format!("{spec:?}");
    }

    #[test]
    fn stable_bytes_is_deterministic() {
        let a = X509Spec::self_signed("determinism-test").stable_bytes();
        let b = X509Spec::self_signed("determinism-test").stable_bytes();
        assert_eq!(a, b);
    }

    #[test]
    fn different_specs_produce_different_bytes() {
        let a = X509Spec::self_signed("alpha").stable_bytes();
        let b = X509Spec::self_signed("beta").stable_bytes();
        assert_ne!(a, b);
    }
}

// ── NotBeforeOffset ──────────────────────────────────────────────────

mod not_before_offset_tests {
    use super::*;

    #[test]
    fn default_is_days_ago_1() {
        assert_eq!(NotBeforeOffset::default(), NotBeforeOffset::DaysAgo(1));
    }

    #[test]
    fn days_ago_and_days_from_now_differ() {
        assert_ne!(NotBeforeOffset::DaysAgo(1), NotBeforeOffset::DaysFromNow(1));
    }

    #[test]
    fn copy_semantics() {
        let a = NotBeforeOffset::DaysAgo(7);
        let b = a; // Copy
        assert_eq!(a, b);
    }

    #[test]
    fn clone_eq() {
        let a = NotBeforeOffset::DaysFromNow(30);
        assert_eq!(a, a.clone());
    }

    #[test]
    fn debug_impl() {
        let dbg = format!("{:?}", NotBeforeOffset::DaysAgo(5));
        assert!(dbg.contains("DaysAgo"));
    }
}

// ── ChainSpec via re-export ──────────────────────────────────────────

mod chain_spec_tests {
    use super::*;

    #[test]
    fn new_sets_defaults() {
        let spec = ChainSpec::new("leaf.example.com");
        assert_eq!(spec.leaf_cn, "leaf.example.com");
        assert_eq!(spec.leaf_sans, vec!["leaf.example.com"]);
        assert!(spec.root_cn.contains("Root CA"));
        assert!(spec.intermediate_cn.contains("Intermediate CA"));
        assert_eq!(spec.rsa_bits, 2048);
    }

    #[test]
    fn builder_methods() {
        let spec = ChainSpec::new("test.com")
            .with_sans(vec!["a.com".into()])
            .with_root_cn("Custom Root")
            .with_intermediate_cn("Custom Int")
            .with_rsa_bits(4096)
            .with_root_validity_days(7300)
            .with_intermediate_validity_days(3650)
            .with_leaf_validity_days(90);

        assert_eq!(spec.leaf_sans, vec!["a.com"]);
        assert_eq!(spec.root_cn, "Custom Root");
        assert_eq!(spec.intermediate_cn, "Custom Int");
        assert_eq!(spec.rsa_bits, 4096);
        assert_eq!(spec.root_validity_days, 7300);
        assert_eq!(spec.intermediate_validity_days, 3650);
        assert_eq!(spec.leaf_validity_days, 90);
    }

    #[test]
    fn clone_eq() {
        let spec = ChainSpec::new("clone.example.com");
        assert_eq!(spec, spec.clone());
    }

    #[test]
    fn stable_bytes_deterministic() {
        let a = ChainSpec::new("det.example.com").stable_bytes();
        let b = ChainSpec::new("det.example.com").stable_bytes();
        assert_eq!(a, b);
    }

    #[test]
    fn different_specs_differ() {
        let a = ChainSpec::new("alpha.example.com").stable_bytes();
        let b = ChainSpec::new("beta.example.com").stable_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn hash_in_set() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ChainSpec::new("a.com"));
        set.insert(ChainSpec::new("b.com"));
        set.insert(ChainSpec::new("a.com"));
        assert_eq!(set.len(), 2);
    }
}

// ── Deterministic derive re-exports ──────────────────────────────────

mod derive_tests {
    use super::*;

    #[test]
    fn base_time_from_parts_is_deterministic() {
        let a = deterministic_base_time_from_parts(&[b"label", b"leaf"]);
        let b = deterministic_base_time_from_parts(&[b"label", b"leaf"]);
        assert_eq!(a, b);
    }

    #[test]
    fn base_time_from_parts_varies_with_input() {
        let a = deterministic_base_time_from_parts(&[b"alpha"]);
        let b = deterministic_base_time_from_parts(&[b"beta"]);
        // Not strictly guaranteed different, but overwhelmingly likely
        // for two distinct inputs
        assert_ne!(a, b);
    }

    #[test]
    fn base_time_from_parts_boundary_safe() {
        let a = deterministic_base_time_from_parts(&[b"ab", b"c"]);
        let b = deterministic_base_time_from_parts(&[b"a", b"bc"]);
        assert_ne!(a, b, "length-prefixed hashing prevents boundary ambiguity");
    }

    #[test]
    fn deterministic_base_time_within_epoch_range() {
        use uselesskey_core_x509::BASE_TIME_EPOCH_UNIX;
        let t = deterministic_base_time_from_parts(&[b"range-test"]);
        let epoch_secs = BASE_TIME_EPOCH_UNIX;
        let max_secs = epoch_secs + i64::from(BASE_TIME_WINDOW_DAYS - 1) * 86400;

        let ts = t.unix_timestamp();
        assert!(ts >= epoch_secs, "time must be >= epoch");
        assert!(ts <= max_secs, "time must be within window");
    }
}

// ── Property-based tests ─────────────────────────────────────────────

mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_x509_negative() -> impl Strategy<Value = X509Negative> {
        prop_oneof![
            Just(X509Negative::Expired),
            Just(X509Negative::NotYetValid),
            Just(X509Negative::WrongKeyUsage),
            Just(X509Negative::SelfSignedButClaimsCA),
        ]
    }

    fn arb_chain_negative() -> impl Strategy<Value = ChainNegative> {
        prop_oneof![
            "[a-z]{1,30}\\.example\\.com"
                .prop_map(|h| ChainNegative::HostnameMismatch { wrong_hostname: h }),
            Just(ChainNegative::UnknownCa),
            Just(ChainNegative::ExpiredLeaf),
            Just(ChainNegative::ExpiredIntermediate),
            Just(ChainNegative::RevokedLeaf),
        ]
    }

    proptest! {
        #[test]
        fn x509_negative_apply_never_panics(variant in arb_x509_negative()) {
            let base = X509Spec::self_signed("proptest-host");
            let _ = variant.apply_to_spec(&base);
        }

        #[test]
        fn x509_negative_variant_name_non_empty(variant in arb_x509_negative()) {
            prop_assert!(!variant.variant_name().is_empty());
        }

        #[test]
        fn x509_negative_description_non_empty(variant in arb_x509_negative()) {
            prop_assert!(!variant.description().is_empty());
        }

        #[test]
        fn chain_negative_apply_never_panics(variant in arb_chain_negative()) {
            let base = ChainSpec::new("proptest.example.com");
            let _ = variant.apply_to_spec(&base);
        }

        #[test]
        fn chain_negative_variant_name_non_empty(variant in arb_chain_negative()) {
            prop_assert!(!variant.variant_name().is_empty());
        }

        #[test]
        fn x509_spec_stable_bytes_deterministic(cn in "[a-z]{1,20}") {
            let a = X509Spec::self_signed(&cn).stable_bytes();
            let b = X509Spec::self_signed(&cn).stable_bytes();
            prop_assert_eq!(a, b);
        }

        #[test]
        fn chain_spec_stable_bytes_deterministic(cn in "[a-z]{1,20}\\.example\\.com") {
            let a = ChainSpec::new(&cn).stable_bytes();
            let b = ChainSpec::new(&cn).stable_bytes();
            prop_assert_eq!(a, b);
        }

        #[test]
        fn key_usage_stable_bytes_round_trips_flags(
            key_cert_sign in any::<bool>(),
            crl_sign in any::<bool>(),
            digital_signature in any::<bool>(),
            key_encipherment in any::<bool>(),
        ) {
            let ku = KeyUsage { key_cert_sign, crl_sign, digital_signature, key_encipherment };
            let bytes = ku.stable_bytes();
            prop_assert_eq!(bytes[0], key_cert_sign as u8);
            prop_assert_eq!(bytes[1], crl_sign as u8);
            prop_assert_eq!(bytes[2], digital_signature as u8);
            prop_assert_eq!(bytes[3], key_encipherment as u8);
        }

        #[test]
        fn base_time_from_parts_always_within_range(
            parts in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..32), 1..5)
        ) {
            let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
            let t = deterministic_base_time_from_parts(&refs);
            let ts = t.unix_timestamp();
            prop_assert!(ts >= BASE_TIME_EPOCH_UNIX);
            let max = BASE_TIME_EPOCH_UNIX + i64::from(BASE_TIME_WINDOW_DAYS - 1) * 86400;
            prop_assert!(ts <= max);
        }

        #[test]
        fn x509_negative_preserves_cn(variant in arb_x509_negative(), cn in "[a-z]{1,20}") {
            let base = X509Spec::self_signed(&cn);
            let modified = variant.apply_to_spec(&base);
            prop_assert_eq!(&modified.subject_cn, &base.subject_cn);
            prop_assert_eq!(&modified.issuer_cn, &base.issuer_cn);
        }
    }
}
