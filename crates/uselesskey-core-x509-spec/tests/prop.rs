use proptest::prelude::*;

use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

// ---------------------------------------------------------------------------
// X509Spec property tests
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn x509_stable_bytes_is_deterministic(
        cn in "[a-z]{1,32}",
        validity in 0u32..10_000,
        rsa_bits in prop::sample::select(vec![1024usize, 2048, 4096]),
        is_ca: bool,
    ) {
        let a = X509Spec::self_signed(&cn)
            .with_validity_days(validity)
            .with_rsa_bits(rsa_bits)
            .with_is_ca(is_ca);
        let b = X509Spec::self_signed(&cn)
            .with_validity_days(validity)
            .with_rsa_bits(rsa_bits)
            .with_is_ca(is_ca);
        prop_assert_eq!(a.stable_bytes(), b.stable_bytes());
    }

    #[test]
    fn x509_stable_bytes_san_order_irrelevant(
        cn in "[a-z]{1,16}",
        mut sans in prop::collection::vec("[a-z]{1,8}\\.test", 0..6),
    ) {
        let a = X509Spec::self_signed(&cn).with_sans(sans.clone());
        sans.reverse();
        let b = X509Spec::self_signed(&cn).with_sans(sans);
        prop_assert_eq!(a.stable_bytes(), b.stable_bytes());
    }

    #[test]
    fn x509_different_subject_different_bytes(
        cn1 in "[a-z]{1,16}",
        cn2 in "[a-z]{1,16}",
    ) {
        prop_assume!(cn1 != cn2);
        let a = X509Spec::self_signed(&cn1).stable_bytes();
        let b = X509Spec::self_signed(&cn2).stable_bytes();
        prop_assert_ne!(a, b);
    }

    #[test]
    fn x509_not_before_duration_zero_for_future(days in 0u32..10_000) {
        let spec = X509Spec::self_signed("t")
            .with_not_before(NotBeforeOffset::DaysFromNow(days));
        prop_assert_eq!(spec.not_before_duration(), std::time::Duration::ZERO);
    }

    #[test]
    fn x509_not_before_duration_matches_days_ago(days in 0u32..10_000) {
        let spec = X509Spec::self_signed("t")
            .with_not_before(NotBeforeOffset::DaysAgo(days));
        let expected = std::time::Duration::from_secs(days as u64 * 86_400);
        prop_assert_eq!(spec.not_before_duration(), expected);
    }

    #[test]
    fn x509_not_after_ge_validity_days(
        validity in 0u32..10_000,
        offset_days in 0u32..10_000,
    ) {
        let spec = X509Spec::self_signed("t")
            .with_not_before(NotBeforeOffset::DaysFromNow(offset_days))
            .with_validity_days(validity);
        let min = std::time::Duration::from_secs(validity as u64 * 86_400);
        prop_assert!(spec.not_after_duration() >= min);
    }

    #[test]
    fn key_usage_stable_bytes_roundtrips_flags(
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
        let bytes = ku.stable_bytes();
        prop_assert_eq!(bytes[0], kcs as u8);
        prop_assert_eq!(bytes[1], cs as u8);
        prop_assert_eq!(bytes[2], ds as u8);
        prop_assert_eq!(bytes[3], ke as u8);
    }
}

// ---------------------------------------------------------------------------
// ChainSpec property tests
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn chain_stable_bytes_is_deterministic(
        cn in "[a-z]{1,32}",
        rsa_bits in prop::sample::select(vec![1024usize, 2048, 4096]),
        root_days in 1u32..10_000,
        int_days in 1u32..10_000,
        leaf_days in 1u32..10_000,
    ) {
        let a = ChainSpec::new(&cn)
            .with_rsa_bits(rsa_bits)
            .with_root_validity_days(root_days)
            .with_intermediate_validity_days(int_days)
            .with_leaf_validity_days(leaf_days);
        let b = ChainSpec::new(&cn)
            .with_rsa_bits(rsa_bits)
            .with_root_validity_days(root_days)
            .with_intermediate_validity_days(int_days)
            .with_leaf_validity_days(leaf_days);
        prop_assert_eq!(a.stable_bytes(), b.stable_bytes());
    }

    #[test]
    fn chain_stable_bytes_san_order_irrelevant(
        cn in "[a-z]{1,16}",
        mut sans in prop::collection::vec("[a-z]{1,8}\\.test", 0..6),
    ) {
        let a = ChainSpec::new(&cn).with_sans(sans.clone());
        sans.reverse();
        let b = ChainSpec::new(&cn).with_sans(sans);
        prop_assert_eq!(a.stable_bytes(), b.stable_bytes());
    }

    #[test]
    fn chain_different_leaf_cn_different_bytes(
        cn1 in "[a-z]{1,16}",
        cn2 in "[a-z]{1,16}",
    ) {
        prop_assume!(cn1 != cn2);
        let a = ChainSpec::new(&cn1).stable_bytes();
        let b = ChainSpec::new(&cn2).stable_bytes();
        prop_assert_ne!(a, b);
    }

    #[test]
    fn chain_new_auto_adds_leaf_cn_to_sans(cn in "[a-z]{1,32}") {
        let spec = ChainSpec::new(&cn);
        prop_assert_eq!(spec.leaf_sans, vec![cn.clone()]);
    }

    #[test]
    fn chain_new_derives_ca_names_from_leaf(cn in "[a-z]{1,32}") {
        let spec = ChainSpec::new(&cn);
        prop_assert_eq!(spec.root_cn, format!("{cn} Root CA"));
        prop_assert_eq!(spec.intermediate_cn, format!("{cn} Intermediate CA"));
    }
}
