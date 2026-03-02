//! Property-based tests for `uselesskey-core-x509-spec`.

use proptest::prelude::*;
use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    // ── X509Spec stable_bytes determinism ─────────────────────────────

    #[test]
    fn x509_stable_bytes_is_deterministic(cn in "[a-zA-Z0-9._-]{1,32}") {
        let spec = X509Spec::self_signed(&cn);
        prop_assert_eq!(spec.stable_bytes(), spec.stable_bytes());
    }

    #[test]
    fn x509_different_cn_different_stable_bytes(
        cn_a in "[a-z]{1,16}",
        cn_b in "[a-z]{1,16}",
    ) {
        prop_assume!(cn_a != cn_b);
        let a = X509Spec::self_signed(&cn_a);
        let b = X509Spec::self_signed(&cn_b);
        prop_assert_ne!(a.stable_bytes(), b.stable_bytes());
    }

    // ── SAN order independence ────────────────────────────────────────

    #[test]
    fn x509_san_order_independent(
        cn in "[a-z]{1,8}",
        san_a in "[a-z]{1,8}\\.[a-z]{2,4}",
        san_b in "[a-z]{1,8}\\.[a-z]{2,4}",
    ) {
        prop_assume!(san_a != san_b);
        let spec_ab = X509Spec::self_signed(&cn)
            .with_sans(vec![san_a.clone(), san_b.clone()]);
        let spec_ba = X509Spec::self_signed(&cn)
            .with_sans(vec![san_b, san_a]);
        prop_assert_eq!(spec_ab.stable_bytes(), spec_ba.stable_bytes());
    }

    #[test]
    fn x509_san_dedup(
        cn in "[a-z]{1,8}",
        san in "[a-z]{1,8}\\.[a-z]{2,4}",
    ) {
        let with_dupes = X509Spec::self_signed(&cn)
            .with_sans(vec![san.clone(), san.clone()]);
        let without_dupes = X509Spec::self_signed(&cn)
            .with_sans(vec![san]);
        prop_assert_eq!(with_dupes.stable_bytes(), without_dupes.stable_bytes());
    }

    // ── Builder preserves values ──────────────────────────────────────

    #[test]
    fn x509_builder_preserves_validity_days(days in 1u32..10000) {
        let spec = X509Spec::self_signed("test").with_validity_days(days);
        prop_assert_eq!(spec.validity_days, days);
    }

    #[test]
    fn x509_builder_preserves_rsa_bits(bits in prop::sample::select(vec![1024usize, 2048, 3072, 4096])) {
        let spec = X509Spec::self_signed("test").with_rsa_bits(bits);
        prop_assert_eq!(spec.rsa_bits, bits);
    }

    #[test]
    fn x509_builder_preserves_is_ca(is_ca: bool) {
        let spec = X509Spec::self_signed("test").with_is_ca(is_ca);
        prop_assert_eq!(spec.is_ca, is_ca);
    }

    // ── Field sensitivity: changing any field changes stable_bytes ────

    #[test]
    fn x509_validity_days_affects_stable_bytes(
        days_a in 1u32..5000,
        days_b in 5001u32..10000,
    ) {
        let a = X509Spec::self_signed("test").with_validity_days(days_a);
        let b = X509Spec::self_signed("test").with_validity_days(days_b);
        prop_assert_ne!(a.stable_bytes(), b.stable_bytes());
    }

    #[test]
    fn x509_not_before_variants_differ(days in 1u32..1000) {
        let ago = X509Spec::self_signed("test")
            .with_not_before(NotBeforeOffset::DaysAgo(days));
        let future = X509Spec::self_signed("test")
            .with_not_before(NotBeforeOffset::DaysFromNow(days));
        prop_assert_ne!(ago.stable_bytes(), future.stable_bytes());
    }

    // ── KeyUsage stable_bytes ────────────────────────────────────────

    #[test]
    fn key_usage_stable_bytes_is_4_bytes(
        cert_sign: bool,
        crl_sign: bool,
        dig_sig: bool,
        key_enc: bool,
    ) {
        let ku = KeyUsage {
            key_cert_sign: cert_sign,
            crl_sign,
            digital_signature: dig_sig,
            key_encipherment: key_enc,
        };
        let bytes = ku.stable_bytes();
        prop_assert_eq!(bytes.len(), 4);
        prop_assert_eq!(bytes[0], cert_sign as u8);
        prop_assert_eq!(bytes[1], crl_sign as u8);
        prop_assert_eq!(bytes[2], dig_sig as u8);
        prop_assert_eq!(bytes[3], key_enc as u8);
    }

    // ── ChainSpec ────────────────────────────────────────────────────

    #[test]
    fn chain_stable_bytes_is_deterministic(cn in "[a-zA-Z0-9._-]{1,32}") {
        let spec = ChainSpec::new(&cn);
        prop_assert_eq!(spec.stable_bytes(), spec.stable_bytes());
    }

    #[test]
    fn chain_san_order_independent(
        cn in "[a-z]{1,8}",
        san_a in "[a-z]{1,8}\\.[a-z]{2,4}",
        san_b in "[a-z]{1,8}\\.[a-z]{2,4}",
    ) {
        prop_assume!(san_a != san_b);
        let spec_ab = ChainSpec::new(&cn)
            .with_sans(vec![san_a.clone(), san_b.clone()]);
        let spec_ba = ChainSpec::new(&cn)
            .with_sans(vec![san_b, san_a]);
        prop_assert_eq!(spec_ab.stable_bytes(), spec_ba.stable_bytes());
    }

    #[test]
    fn chain_different_leaf_cn_different_bytes(
        cn_a in "[a-z]{1,16}",
        cn_b in "[a-z]{1,16}",
    ) {
        prop_assume!(cn_a != cn_b);
        let a = ChainSpec::new(&cn_a);
        let b = ChainSpec::new(&cn_b);
        prop_assert_ne!(a.stable_bytes(), b.stable_bytes());
    }

    #[test]
    fn chain_builder_preserves_rsa_bits(bits in prop::sample::select(vec![1024usize, 2048, 4096])) {
        let spec = ChainSpec::new("test").with_rsa_bits(bits);
        prop_assert_eq!(spec.rsa_bits, bits);
    }

    #[test]
    fn chain_builder_preserves_validity_days(
        root in 1u32..10000,
        inter in 1u32..10000,
        leaf in 1u32..10000,
    ) {
        let spec = ChainSpec::new("test")
            .with_root_validity_days(root)
            .with_intermediate_validity_days(inter)
            .with_leaf_validity_days(leaf);
        prop_assert_eq!(spec.root_validity_days, root);
        prop_assert_eq!(spec.intermediate_validity_days, inter);
        prop_assert_eq!(spec.leaf_validity_days, leaf);
    }

    // ── X509Spec duration helpers ────────────────────────────────────

    #[test]
    fn not_before_duration_days_ago_matches(days in 0u32..1000) {
        let spec = X509Spec::self_signed("test")
            .with_not_before(NotBeforeOffset::DaysAgo(days));
        let dur = spec.not_before_duration();
        prop_assert_eq!(dur.as_secs(), days as u64 * 86400);
    }

    #[test]
    fn not_before_duration_days_from_now_is_zero(days in 0u32..1000) {
        let spec = X509Spec::self_signed("test")
            .with_not_before(NotBeforeOffset::DaysFromNow(days));
        prop_assert_eq!(spec.not_before_duration().as_secs(), 0);
    }
}
