use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

// ---------------------------------------------------------------------------
// 1. x509_spec_builder_chaining
// ---------------------------------------------------------------------------

#[test]
fn x509_spec_builder_chaining() {
    let ku = KeyUsage::ca();
    let sans = vec!["a.example.com".into(), "b.example.com".into()];

    let spec = X509Spec::self_signed("myapp.example.com")
        .with_validity_days(365)
        .with_not_before(NotBeforeOffset::DaysAgo(7))
        .with_rsa_bits(4096)
        .with_is_ca(true)
        .with_key_usage(ku)
        .with_sans(sans.clone());

    assert_eq!(spec.subject_cn, "myapp.example.com");
    assert_eq!(spec.issuer_cn, "myapp.example.com");
    assert_eq!(spec.validity_days, 365);
    assert_eq!(spec.not_before_offset, NotBeforeOffset::DaysAgo(7));
    assert_eq!(spec.rsa_bits, 4096);
    assert!(spec.is_ca);
    assert_eq!(spec.key_usage, ku);
    assert!(spec.key_usage.key_cert_sign);
    assert!(spec.key_usage.crl_sign);
    assert!(spec.key_usage.digital_signature);
    assert!(!spec.key_usage.key_encipherment);
    assert_eq!(spec.sans, sans);
}

// ---------------------------------------------------------------------------
// 2. x509_spec_san_deduplication
// ---------------------------------------------------------------------------

#[test]
fn x509_spec_san_deduplication() {
    let with_dupes = X509Spec::self_signed("test").with_sans(vec![
        "dup.example.com".into(),
        "unique.example.com".into(),
        "dup.example.com".into(),
        "dup.example.com".into(),
    ]);
    let without_dupes = X509Spec::self_signed("test").with_sans(vec![
        "dup.example.com".into(),
        "unique.example.com".into(),
    ]);

    // stable_bytes deduplicates SANs, so both must produce identical output
    assert_eq!(with_dupes.stable_bytes(), without_dupes.stable_bytes());

    // Order should not matter either
    let reversed = X509Spec::self_signed("test").with_sans(vec![
        "unique.example.com".into(),
        "dup.example.com".into(),
    ]);
    assert_eq!(with_dupes.stable_bytes(), reversed.stable_bytes());
}

// ---------------------------------------------------------------------------
// 3. chain_spec_custom_validity
// ---------------------------------------------------------------------------

#[test]
fn chain_spec_custom_validity() {
    let spec = ChainSpec::new("leaf.example.com")
        .with_root_validity_days(7300)
        .with_intermediate_validity_days(1825)
        .with_leaf_validity_days(90);

    assert_eq!(spec.root_validity_days, 7300);
    assert_eq!(spec.intermediate_validity_days, 1825);
    assert_eq!(spec.leaf_validity_days, 90);

    // Verify defaults for the CN fields are still intact
    assert_eq!(spec.leaf_cn, "leaf.example.com");
    assert_eq!(spec.root_cn, "leaf.example.com Root CA");
    assert_eq!(spec.intermediate_cn, "leaf.example.com Intermediate CA");
    assert_eq!(spec.leaf_sans, vec!["leaf.example.com"]);
}

// ---------------------------------------------------------------------------
// 4. stable_bytes_is_deterministic
// ---------------------------------------------------------------------------

#[test]
fn stable_bytes_is_deterministic() {
    // X509Spec
    let spec_a = X509Spec::self_signed("determinism-test")
        .with_validity_days(180)
        .with_rsa_bits(4096)
        .with_sans(vec!["san1.test".into(), "san2.test".into()]);
    let spec_b = X509Spec::self_signed("determinism-test")
        .with_validity_days(180)
        .with_rsa_bits(4096)
        .with_sans(vec!["san1.test".into(), "san2.test".into()]);
    assert_eq!(spec_a.stable_bytes(), spec_b.stable_bytes());

    // ChainSpec
    let chain_a = ChainSpec::new("chain.test")
        .with_root_validity_days(3650)
        .with_intermediate_validity_days(1825)
        .with_leaf_validity_days(365);
    let chain_b = ChainSpec::new("chain.test")
        .with_root_validity_days(3650)
        .with_intermediate_validity_days(1825)
        .with_leaf_validity_days(365);
    assert_eq!(chain_a.stable_bytes(), chain_b.stable_bytes());
}

// ---------------------------------------------------------------------------
// 5. stable_bytes_differs_with_any_change
// ---------------------------------------------------------------------------

#[test]
fn stable_bytes_differs_with_any_change() {
    let base = X509Spec::self_signed("base.example.com")
        .with_validity_days(365)
        .with_not_before(NotBeforeOffset::DaysAgo(1))
        .with_rsa_bits(2048)
        .with_is_ca(false)
        .with_key_usage(KeyUsage::leaf())
        .with_sans(vec!["base.example.com".into()]);

    let base_bytes = base.stable_bytes();

    // subject_cn
    let mut changed = base.clone();
    changed.subject_cn = "other.example.com".into();
    assert_ne!(changed.stable_bytes(), base_bytes, "subject_cn");

    // issuer_cn
    let mut changed = base.clone();
    changed.issuer_cn = "issuer.example.com".into();
    assert_ne!(changed.stable_bytes(), base_bytes, "issuer_cn");

    // not_before_offset
    let changed = base
        .clone()
        .with_not_before(NotBeforeOffset::DaysFromNow(5));
    assert_ne!(changed.stable_bytes(), base_bytes, "not_before_offset");

    // validity_days
    let changed = base.clone().with_validity_days(999);
    assert_ne!(changed.stable_bytes(), base_bytes, "validity_days");

    // key_usage
    let changed = base.clone().with_key_usage(KeyUsage::ca());
    assert_ne!(changed.stable_bytes(), base_bytes, "key_usage");

    // is_ca
    let changed = base.clone().with_is_ca(true);
    assert_ne!(changed.stable_bytes(), base_bytes, "is_ca");

    // rsa_bits
    let changed = base.clone().with_rsa_bits(4096);
    assert_ne!(changed.stable_bytes(), base_bytes, "rsa_bits");

    // sans
    let changed = base
        .clone()
        .with_sans(vec!["different.example.com".into()]);
    assert_ne!(changed.stable_bytes(), base_bytes, "sans");
}

// ---------------------------------------------------------------------------
// 6. proptest_arbitrary_specs
// ---------------------------------------------------------------------------

mod proptest_specs {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn arbitrary_x509_spec_stable_bytes_never_panics(
            cn in "[a-z]{1,64}",
            validity_days in 0u32..36500,
            rsa_bits in prop_oneof![Just(2048usize), Just(3072usize), Just(4096usize)],
            is_ca in any::<bool>(),
            san_count in 0usize..5,
        ) {
            let sans: Vec<String> = (0..san_count)
                .map(|i| format!("san{i}.example.com"))
                .collect();

            let spec = X509Spec::self_signed(&cn)
                .with_validity_days(validity_days)
                .with_rsa_bits(rsa_bits)
                .with_is_ca(is_ca)
                .with_sans(sans);

            // Must not panic and must return non-empty bytes
            let bytes = spec.stable_bytes();
            prop_assert!(!bytes.is_empty());
        }

        #[test]
        fn arbitrary_chain_spec_stable_bytes_never_panics(
            cn in "[a-z]{1,64}",
            root_days in 0u32..36500,
            int_days in 0u32..36500,
            leaf_days in 0u32..36500,
        ) {
            let spec = ChainSpec::new(&cn)
                .with_root_validity_days(root_days)
                .with_intermediate_validity_days(int_days)
                .with_leaf_validity_days(leaf_days);

            let bytes = spec.stable_bytes();
            prop_assert!(!bytes.is_empty());
        }
    }
}

// ---------------------------------------------------------------------------
// 7. not_before_offset_variants
// ---------------------------------------------------------------------------

#[test]
fn not_before_offset_variants() {
    let same_day = 10u32;

    let days_ago = X509Spec::self_signed("offset-test")
        .with_not_before(NotBeforeOffset::DaysAgo(same_day));
    let days_from_now = X509Spec::self_signed("offset-test")
        .with_not_before(NotBeforeOffset::DaysFromNow(same_day));
    let default_offset = X509Spec::self_signed("offset-test")
        .with_not_before(NotBeforeOffset::default());

    let bytes_ago = days_ago.stable_bytes();
    let bytes_from_now = days_from_now.stable_bytes();
    let bytes_default = default_offset.stable_bytes();

    // DaysAgo and DaysFromNow with the same value must differ (tag byte 0 vs 1)
    assert_ne!(
        bytes_ago, bytes_from_now,
        "DaysAgo and DaysFromNow with same value must produce different stable_bytes"
    );

    // DaysAgo(10) differs from default DaysAgo(1)
    assert_ne!(
        bytes_ago, bytes_default,
        "DaysAgo(10) must differ from DaysAgo(1)"
    );

    // DaysFromNow(10) differs from default DaysAgo(1)
    assert_ne!(
        bytes_from_now, bytes_default,
        "DaysFromNow(10) must differ from default DaysAgo(1)"
    );

    // Two DaysAgo with different values must differ
    let days_ago_20 = X509Spec::self_signed("offset-test")
        .with_not_before(NotBeforeOffset::DaysAgo(20));
    assert_ne!(
        bytes_ago,
        days_ago_20.stable_bytes(),
        "DaysAgo(10) must differ from DaysAgo(20)"
    );

    // Two DaysFromNow with different values must differ
    let days_from_now_20 = X509Spec::self_signed("offset-test")
        .with_not_before(NotBeforeOffset::DaysFromNow(20));
    assert_ne!(
        bytes_from_now,
        days_from_now_20.stable_bytes(),
        "DaysFromNow(10) must differ from DaysFromNow(20)"
    );
}
