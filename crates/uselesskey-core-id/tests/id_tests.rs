#![cfg(feature = "std")]

use uselesskey_core_id::{ArtifactId, DerivationVersion, Seed, derive_seed};

// ---------------------------------------------------------------------------
// Construction & field preservation
// ---------------------------------------------------------------------------

#[test]
fn new_preserves_all_fields() {
    let id = ArtifactId::new("domain:rsa", "issuer", b"RS256", "default", DerivationVersion::V1);

    assert_eq!(id.domain, "domain:rsa");
    assert_eq!(id.label, "issuer");
    assert_eq!(id.variant, "default");
    assert_eq!(id.derivation_version, DerivationVersion::V1);
}

#[test]
fn spec_fingerprint_is_hash_of_spec_bytes() {
    let spec = b"RS256-2048";
    let id = ArtifactId::new("d", "l", spec, "v", DerivationVersion::V1);

    let expected = *uselesskey_core_id::hash32(spec).as_bytes();
    assert_eq!(id.spec_fingerprint, expected);
}

#[test]
fn different_spec_bytes_produce_different_fingerprints() {
    let id_a = ArtifactId::new("d", "l", b"RS256", "v", DerivationVersion::V1);
    let id_b = ArtifactId::new("d", "l", b"RS384", "v", DerivationVersion::V1);
    assert_ne!(id_a.spec_fingerprint, id_b.spec_fingerprint);
}

// ---------------------------------------------------------------------------
// Equality
// ---------------------------------------------------------------------------

#[test]
fn same_components_are_equal() {
    let a = ArtifactId::new("d", "l", b"spec", "v", DerivationVersion::V1);
    let b = ArtifactId::new("d", "l", b"spec", "v", DerivationVersion::V1);
    assert_eq!(a, b);
}

#[test]
fn changing_domain_produces_different_id() {
    let base = ArtifactId::new("domain-a", "l", b"s", "v", DerivationVersion::V1);
    let other = ArtifactId::new("domain-b", "l", b"s", "v", DerivationVersion::V1);
    assert_ne!(base, other);
}

#[test]
fn changing_label_produces_different_id() {
    let base = ArtifactId::new("d", "label-a", b"s", "v", DerivationVersion::V1);
    let other = ArtifactId::new("d", "label-b", b"s", "v", DerivationVersion::V1);
    assert_ne!(base, other);
}

#[test]
fn changing_spec_produces_different_id() {
    let base = ArtifactId::new("d", "l", b"spec-a", "v", DerivationVersion::V1);
    let other = ArtifactId::new("d", "l", b"spec-b", "v", DerivationVersion::V1);
    assert_ne!(base, other);
}

#[test]
fn changing_variant_produces_different_id() {
    let base = ArtifactId::new("d", "l", b"s", "variant-a", DerivationVersion::V1);
    let other = ArtifactId::new("d", "l", b"s", "variant-b", DerivationVersion::V1);
    assert_ne!(base, other);
}

#[test]
fn changing_derivation_version_produces_different_id() {
    let base = ArtifactId::new("d", "l", b"s", "v", DerivationVersion::V1);
    let other = ArtifactId::new("d", "l", b"s", "v", DerivationVersion(2));
    assert_ne!(base, other);
}

// ---------------------------------------------------------------------------
// Display / Debug formatting
// ---------------------------------------------------------------------------

#[test]
fn debug_contains_all_component_names() {
    let id = ArtifactId::new("domain:rsa", "issuer", b"RS256", "default", DerivationVersion::V1);
    let dbg = format!("{id:?}");

    assert!(dbg.contains("domain:rsa"), "debug missing domain");
    assert!(dbg.contains("issuer"), "debug missing label");
    assert!(dbg.contains("default"), "debug missing variant");
    assert!(dbg.contains("DerivationVersion"), "debug missing version wrapper");
}

#[test]
fn derivation_version_debug_shows_inner_value() {
    let v = DerivationVersion(42);
    let dbg = format!("{v:?}");
    assert!(dbg.contains("42"), "debug should contain inner u16 value");
}

// ---------------------------------------------------------------------------
// Fingerprint stability
// ---------------------------------------------------------------------------

#[test]
fn fingerprint_is_stable_across_calls() {
    let a = ArtifactId::new("d", "l", b"stable-spec", "v", DerivationVersion::V1);
    let b = ArtifactId::new("d", "l", b"stable-spec", "v", DerivationVersion::V1);
    assert_eq!(a.spec_fingerprint, b.spec_fingerprint);
}

// ---------------------------------------------------------------------------
// Edge cases: empty strings
// ---------------------------------------------------------------------------

#[test]
fn empty_domain_is_accepted() {
    let id = ArtifactId::new("", "l", b"s", "v", DerivationVersion::V1);
    assert_eq!(id.domain, "");
}

#[test]
fn empty_label_is_accepted() {
    let id = ArtifactId::new("d", "", b"s", "v", DerivationVersion::V1);
    assert_eq!(id.label, "");
}

#[test]
fn empty_variant_is_accepted() {
    let id = ArtifactId::new("d", "l", b"s", "", DerivationVersion::V1);
    assert_eq!(id.variant, "");
}

#[test]
fn empty_spec_bytes_produce_valid_fingerprint() {
    let id = ArtifactId::new("d", "l", b"", "v", DerivationVersion::V1);
    let expected = *uselesskey_core_id::hash32(b"").as_bytes();
    assert_eq!(id.spec_fingerprint, expected);
}

#[test]
fn all_empty_strings_still_produces_valid_id() {
    let id = ArtifactId::new("", "", b"", "", DerivationVersion::V1);
    assert_eq!(id.domain, "");
    assert_eq!(id.label, "");
    assert_eq!(id.variant, "");
}

// ---------------------------------------------------------------------------
// Unicode strings
// ---------------------------------------------------------------------------

#[test]
fn unicode_label_is_preserved() {
    let id = ArtifactId::new("d", "日本語ラベル", b"s", "v", DerivationVersion::V1);
    assert_eq!(id.label, "日本語ラベル");
}

#[test]
fn unicode_variant_is_preserved() {
    let id = ArtifactId::new("d", "l", b"s", "вариант", DerivationVersion::V1);
    assert_eq!(id.variant, "вариант");
}

#[test]
fn unicode_label_affects_derived_seed() {
    let master = Seed::new([7u8; 32]);
    let id_a = ArtifactId::new("d", "alpha", b"s", "v", DerivationVersion::V1);
    let id_b = ArtifactId::new("d", "αlpha", b"s", "v", DerivationVersion::V1);
    assert_ne!(
        derive_seed(&master, &id_a).bytes(),
        derive_seed(&master, &id_b).bytes()
    );
}

// ---------------------------------------------------------------------------
// Clone semantics
// ---------------------------------------------------------------------------

#[test]
fn clone_produces_equal_id() {
    let id = ArtifactId::new("d", "l", b"s", "v", DerivationVersion::V1);
    let cloned = id.clone();
    assert_eq!(id, cloned);
}

#[test]
fn derivation_version_is_copy() {
    let v = DerivationVersion::V1;
    let copied = v;
    assert_eq!(v, copied);
}

// ---------------------------------------------------------------------------
// Hash / Ord consistency
// ---------------------------------------------------------------------------

#[test]
fn equal_ids_produce_equal_hashes() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let a = ArtifactId::new("d", "l", b"s", "v", DerivationVersion::V1);
    let b = ArtifactId::new("d", "l", b"s", "v", DerivationVersion::V1);

    let hash = |id: &ArtifactId| {
        let mut h = DefaultHasher::new();
        id.hash(&mut h);
        h.finish()
    };

    assert_eq!(hash(&a), hash(&b));
}

#[test]
fn ord_is_consistent_with_eq() {
    let a = ArtifactId::new("a", "l", b"s", "v", DerivationVersion::V1);
    let b = ArtifactId::new("b", "l", b"s", "v", DerivationVersion::V1);
    assert!(a < b);
    assert!(b > a);
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// derive_seed determinism & sensitivity
// ---------------------------------------------------------------------------

#[test]
fn derive_seed_is_deterministic() {
    let master = Seed::new([1u8; 32]);
    let id = ArtifactId::new("d", "l", b"s", "v", DerivationVersion::V1);

    let first = derive_seed(&master, &id);
    let second = derive_seed(&master, &id);
    assert_eq!(first.bytes(), second.bytes());
}

#[test]
fn derive_seed_differs_for_different_masters() {
    let id = ArtifactId::new("d", "l", b"s", "v", DerivationVersion::V1);

    let s1 = derive_seed(&Seed::new([1u8; 32]), &id);
    let s2 = derive_seed(&Seed::new([2u8; 32]), &id);
    assert_ne!(s1.bytes(), s2.bytes());
}

#[test]
fn derive_seed_differs_for_different_domains() {
    let master = Seed::new([1u8; 32]);
    let id_a = ArtifactId::new("domain-a", "l", b"s", "v", DerivationVersion::V1);
    let id_b = ArtifactId::new("domain-b", "l", b"s", "v", DerivationVersion::V1);
    assert_ne!(
        derive_seed(&master, &id_a).bytes(),
        derive_seed(&master, &id_b).bytes()
    );
}

#[test]
fn derive_seed_differs_for_different_variants() {
    let master = Seed::new([1u8; 32]);
    let id_a = ArtifactId::new("d", "l", b"s", "variant-a", DerivationVersion::V1);
    let id_b = ArtifactId::new("d", "l", b"s", "variant-b", DerivationVersion::V1);
    assert_ne!(
        derive_seed(&master, &id_a).bytes(),
        derive_seed(&master, &id_b).bytes()
    );
}

#[test]
fn derive_seed_differs_for_different_spec() {
    let master = Seed::new([1u8; 32]);
    let id_a = ArtifactId::new("d", "l", b"spec-a", "v", DerivationVersion::V1);
    let id_b = ArtifactId::new("d", "l", b"spec-b", "v", DerivationVersion::V1);
    assert_ne!(
        derive_seed(&master, &id_a).bytes(),
        derive_seed(&master, &id_b).bytes()
    );
}

// ---------------------------------------------------------------------------
// Property-based tests (proptest)
// ---------------------------------------------------------------------------

mod proptest_tests {
    use proptest::prelude::*;
    use uselesskey_core_id::{ArtifactId, DerivationVersion, Seed, derive_seed};

    fn arb_version() -> impl Strategy<Value = DerivationVersion> {
        (1u16..=100).prop_map(DerivationVersion)
    }

    proptest! {
        #[test]
        fn identical_fields_produce_equal_ids(
            label in "\\PC{0,30}",
            variant in "\\PC{0,30}",
            spec in proptest::collection::vec(any::<u8>(), 0..64),
            version in arb_version(),
        ) {
            let a = ArtifactId::new("domain:proptest", &label, &spec, &variant, version);
            let b = ArtifactId::new("domain:proptest", &label, &spec, &variant, version);
            prop_assert_eq!(&a, &b);
        }

        #[test]
        fn different_label_produces_different_id(
            label_a in "[a-z]{1,10}",
            label_b in "[a-z]{1,10}",
            spec in proptest::collection::vec(any::<u8>(), 1..32),
        ) {
            prop_assume!(label_a != label_b);
            let a = ArtifactId::new("d", &label_a, &spec, "v", DerivationVersion::V1);
            let b = ArtifactId::new("d", &label_b, &spec, "v", DerivationVersion::V1);
            prop_assert_ne!(&a, &b);
        }

        #[test]
        fn different_variant_produces_different_id(
            variant_a in "[a-z]{1,10}",
            variant_b in "[a-z]{1,10}",
        ) {
            prop_assume!(variant_a != variant_b);
            let a = ArtifactId::new("d", "l", b"s", &variant_a, DerivationVersion::V1);
            let b = ArtifactId::new("d", "l", b"s", &variant_b, DerivationVersion::V1);
            prop_assert_ne!(&a, &b);
        }

        #[test]
        fn different_version_produces_different_id(
            va in 1u16..50,
            vb in 51u16..100,
        ) {
            let a = ArtifactId::new("d", "l", b"s", "v", DerivationVersion(va));
            let b = ArtifactId::new("d", "l", b"s", "v", DerivationVersion(vb));
            prop_assert_ne!(&a, &b);
        }

        #[test]
        fn identical_ids_produce_identical_derived_seeds(
            label in "\\PC{0,20}",
            variant in "\\PC{0,20}",
            spec in proptest::collection::vec(any::<u8>(), 0..32),
            master_bytes in proptest::collection::vec(any::<u8>(), 32..=32),
        ) {
            let mut seed_arr = [0u8; 32];
            seed_arr.copy_from_slice(&master_bytes);
            let master = Seed::new(seed_arr);

            let id_a = ArtifactId::new("d", &label, &spec, &variant, DerivationVersion::V1);
            let id_b = ArtifactId::new("d", &label, &spec, &variant, DerivationVersion::V1);
            let seed_a = derive_seed(&master, &id_a);
            let seed_b = derive_seed(&master, &id_b);
            prop_assert_eq!(seed_a.bytes(), seed_b.bytes());
        }

        #[test]
        fn changing_any_field_changes_derived_seed(
            label in "[a-z]{1,10}",
            variant in "[a-z]{1,10}",
        ) {
            let master = Seed::new([42u8; 32]);
            let base = ArtifactId::new("d", &label, b"spec", &variant, DerivationVersion::V1);
            let alt_label = ArtifactId::new("d", "ZZZZZ", b"spec", &variant, DerivationVersion::V1);
            let alt_variant = ArtifactId::new("d", &label, b"spec", "ZZZZZ", DerivationVersion::V1);
            let alt_spec = ArtifactId::new("d", &label, b"other-spec", &variant, DerivationVersion::V1);
            let alt_domain = ArtifactId::new("other", &label, b"spec", &variant, DerivationVersion::V1);

            let base_seed = derive_seed(&master, &base);

            if base.label != "ZZZZZ" {
                let s = derive_seed(&master, &alt_label);
                prop_assert_ne!(base_seed.bytes(), s.bytes());
            }
            if base.variant != "ZZZZZ" {
                let s = derive_seed(&master, &alt_variant);
                prop_assert_ne!(base_seed.bytes(), s.bytes());
            }
            let s_spec = derive_seed(&master, &alt_spec);
            prop_assert_ne!(base_seed.bytes(), s_spec.bytes());
            let s_domain = derive_seed(&master, &alt_domain);
            prop_assert_ne!(base_seed.bytes(), s_domain.bytes());
        }
    }
}
