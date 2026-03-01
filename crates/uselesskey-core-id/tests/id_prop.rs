use proptest::prelude::*;
use uselesskey_core_id::{ArtifactId, DerivationVersion, Seed, derive_seed};

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Same master seed and ArtifactId always produce the same derived seed.
    #[test]
    fn derive_seed_is_deterministic(
        master in any::<[u8; 32]>(),
        label in ".*",
        spec in any::<[u8; 8]>(),
        variant in ".*",
    ) {
        let seed = Seed::new(master);
        let id = ArtifactId::new("domain:prop", &label, &spec, &variant, DerivationVersion::V1);

        let a = derive_seed(&seed, &id);
        let b = derive_seed(&seed, &id);
        prop_assert_eq!(a.bytes(), b.bytes());
    }

    /// Changing the label changes the derived seed.
    #[test]
    fn different_labels_produce_different_seeds(
        master in any::<[u8; 32]>(),
        label_a in "[a-z]{1,8}",
        label_b in "[a-z]{1,8}",
    ) {
        prop_assume!(label_a != label_b);
        let seed = Seed::new(master);
        let id_a = ArtifactId::new("domain:prop", &label_a, b"spec", "v", DerivationVersion::V1);
        let id_b = ArtifactId::new("domain:prop", &label_b, b"spec", "v", DerivationVersion::V1);

        let sa = derive_seed(&seed, &id_a);
        let sb = derive_seed(&seed, &id_b);
        prop_assert_ne!(sa.bytes(), sb.bytes());
    }

    /// Changing the variant changes the derived seed.
    #[test]
    fn different_variants_produce_different_seeds(
        master in any::<[u8; 32]>(),
        variant_a in "[a-z]{1,8}",
        variant_b in "[a-z]{1,8}",
    ) {
        prop_assume!(variant_a != variant_b);
        let seed = Seed::new(master);
        let id_a = ArtifactId::new("domain:prop", "label", b"spec", &variant_a, DerivationVersion::V1);
        let id_b = ArtifactId::new("domain:prop", "label", b"spec", &variant_b, DerivationVersion::V1);

        let sa = derive_seed(&seed, &id_a);
        let sb = derive_seed(&seed, &id_b);
        prop_assert_ne!(sa.bytes(), sb.bytes());
    }

    /// spec_fingerprint is always the BLAKE3 hash of the spec bytes.
    #[test]
    fn spec_fingerprint_matches_hash32(spec in any::<Vec<u8>>()) {
        let id = ArtifactId::new("d", "l", &spec, "v", DerivationVersion::V1);
        let expected = *uselesskey_core_id::hash32(&spec).as_bytes();
        prop_assert_eq!(id.spec_fingerprint, expected);
    }

    /// ArtifactId construction never panics on arbitrary input.
    #[test]
    fn artifact_id_new_never_panics(
        label in ".*",
        spec in any::<Vec<u8>>(),
        variant in ".*",
        version in any::<u16>(),
    ) {
        let _ = ArtifactId::new("domain:prop", label, &spec, variant, DerivationVersion(version));
    }
}
