use proptest::prelude::*;
use uselesskey_core_id::{ArtifactId, DerivationVersion, Seed, derive_seed};

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn derive_seed_is_deterministic(
        master in any::<[u8; 32]>(),
        label in "[a-z0-9_-]{1,16}",
        spec in any::<Vec<u8>>(),
        variant in "[a-z0-9_-]{1,16}",
    ) {
        let master = Seed::new(master);
        let id = ArtifactId::new("domain:test", &label, &spec, &variant, DerivationVersion::V1);
        let a = derive_seed(&master, &id);
        let b = derive_seed(&master, &id);
        prop_assert_eq!(a.bytes(), b.bytes());
    }

    #[test]
    fn different_labels_produce_different_seeds(
        master in any::<[u8; 32]>(),
        label_a in "[a-z]{1,8}",
        label_b in "[a-z]{1,8}",
    ) {
        prop_assume!(label_a != label_b);
        let master = Seed::new(master);
        let id_a = ArtifactId::new("d", &label_a, b"spec", "v", DerivationVersion::V1);
        let id_b = ArtifactId::new("d", &label_b, b"spec", "v", DerivationVersion::V1);
        let sa = derive_seed(&master, &id_a);
        let sb = derive_seed(&master, &id_b);
        prop_assert_ne!(sa.bytes(), sb.bytes());
    }

    #[test]
    fn different_variants_produce_different_seeds(
        master in any::<[u8; 32]>(),
        var_a in "[a-z]{1,8}",
        var_b in "[a-z]{1,8}",
    ) {
        prop_assume!(var_a != var_b);
        let master = Seed::new(master);
        let id_a = ArtifactId::new("d", "label", b"spec", &var_a, DerivationVersion::V1);
        let id_b = ArtifactId::new("d", "label", b"spec", &var_b, DerivationVersion::V1);
        let sa = derive_seed(&master, &id_a);
        let sb = derive_seed(&master, &id_b);
        prop_assert_ne!(sa.bytes(), sb.bytes());
    }

    #[test]
    fn different_specs_produce_different_seeds(
        master in any::<[u8; 32]>(),
        spec_a in proptest::collection::vec(any::<u8>(), 1..32),
        spec_b in proptest::collection::vec(any::<u8>(), 1..32),
    ) {
        prop_assume!(spec_a != spec_b);
        let master = Seed::new(master);
        let id_a = ArtifactId::new("d", "label", &spec_a, "v", DerivationVersion::V1);
        let id_b = ArtifactId::new("d", "label", &spec_b, "v", DerivationVersion::V1);
        let sa = derive_seed(&master, &id_a);
        let sb = derive_seed(&master, &id_b);
        prop_assert_ne!(sa.bytes(), sb.bytes());
    }

    #[test]
    fn different_masters_produce_different_seeds(
        master_a in any::<[u8; 32]>(),
        master_b in any::<[u8; 32]>(),
    ) {
        prop_assume!(master_a != master_b);
        let id = ArtifactId::new("d", "label", b"spec", "v", DerivationVersion::V1);
        let a = derive_seed(&Seed::new(master_a), &id);
        let b = derive_seed(&Seed::new(master_b), &id);
        prop_assert_ne!(a.bytes(), b.bytes());
    }

    #[test]
    fn spec_fingerprint_is_stable(spec in any::<Vec<u8>>()) {
        let id_a = ArtifactId::new("d", "l", &spec, "v", DerivationVersion::V1);
        let id_b = ArtifactId::new("d", "l", &spec, "v", DerivationVersion::V1);
        prop_assert_eq!(id_a.spec_fingerprint, id_b.spec_fingerprint);
    }

    #[test]
    fn derivation_version_affects_output(
        master in any::<[u8; 32]>(),
        v1 in 1u16..100,
        v2 in 100u16..200,
    ) {
        let master = Seed::new(master);
        let id_a = ArtifactId::new("d", "l", b"s", "v", DerivationVersion(v1));
        let id_b = ArtifactId::new("d", "l", b"s", "v", DerivationVersion(v2));
        let sa = derive_seed(&master, &id_a);
        let sb = derive_seed(&master, &id_b);
        prop_assert_ne!(sa.bytes(), sb.bytes());
    }
}
