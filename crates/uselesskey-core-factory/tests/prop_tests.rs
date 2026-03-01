#![cfg(feature = "std")]

use proptest::prelude::*;
use rand_core::RngCore;
use uselesskey_core_factory::{Factory, Mode};
use uselesskey_core_id::{ArtifactId, DerivationVersion, Seed, derive_seed};

proptest! {
    #[test]
    fn deterministic_factory_same_seed_same_result(seed in any::<[u8; 32]>()) {
        let fx1 = Factory::deterministic(Seed::new(seed));
        let fx2 = Factory::deterministic(Seed::new(seed));

        let a = *fx1.get_or_init("domain:prop", "label", b"spec", "variant", |rng| rng.next_u64());
        let b = *fx2.get_or_init("domain:prop", "label", b"spec", "variant", |rng| rng.next_u64());

        prop_assert_eq!(a, b);
    }

    #[test]
    fn different_seeds_produce_different_derivations(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
    ) {
        prop_assume!(seed_a != seed_b);

        let fx_a = Factory::deterministic(Seed::new(seed_a));
        let fx_b = Factory::deterministic(Seed::new(seed_b));

        let a = *fx_a.get_or_init("domain:prop", "label", b"spec", "variant", |rng| rng.next_u64());
        let b = *fx_b.get_or_init("domain:prop", "label", b"spec", "variant", |rng| rng.next_u64());

        prop_assert_ne!(a, b);
    }

    #[test]
    fn derive_seed_is_deterministic(
        seed in any::<[u8; 32]>(),
        label in "[a-zA-Z0-9_-]{1,16}",
    ) {
        let master = Seed::new(seed);
        let id = ArtifactId::new("domain:prop", &label, b"spec", "variant", DerivationVersion::V1);

        let first = derive_seed(&master, &id);
        let second = derive_seed(&master, &id);

        prop_assert_eq!(first.bytes(), second.bytes());
    }

    #[test]
    fn derive_seed_varies_with_label(
        seed in any::<[u8; 32]>(),
        label_a in "[a-zA-Z0-9_-]{1,12}",
        label_b in "[a-zA-Z0-9_-]{1,12}",
    ) {
        prop_assume!(label_a != label_b);

        let master = Seed::new(seed);
        let id_a = ArtifactId::new("domain:prop", &label_a, b"spec", "variant", DerivationVersion::V1);
        let id_b = ArtifactId::new("domain:prop", &label_b, b"spec", "variant", DerivationVersion::V1);

        let seed_a = derive_seed(&master, &id_a);
        let seed_b = derive_seed(&master, &id_b);

        prop_assert_ne!(seed_a.bytes(), seed_b.bytes());
    }
}

#[test]
fn factory_mode_detection() {
    let det = Factory::deterministic(Seed::new([0u8; 32]));
    assert!(matches!(det.mode(), Mode::Deterministic { .. }));

    let rnd = Factory::random();
    assert!(matches!(rnd.mode(), Mode::Random));
}
