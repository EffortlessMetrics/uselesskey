#![cfg(feature = "std")]

use proptest::prelude::*;
use uselesskey_core_factory::Factory;
use uselesskey_core_id::Seed;

fn seed_u64(seed: Seed) -> u64 {
    let mut buf = [0u8; 8];
    seed.fill_bytes(&mut buf);
    u64::from_le_bytes(buf)
}

#[test]
fn deterministic_factory_returns_same_value_for_same_id() {
    let fx = Factory::deterministic(Seed::new([1u8; 32]));
    let a = fx.get_or_init("domain:seed", "label", b"spec", "variant", seed_u64);
    let b = fx.get_or_init("domain:seed", "label", b"spec", "variant", seed_u64);

    assert_eq!(*a, *b);
}

proptest! {
    #[test]
    fn different_spec_seeds_still_distinct(seed in any::<[u8; 32]>(), label in "[a-zA-Z0-9_-]{1,16}") {
        let fx = Factory::deterministic(Seed::new(seed));

        let left = *fx.get_or_init("domain:prop", &label, b"spec-A", "variant", seed_u64);
        let right = *fx.get_or_init("domain:prop", &label, b"spec-B", "variant", seed_u64);

        prop_assert_ne!(left, right);
    }

    #[test]
    fn different_labels_still_distinct(seed in any::<[u8; 32]>(), left in "[a-zA-Z0-9_-]{1,12}", right in "[a-zA-Z0-9_-]{1,12}") {
        prop_assume!(left != right);

        let fx = Factory::deterministic(Seed::new(seed));

        let left_value = *fx.get_or_init("domain:prop", &left, b"spec", "variant", seed_u64);
        let right_value = *fx.get_or_init("domain:prop", &right, b"spec", "variant", seed_u64);

        prop_assert_ne!(left_value, right_value);
    }

    #[test]
    fn different_variants_still_distinct(seed in any::<[u8; 32]>(), variant_a in "[a-zA-Z0-9_-]{1,12}", variant_b in "[a-zA-Z0-9_-]{1,12}") {
        prop_assume!(variant_a != variant_b);

        let fx = Factory::deterministic(Seed::new(seed));

        let a = *fx.get_or_init("domain:prop", "label", b"spec", &variant_a, seed_u64);
        let b = *fx.get_or_init("domain:prop", "label", b"spec", &variant_b, seed_u64);

        prop_assert_ne!(a, b);
    }
}
