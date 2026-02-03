use proptest::prelude::*;

use uselesskey_core::{Factory, Seed};

fn spec_bytes(bits: u32, e: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&bits.to_be_bytes());
    v.extend_from_slice(&e.to_be_bytes());
    v
}

#[test]
fn deterministic_is_order_independent_for_cache_keys() {
    let seed = Seed::new([42u8; 32]);
    let fx = Factory::deterministic(seed);

    // Two different artifact keys.
    let a = fx.get_or_init("domain:a", "label", &spec_bytes(1, 2), "good", |_rng| 123u32);
    let b = fx.get_or_init("domain:b", "label", &spec_bytes(3, 4), "good", |_rng| 456u32);

    // Clear cache and request in reverse order; values should match.
    fx.clear_cache();
    let b2 = fx.get_or_init("domain:b", "label", &spec_bytes(3, 4), "good", |_rng| 456u32);
    let a2 = fx.get_or_init("domain:a", "label", &spec_bytes(1, 2), "good", |_rng| 123u32);

    assert_eq!(*a, *a2);
    assert_eq!(*b, *b2);
}

proptest! {
    #[test]
    fn deterministic_factory_returns_same_value_for_same_id(seed_bytes in any::<[u8;32]>(), label in "[-_a-zA-Z0-9]{1,32}") {
        let fx = Factory::deterministic(Seed::new(seed_bytes));
        let spec = spec_bytes(2048, 65537);

        let v1 = fx.get_or_init("domain:test", &label, &spec, "good", |_rng| 7u32);
        let v2 = fx.get_or_init("domain:test", &label, &spec, "good", |_rng| 7u32);

        prop_assert_eq!(*v1, *v2);
    }
}
