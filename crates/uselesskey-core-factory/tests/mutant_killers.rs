//! Mutant-killing tests for core factory.

use std::sync::Arc;
use uselesskey_core_factory::{Factory, Mode};
use uselesskey_core_id::Seed;

fn seed_u64(seed: Seed) -> u64 {
    let mut buf = [0u8; 8];
    seed.fill_bytes(&mut buf);
    u64::from_le_bytes(buf)
}

#[test]
fn factory_random_mode() {
    let fx = Factory::random();
    assert!(matches!(fx.mode(), Mode::Random));
}

#[test]
fn factory_deterministic_mode() {
    let seed = Seed::new([1u8; 32]);
    let fx = Factory::deterministic(seed);
    match fx.mode() {
        Mode::Deterministic { master } => {
            assert_eq!(master.bytes(), seed.bytes());
        }
        Mode::Random => panic!("expected Deterministic"),
    }
}

#[test]
fn deterministic_same_inputs_produce_same_value() {
    let seed = Seed::new([42u8; 32]);
    let fx = Factory::deterministic(seed);

    let a: Arc<u64> = fx.get_or_init("test:domain", "label", b"spec", "good", |_rng| 12345u64);
    let b: Arc<u64> = fx.get_or_init("test:domain", "label", b"spec", "good", |_rng| 99999u64);

    assert_eq!(*a, 12345);
    assert_eq!(*b, 12345); // cached
    assert!(Arc::ptr_eq(&a, &b));
}

#[test]
fn deterministic_different_labels_produce_different_values() {
    let seed = Seed::new([42u8; 32]);
    let fx = Factory::deterministic(seed);

    let a: Arc<u64> = fx.get_or_init("d", "label-a", b"spec", "good", seed_u64);
    let b: Arc<u64> = fx.get_or_init("d", "label-b", b"spec", "good", seed_u64);

    assert_ne!(*a, *b);
}

#[test]
fn deterministic_different_variants_produce_different_values() {
    let seed = Seed::new([42u8; 32]);
    let fx = Factory::deterministic(seed);

    let a: Arc<u64> = fx.get_or_init("d", "label", b"spec", "variant-a", seed_u64);
    let b: Arc<u64> = fx.get_or_init("d", "label", b"spec", "variant-b", seed_u64);

    assert_ne!(*a, *b);
}

#[test]
fn clear_cache_allows_regeneration() {
    // Deterministic mode keeps this behavior test valid under `--no-default-features`.
    let fx = Factory::deterministic(Seed::new([7u8; 32]));

    let a: Arc<u32> = fx.get_or_init("d", "l", b"s", "v", |_| 1u32);
    assert_eq!(*a, 1);

    fx.clear_cache();

    let b: Arc<u32> = fx.get_or_init("d", "l", b"s", "v", |_| 2u32);
    assert_eq!(*b, 2);
    assert!(!Arc::ptr_eq(&a, &b));
}

#[test]
fn debug_includes_mode_and_cache_size() {
    let fx = Factory::random();
    let dbg = format!("{fx:?}");
    assert!(dbg.contains("Factory"));
    assert!(dbg.contains("Random"));
    assert!(dbg.contains("cache_size: 0"));
}

#[test]
fn debug_deterministic_mode() {
    let seed = Seed::new([0u8; 32]);
    let fx = Factory::deterministic(seed);
    let dbg = format!("{fx:?}");
    assert!(dbg.contains("Deterministic"));
    // Seed should be redacted
    assert!(dbg.contains("redacted"));
}

#[test]
fn clone_shares_cache() {
    // Deterministic mode keeps this cache-sharing invariant test independent
    // from `std`-only random seeding.
    let fx = Factory::deterministic(Seed::new([8u8; 32]));
    let a: Arc<u32> = fx.get_or_init("d", "l", b"s", "v", |_| 42u32);

    let fx2 = fx.clone();
    let b: Arc<u32> = fx2.get_or_init("d", "l", b"s", "v", |_| 99u32);

    assert_eq!(*b, 42); // should get cached value from original
    assert!(Arc::ptr_eq(&a, &b));
}
