//! Error handling and edge case tests for `uselesskey-core-factory`.

#![cfg(feature = "std")]

use std::sync::Arc;

use rstest::rstest;
use uselesskey_core_factory::{Factory, Mode};
use uselesskey_core_id::Seed;

// ---------------------------------------------------------------------------
// 1. Debug impl: no seed material leakage
// ---------------------------------------------------------------------------

#[test]
fn factory_debug_does_not_leak_seed_bytes() {
    let seed = Seed::new([0xAB; 32]);
    let fx = Factory::deterministic(seed);
    let dbg = format!("{fx:?}");
    // Seed debug is redacted
    assert!(
        dbg.contains("redacted"),
        "Factory debug should show redacted seed, got: {dbg}"
    );
    assert!(
        !dbg.contains("ABABABAB"),
        "Factory debug must not leak raw seed bytes"
    );
    assert!(dbg.contains("Factory"), "Debug should name the type");
    assert!(dbg.contains("cache_size"), "Debug should show cache_size");
}

#[test]
fn factory_debug_random_mode() {
    let fx = Factory::random();
    let dbg = format!("{fx:?}");
    assert!(dbg.contains("Random"), "Random factory debug: {dbg}");
    assert!(dbg.contains("cache_size: 0"));
}

#[test]
fn mode_debug_deterministic_is_redacted() {
    let mode = Mode::Deterministic {
        master: Seed::new([0xFF; 32]),
    };
    let dbg = format!("{mode:?}");
    assert!(dbg.contains("Deterministic"));
    assert!(dbg.contains("redacted"));
    assert!(
        !dbg.contains("FFFFFFFF"),
        "Mode debug must not show seed bytes"
    );
}

#[test]
fn mode_debug_random() {
    let mode = Mode::Random;
    let dbg = format!("{mode:?}");
    assert!(dbg.contains("Random"));
}

// ---------------------------------------------------------------------------
// 2. Mode Clone
// ---------------------------------------------------------------------------

#[test]
fn mode_clone_deterministic() {
    let seed = Seed::new([1u8; 32]);
    let mode = Mode::Deterministic { master: seed };
    let cloned = mode.clone();
    match cloned {
        Mode::Deterministic { master } => assert_eq!(master.bytes(), seed.bytes()),
        Mode::Random => panic!("clone should preserve Deterministic"),
    }
}

#[test]
fn mode_clone_random() {
    let mode = Mode::Random;
    let cloned = mode.clone();
    matches!(cloned, Mode::Random);
}

// ---------------------------------------------------------------------------
// 3. Factory clone shares cache
// ---------------------------------------------------------------------------

#[test]
fn factory_clone_shares_cache() {
    let fx = Factory::random();
    let fx2 = fx.clone();

    let val: Arc<u64> = fx.get_or_init("domain:share", "label", b"spec", "v", |_rng| 42u64);
    let val2: Arc<u64> = fx2.get_or_init("domain:share", "label", b"spec", "v", |_rng| 99u64);

    // The second call should hit the cache from the first
    assert!(Arc::ptr_eq(&val, &val2));
    assert_eq!(*val, 42);
}

#[test]
fn factory_clear_cache_on_clone_affects_original() {
    let fx = Factory::random();
    let fx2 = fx.clone();

    let _ = fx.get_or_init("domain:clear", "label", b"spec", "v", |_rng| 1u8);
    fx2.clear_cache();

    // Cache was shared, so original's cache is also cleared
    let dbg = format!("{fx:?}");
    assert!(
        dbg.contains("cache_size: 0"),
        "clear_cache on clone should affect original: {dbg}"
    );
}

// ---------------------------------------------------------------------------
// 4. get_or_init: different keys produce different cache entries
// ---------------------------------------------------------------------------

#[rstest]
#[case(
    "domain:a", "label", b"spec", "variant", "domain:b", "label", b"spec", "variant"
)]
#[case("domain:x", "alpha", b"spec", "v", "domain:x", "beta", b"spec", "v")]
#[case(
    "domain:x", "label", b"spec-1", "v", "domain:x", "label", b"spec-2", "v"
)]
#[case("domain:x", "label", b"spec", "v1", "domain:x", "label", b"spec", "v2")]
#[allow(clippy::too_many_arguments)]
fn different_keys_produce_distinct_entries(
    #[case] d1: &'static str,
    #[case] l1: &str,
    #[case] s1: &[u8],
    #[case] v1: &str,
    #[case] d2: &'static str,
    #[case] l2: &str,
    #[case] s2: &[u8],
    #[case] v2: &str,
) {
    let fx = Factory::random();
    let a: Arc<u64> = fx.get_or_init(d1, l1, s1, v1, |_rng| 1u64);
    let b: Arc<u64> = fx.get_or_init(d2, l2, s2, v2, |_rng| 2u64);
    assert!(!Arc::ptr_eq(&a, &b));
}

// ---------------------------------------------------------------------------
// 5. Deterministic mode: same seed + same id = same value
// ---------------------------------------------------------------------------

#[test]
fn deterministic_same_inputs_same_output() {
    let fx = Factory::deterministic(Seed::new([99u8; 32]));
    let a: Arc<u64> = fx.get_or_init("domain:det", "lab", b"spec", "v", |rng| {
        use rand_core::RngCore;
        rng.next_u64()
    });
    // Clear cache and re-derive — should get same value from same seed
    fx.clear_cache();
    let b: Arc<u64> = fx.get_or_init("domain:det", "lab", b"spec", "v", |rng| {
        use rand_core::RngCore;
        rng.next_u64()
    });
    assert_eq!(*a, *b);
    assert!(!Arc::ptr_eq(&a, &b)); // Different Arc instances after clear
}

// ---------------------------------------------------------------------------
// 6. Different seeds produce different values
// ---------------------------------------------------------------------------

#[test]
fn different_seeds_produce_different_values() {
    let fx1 = Factory::deterministic(Seed::new([1u8; 32]));
    let fx2 = Factory::deterministic(Seed::new([2u8; 32]));

    let a: Arc<u64> = fx1.get_or_init("domain:seed", "lab", b"spec", "v", |rng| {
        use rand_core::RngCore;
        rng.next_u64()
    });
    let b: Arc<u64> = fx2.get_or_init("domain:seed", "lab", b"spec", "v", |rng| {
        use rand_core::RngCore;
        rng.next_u64()
    });
    assert_ne!(*a, *b);
}

// ---------------------------------------------------------------------------
// 7. Type mismatch causes panic
// ---------------------------------------------------------------------------

#[test]
fn type_mismatch_panics() {
    let fx = Factory::random();
    let _ = fx.get_or_init("domain:mismatch", "label", b"spec", "v", |_rng| 42u32);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Arc<String> = fx.get_or_init("domain:mismatch", "label", b"spec", "v", |_rng| {
            String::from("wrong type")
        });
    }));
    assert!(result.is_err(), "Type mismatch should panic");
}

// ---------------------------------------------------------------------------
// 8. Edge case: empty and special strings as keys
// ---------------------------------------------------------------------------

#[test]
fn empty_label_and_variant_work() {
    let fx = Factory::random();
    let val: Arc<u8> = fx.get_or_init("domain:empty", "", b"", "", |_rng| 7u8);
    assert_eq!(*val, 7);
}

#[test]
fn unicode_label_works() {
    let fx = Factory::random();
    let val: Arc<u8> = fx.get_or_init("domain:unicode", "日本語", b"spec", "变体", |_rng| 8u8);
    assert_eq!(*val, 8);
}

// ---------------------------------------------------------------------------
// 9. Cache size tracking
// ---------------------------------------------------------------------------

#[test]
fn cache_size_grows_and_resets() {
    let fx = Factory::random();
    let dbg = format!("{fx:?}");
    assert!(dbg.contains("cache_size: 0"));

    let _ = fx.get_or_init("domain:size", "a", b"s", "v", |_rng| 1u8);
    let _ = fx.get_or_init("domain:size", "b", b"s", "v", |_rng| 2u8);
    let dbg = format!("{fx:?}");
    assert!(dbg.contains("cache_size: 2"), "after 2 inserts: {dbg}");

    fx.clear_cache();
    let dbg = format!("{fx:?}");
    assert!(dbg.contains("cache_size: 0"), "after clear: {dbg}");
}

// ---------------------------------------------------------------------------
// 10. mode() accessor returns correct variant
// ---------------------------------------------------------------------------

#[test]
fn mode_accessor_random() {
    let fx = Factory::random();
    assert!(matches!(fx.mode(), Mode::Random));
}

#[test]
fn mode_accessor_deterministic() {
    let seed = Seed::new([5u8; 32]);
    let fx = Factory::deterministic(seed);
    match fx.mode() {
        Mode::Deterministic { master } => assert_eq!(master.bytes(), seed.bytes()),
        Mode::Random => panic!("expected Deterministic"),
    }
}
