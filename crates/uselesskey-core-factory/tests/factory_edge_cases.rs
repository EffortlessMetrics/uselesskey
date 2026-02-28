#![cfg(feature = "std")]

use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

use rand_core::RngCore;
use uselesskey_core_factory::Factory;
use uselesskey_core_id::Seed;

// ---------------------------------------------------------------------------
// 1. Concurrent factory usage from multiple threads
// ---------------------------------------------------------------------------

#[test]
fn concurrent_factory_usage_from_multiple_threads() {
    let fx = Factory::deterministic(Seed::new([10u8; 32]));
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let fx = fx.clone();
            thread::spawn(move || {
                let label = format!("thread-{i}");
                let val: Arc<u64> =
                    fx.get_or_init("domain:thread", &label, b"spec", "good", |rng| {
                        rng.next_u64()
                    });
                *val
            })
        })
        .collect();

    let results: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let unique: HashSet<_> = results.iter().collect();
    assert_eq!(
        unique.len(),
        8,
        "each thread should produce a distinct value"
    );
}

// ---------------------------------------------------------------------------
// 2. Factory::random() produces different values each time (different keys)
// ---------------------------------------------------------------------------

#[test]
fn random_factory_produces_different_values_for_different_labels() {
    let fx = Factory::random();
    let mut values = HashSet::new();

    for i in 0..20 {
        let label = format!("rand-{i}");
        let val: Arc<u64> = fx.get_or_init("domain:random", &label, b"spec", "good", |rng| {
            rng.next_u64()
        });
        values.insert(*val);
    }

    assert!(
        values.len() >= 18,
        "random factory should produce mostly distinct values, got {}",
        values.len()
    );
}

// ---------------------------------------------------------------------------
// 3. Factory::deterministic() with same seed produces identical values
// ---------------------------------------------------------------------------

#[test]
fn deterministic_same_seed_produces_identical_values() {
    let seed = Seed::new([55u8; 32]);

    let fx1 = Factory::deterministic(seed);
    let fx2 = Factory::deterministic(seed);

    for i in 0..10 {
        let label = format!("det-{i}");
        let v1: Arc<u64> =
            fx1.get_or_init("domain:det", &label, b"spec", "good", |rng| rng.next_u64());
        let v2: Arc<u64> =
            fx2.get_or_init("domain:det", &label, b"spec", "good", |rng| rng.next_u64());
        assert_eq!(*v1, *v2, "mismatch at label {label}");
    }
}

// ---------------------------------------------------------------------------
// 4. Large number of artifacts (100+) generated without cache collision
// ---------------------------------------------------------------------------

#[test]
fn large_artifact_count_no_cache_collision() {
    let fx = Factory::deterministic(Seed::new([77u8; 32]));
    let count = 200;
    let mut values = HashSet::new();

    for i in 0..count {
        let label = format!("bulk-{i}");
        let val: Arc<u64> =
            fx.get_or_init("domain:bulk", &label, b"spec", "good", |rng| rng.next_u64());
        values.insert(*val);
    }

    assert_eq!(
        values.len(),
        count,
        "all {count} artifacts should have unique values"
    );
}

// ---------------------------------------------------------------------------
// 5. Cache isolation between different label/domain combinations
// ---------------------------------------------------------------------------

#[test]
fn cache_isolation_between_label_and_domain() {
    let fx = Factory::deterministic(Seed::new([33u8; 32]));

    let a: Arc<u64> = fx.get_or_init("domain:alpha", "shared-label", b"spec", "good", |rng| {
        rng.next_u64()
    });
    let b: Arc<u64> = fx.get_or_init("domain:beta", "shared-label", b"spec", "good", |rng| {
        rng.next_u64()
    });

    assert_ne!(
        *a, *b,
        "different domains with same label should produce different values"
    );
    assert!(
        !Arc::ptr_eq(&a, &b),
        "different domains must not share cache entries"
    );
}

#[test]
fn cache_isolation_between_labels_same_domain() {
    let fx = Factory::deterministic(Seed::new([33u8; 32]));

    let a: Arc<u64> = fx.get_or_init("domain:same", "label-a", b"spec", "good", |rng| {
        rng.next_u64()
    });
    let b: Arc<u64> = fx.get_or_init("domain:same", "label-b", b"spec", "good", |rng| {
        rng.next_u64()
    });

    assert_ne!(
        *a, *b,
        "different labels in same domain should produce different values"
    );
}

#[test]
fn cache_isolation_between_variants() {
    let fx = Factory::deterministic(Seed::new([33u8; 32]));

    let a: Arc<u64> = fx.get_or_init("domain:var", "label", b"spec", "variant-a", |rng| {
        rng.next_u64()
    });
    let b: Arc<u64> = fx.get_or_init("domain:var", "label", b"spec", "variant-b", |rng| {
        rng.next_u64()
    });

    assert_ne!(*a, *b, "different variants should produce different values");
}

// ---------------------------------------------------------------------------
// 6. Thread safety: shared factory across threads producing correct results
// ---------------------------------------------------------------------------

#[test]
fn shared_factory_across_threads_deterministic_consistency() {
    let seed = Seed::new([99u8; 32]);
    let fx = Factory::deterministic(seed);

    // Pre-compute expected values in the main thread.
    let expected: Vec<(String, u64)> = (0..16)
        .map(|i| {
            let label = format!("ts-{i}");
            let val: Arc<u64> =
                fx.get_or_init("domain:ts", &label, b"spec", "good", |rng| rng.next_u64());
            (label, *val)
        })
        .collect();

    fx.clear_cache();

    // Re-generate from threads and verify determinism.
    let handles: Vec<_> = expected
        .into_iter()
        .map(|(label, expected_val)| {
            let fx = fx.clone();
            thread::spawn(move || {
                let val: Arc<u64> =
                    fx.get_or_init("domain:ts", &label, b"spec", "good", |rng| rng.next_u64());
                assert_eq!(*val, expected_val, "thread mismatch for {label}");
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

// ---------------------------------------------------------------------------
// 7. Factory with empty seed behavior
// ---------------------------------------------------------------------------

#[test]
fn factory_with_zero_seed_is_deterministic() {
    let fx1 = Factory::deterministic(Seed::new([0u8; 32]));
    let fx2 = Factory::deterministic(Seed::new([0u8; 32]));

    let v1: Arc<u64> = fx1.get_or_init("domain:zero", "label", b"spec", "good", |rng| {
        rng.next_u64()
    });
    let v2: Arc<u64> = fx2.get_or_init("domain:zero", "label", b"spec", "good", |rng| {
        rng.next_u64()
    });

    assert_eq!(*v1, *v2, "zero seed should still be deterministic");
}

#[test]
fn factory_with_zero_seed_differs_from_nonzero_seed() {
    let fx_zero = Factory::deterministic(Seed::new([0u8; 32]));
    let fx_one = Factory::deterministic(Seed::new([1u8; 32]));

    let v_zero: Arc<u64> =
        fx_zero.get_or_init("domain:seed-cmp", "label", b"spec", "good", |rng| {
            rng.next_u64()
        });
    let v_one: Arc<u64> = fx_one.get_or_init("domain:seed-cmp", "label", b"spec", "good", |rng| {
        rng.next_u64()
    });

    assert_ne!(
        *v_zero, *v_one,
        "different seeds must produce different values"
    );
}

// ---------------------------------------------------------------------------
// 8. Multiple factories with different seeds don't interfere
// ---------------------------------------------------------------------------

#[test]
fn multiple_factories_different_seeds_no_interference() {
    let seeds: Vec<Seed> = (0u8..5).map(|i| Seed::new([i + 10; 32])).collect();
    let factories: Vec<Factory> = seeds.iter().map(|s| Factory::deterministic(*s)).collect();

    // Each factory generates a value for the same artifact id.
    let values: Vec<u64> = factories
        .iter()
        .map(|fx| {
            *fx.get_or_init("domain:multi", "shared", b"spec", "good", |rng| {
                rng.next_u64()
            })
        })
        .collect();

    let unique: HashSet<_> = values.iter().collect();
    assert_eq!(
        unique.len(),
        5,
        "five different seeds should produce five distinct values"
    );
}

#[test]
fn factories_do_not_share_cache() {
    let seed = Seed::new([42u8; 32]);
    let fx1 = Factory::deterministic(seed);
    let fx2 = Factory::deterministic(seed);

    let v1: Arc<u64> =
        fx1.get_or_init("domain:iso", "label", b"spec", "good", |rng| rng.next_u64());
    let v2: Arc<u64> =
        fx2.get_or_init("domain:iso", "label", b"spec", "good", |rng| rng.next_u64());

    // Values are equal (same seed + same id) but Arc identity differs (separate caches).
    assert_eq!(*v1, *v2);
    assert!(
        !Arc::ptr_eq(&v1, &v2),
        "separate factories must have separate caches"
    );
}
