//! Integration tests for Factory concurrency and cloning behavior.

#![cfg(feature = "std")]

use std::sync::Arc;
use std::thread;

use uselesskey_core_factory::Factory;
use uselesskey_core_id::Seed;

fn seed_u64(seed: Seed) -> u64 {
    let mut buf = [0u8; 8];
    seed.fill_bytes(&mut buf);
    u64::from_le_bytes(buf)
}

// ── concurrent get_or_init from multiple threads ─────────────────────

#[test]
fn concurrent_get_or_init_returns_same_arc() {
    let fx = Arc::new(Factory::deterministic(Seed::new([42u8; 32])));
    let mut handles = Vec::new();

    for _ in 0..8 {
        let fx = Arc::clone(&fx);
        handles.push(thread::spawn(move || {
            fx.get_or_init("domain:conc", "shared", b"spec", "good", |_rng| 123u64)
        }));
    }

    let results: Vec<Arc<u64>> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All threads should get the same Arc (same pointer)
    for r in &results {
        assert_eq!(**r, 123u64);
        assert!(Arc::ptr_eq(r, &results[0]));
    }
}

#[test]
fn concurrent_different_keys_are_independent() {
    let fx = Arc::new(Factory::deterministic(Seed::new([7u8; 32])));
    let mut handles = Vec::new();

    for i in 0u32..8 {
        let fx = Arc::clone(&fx);
        handles.push(thread::spawn(move || {
            let label = format!("key-{i}");
            let val = fx.get_or_init("domain:conc", &label, b"spec", "good", |_rng| i);
            (label, *val)
        }));
    }

    for h in handles {
        let (label, val) = h.join().unwrap();
        let expected: u32 = label.strip_prefix("key-").unwrap().parse().unwrap();
        assert_eq!(val, expected);
    }
}

// ── clone shares cache ───────────────────────────────────────────────

#[test]
fn cloned_factory_shares_cache() {
    let fx = Factory::deterministic(Seed::new([5u8; 32]));
    let fx2 = fx.clone();

    let a = fx.get_or_init("domain:clone", "shared", b"spec", "good", |_rng| 999u32);
    let b = fx2.get_or_init("domain:clone", "shared", b"spec", "good", |_rng| 0u32);

    assert!(Arc::ptr_eq(&a, &b));
    assert_eq!(*b, 999u32);
}

#[test]
fn clear_cache_on_clone_affects_original() {
    let fx = Factory::deterministic(Seed::new([8u8; 32]));
    let fx2 = fx.clone();

    let _ = fx.get_or_init("domain:clone", "key", b"spec", "good", |_rng| 10u8);
    fx2.clear_cache();

    // After clearing through clone, original should reinitialize
    let reinit = fx.get_or_init("domain:clone", "key", b"spec", "good", |_rng| 20u8);
    // Value comes from re-init so may differ from first init
    // The key test: init was called again (not returning the old 10u8)
    assert_eq!(*reinit, 20u8);
}

// ── deterministic reproducibility ────────────────────────────────────

#[test]
fn same_seed_same_label_same_value() {
    let seed = Seed::new([99u8; 32]);
    let fx1 = Factory::deterministic(seed);
    let fx2 = Factory::deterministic(seed);

    let a = fx1.get_or_init("domain:det", "label", b"spec", "good", seed_u64);
    let b = fx2.get_or_init("domain:det", "label", b"spec", "good", seed_u64);

    assert_eq!(*a, *b);
}

#[test]
fn different_seeds_different_values() {
    let fx1 = Factory::deterministic(Seed::new([1u8; 32]));
    let fx2 = Factory::deterministic(Seed::new([2u8; 32]));

    let a = fx1.get_or_init("domain:det", "label", b"spec", "good", seed_u64);
    let b = fx2.get_or_init("domain:det", "label", b"spec", "good", seed_u64);

    assert_ne!(*a, *b);
}

// ── random mode ──────────────────────────────────────────────────────

#[test]
fn random_mode_caches_after_first_init() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let fx = Factory::random();
    let counter = AtomicUsize::new(0);

    let a = fx.get_or_init("domain:rand", "once", b"spec", "good", |_rng| {
        counter.fetch_add(1, Ordering::SeqCst);
        42u64
    });
    let b = fx.get_or_init("domain:rand", "once", b"spec", "good", |_rng| {
        counter.fetch_add(1, Ordering::SeqCst);
        99u64
    });

    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert!(Arc::ptr_eq(&a, &b));
}

// ── Debug format ─────────────────────────────────────────────────────

#[test]
fn debug_format_includes_mode_and_cache_size() {
    let fx = Factory::deterministic(Seed::new([0u8; 32]));
    let dbg = format!("{fx:?}");
    assert!(dbg.contains("Factory"));
    assert!(dbg.contains("Deterministic"));
    assert!(dbg.contains("cache_size: 0"));

    let _ = fx.get_or_init("domain:dbg", "k", b"s", "v", |_rng| 1u8);
    let dbg = format!("{fx:?}");
    assert!(dbg.contains("cache_size: 1"));
}
