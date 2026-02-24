#![cfg(feature = "std")]

use std::sync::atomic::{AtomicUsize, Ordering};

use std::sync::Arc;

use uselesskey_core_factory::Factory;
use uselesskey_core_id::Seed;

#[test]
fn clear_cache_reinitializes_deterministic_entries() {
    let fx = Factory::deterministic(Seed::new([3u8; 32]));

    let first = fx.get_or_init("domain:integration", "label", b"spec", "good", |_rng| 123u8);
    let second = fx.get_or_init("domain:integration", "label", b"spec", "good", |_rng| 99u8);

    assert!(Arc::ptr_eq(&first, &second));

    fx.clear_cache();
    let third = fx.get_or_init("domain:integration", "label", b"spec", "good", |_rng| 45u8);

    assert!(!Arc::ptr_eq(&first, &third));
}

#[test]
fn random_seed_factory_reuses_cached_value() {
    let fx = Factory::random();
    let a = fx.get_or_init("domain:integration", "label", b"spec", "good", |_rng| 7u8);
    let b = fx.get_or_init("domain:integration", "label", b"spec", "good", |_rng| 11u8);

    assert!(Arc::ptr_eq(&a, &b));
}

#[test]
fn deterministic_reentrant_get_or_init_is_supported() {
    let fx = Factory::deterministic(Seed::new([7u8; 32]));

    let value: Arc<String> = fx.get_or_init("domain:integration", "outer", b"spec", "good", |_rng| {
        let inner = fx.get_or_init("domain:integration", "inner", b"spec", "good", |_rng| 12u8);
        format!("outer-{}", *inner)
    });

    assert_eq!(value.as_str(), "outer-12");
}

#[test]
fn clear_cache_changes_arc_identity() {
    let fx = Factory::deterministic(Seed::new([9u8; 32]));

    let first: Arc<u64> = fx.get_or_init("domain:integration", "identity", b"spec", "v", |_rng| {
        1234u64
    });

    fx.clear_cache();

    let second: Arc<u64> = fx.get_or_init("domain:integration", "identity", b"spec", "v", |_rng| {
        1234u64
    });

    assert_eq!(*first, *second);
    assert!(!Arc::ptr_eq(&first, &second));
}

#[test]
fn get_or_init_type_switch_panics_when_type_differs() {
    let fx = Factory::random();
    let _ = fx.get_or_init("domain:integration", "type", b"spec", "v", |_rng| 1u32);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = fx.get_or_init("domain:integration", "type", b"spec", "v", |_rng| "not-a-u32");
    }));

    assert!(result.is_err());
}

#[test]
fn get_or_init_mutates_hit_counter() {
    let fx = Factory::random();
    let hits = AtomicUsize::new(0);

    let _ = fx.get_or_init("domain:integration", "counter", b"spec", "v", |_rng| {
        hits.fetch_add(1, Ordering::SeqCst);
        7u8
    });
    let _ = fx.get_or_init("domain:integration", "counter", b"spec", "v", |_rng| {
        hits.fetch_add(1, Ordering::SeqCst);
        7u8
    });

    assert_eq!(hits.load(Ordering::SeqCst), 1);
}
