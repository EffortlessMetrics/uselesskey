use crate::factory::{Factory, downcast_or_panic, random_seed};
use crate::id::{ArtifactId, DerivationVersion, Seed};
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn clear_cache_forces_reinit() {
    let fx = Factory::random();
    let hits = AtomicUsize::new(0);

    let first = fx.get_or_init("domain:test", "label", b"spec", "good", |_rng| {
        hits.fetch_add(1, Ordering::SeqCst);
        42u8
    });

    assert_eq!(hits.load(Ordering::SeqCst), 1);
    let second = fx.get_or_init("domain:test", "label", b"spec", "good", |_rng| {
        hits.fetch_add(1, Ordering::SeqCst);
        99u8
    });
    assert!(Arc::ptr_eq(&first, &second));

    fx.clear_cache();
    let third = fx.get_or_init("domain:test", "label", b"spec", "good", |_rng| {
        hits.fetch_add(1, Ordering::SeqCst);
        44u8
    });

    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert!(!Arc::ptr_eq(&first, &third));
}

#[test]
fn get_or_init_type_mismatch_panics() {
    let fx = Factory::random();
    let _ = fx.get_or_init("domain:test", "label", b"spec", "good", |_rng| 123u32);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = fx.get_or_init("domain:test", "label", b"spec", "good", |_rng| {
            "oops".to_string()
        });
    }));

    assert!(result.is_err(), "expected panic on type mismatch");
}

#[test]
fn downcast_or_panic_type_mismatch_panics() {
    let id = ArtifactId::new(
        "domain:test",
        "label".to_string(),
        b"spec",
        "good".to_string(),
        DerivationVersion::V1,
    );
    let arc_any: Arc<dyn Any + Send + Sync> = Arc::new(123u32);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = downcast_or_panic::<String>(arc_any.clone(), &id);
    }));

    assert!(result.is_err(), "expected panic on type mismatch");
}

#[test]
fn downcast_or_panic_ok_returns_value() {
    let id = ArtifactId::new(
        "domain:test",
        "label".to_string(),
        b"spec",
        "good".to_string(),
        DerivationVersion::V1,
    );
    let arc_any: Arc<dyn Any + Send + Sync> = Arc::new(123u32);
    let arc = downcast_or_panic::<u32>(arc_any, &id);
    assert_eq!(*arc, 123u32);
}

#[test]
fn random_seed_has_expected_length() {
    let seed = random_seed();
    assert_eq!(seed.bytes().len(), 32);
}

#[test]
fn get_or_init_reentrant_does_not_deadlock() {
    let fx = Factory::deterministic(Seed::new([42u8; 32]));

    // Outer init closure calls get_or_init again (re-entrant).
    // This mirrors X.509 cert generation calling factory.rsa().
    // Would deadlock if the init closure ran while holding the shard lock.
    let outer: Arc<String> = fx.get_or_init("test:outer", "label", b"spec", "good", |_rng| {
        let inner: Arc<u64> = fx.get_or_init("test:inner", "label", b"spec", "good", |_rng| 42u64);
        format!("outer-{}", *inner)
    });

    assert_eq!(*outer, "outer-42");
}

#[test]
fn debug_includes_cache_size() {
    let fx = Factory::random();
    let _ = fx.get_or_init("domain:test", "label", b"spec", "good", |_rng| 7u8);

    let dbg = format!("{:?}", fx);
    assert!(dbg.contains("cache_size"), "debug output was: {dbg}");
}
