//! Comprehensive tests for `ArtifactCache` covering CRUD, type safety,
//! concurrency, and property-based scenarios.

use std::collections::HashSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::thread;

use proptest::prelude::*;

use uselesskey_core_cache::ArtifactCache;
use uselesskey_core_id::{ArtifactId, DerivationVersion};

fn make_id(domain: &'static str, label: &str, variant: &str) -> ArtifactId {
    ArtifactId::new(domain, label, b"spec", variant, DerivationVersion::V1)
}

// ===========================================================================
// 1. Basic CRUD tests
// ===========================================================================

#[test]
fn new_cache_is_empty() {
    let cache = ArtifactCache::new();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}

#[test]
fn insert_and_get_typed() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:crud", "insert-get", "good");

    let inserted = cache.insert_if_absent_typed(id.clone(), Arc::new(42u32));
    assert_eq!(*inserted, 42);

    let fetched = cache.get_typed::<u32>(&id).expect("value should exist");
    assert_eq!(*fetched, 42);
    assert!(Arc::ptr_eq(&inserted, &fetched));
}

#[test]
fn get_missing_returns_none() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:crud", "nonexistent", "good");

    assert!(cache.get_typed::<u32>(&id).is_none());
}

#[test]
fn insert_if_absent_deduplicates() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:crud", "dedup", "good");

    let first = cache.insert_if_absent_typed(id.clone(), Arc::new(100u64));
    let second = cache.insert_if_absent_typed(id.clone(), Arc::new(200u64));

    // The first value wins; second insert is ignored.
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(*second, 100);
    assert_eq!(cache.len(), 1);
}

#[test]
fn clear_removes_all() {
    let cache = ArtifactCache::new();

    for i in 0..10 {
        let id = make_id("domain:crud", &format!("clear-{i}"), "good");
        cache.insert_if_absent_typed(id, Arc::new(i as u32));
    }
    assert_eq!(cache.len(), 10);

    cache.clear();

    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);

    // Confirm previously inserted keys are gone.
    let id = make_id("domain:crud", "clear-0", "good");
    assert!(cache.get_typed::<u32>(&id).is_none());
}

#[test]
fn len_tracks_entries() {
    let cache = ArtifactCache::new();
    assert_eq!(cache.len(), 0);

    let id1 = make_id("domain:crud", "len-a", "good");
    let id2 = make_id("domain:crud", "len-b", "good");
    let id3 = make_id("domain:crud", "len-c", "good");

    cache.insert_if_absent_typed(id1.clone(), Arc::new(1u32));
    assert_eq!(cache.len(), 1);

    cache.insert_if_absent_typed(id2, Arc::new(2u32));
    assert_eq!(cache.len(), 2);

    // Duplicate insert on id1 should NOT increase len.
    cache.insert_if_absent_typed(id1, Arc::new(99u32));
    assert_eq!(cache.len(), 2);

    cache.insert_if_absent_typed(id3, Arc::new(3u32));
    assert_eq!(cache.len(), 3);

    cache.clear();
    assert_eq!(cache.len(), 0);
}

// ===========================================================================
// 2. Type safety tests
// ===========================================================================

#[test]
fn wrong_type_panics() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:type", "wrong", "good");

    cache.insert_if_absent_typed(id.clone(), Arc::new(42u32));

    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = cache.get_typed::<String>(&id);
    }));
    assert!(result.is_err(), "expected panic on wrong type downcast");
}

#[test]
fn different_types_same_id() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:type", "same-id", "good");

    // Insert a u32 first.
    let first = cache.insert_if_absent_typed(id.clone(), Arc::new(42u32));
    assert_eq!(*first, 42);

    // Attempt to insert a String under the same id panics because
    // insert_if_absent_typed returns the existing value and tries to
    // downcast it to the new type (String), which fails.
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = cache.insert_if_absent_typed(id.clone(), Arc::new(String::from("hello")));
    }));
    assert!(
        result.is_err(),
        "inserting a different type on the same key should panic"
    );

    // Original value is still intact.
    let fetched = cache
        .get_typed::<u32>(&id)
        .expect("original should survive");
    assert_eq!(*fetched, 42);
}

// ===========================================================================
// 3. Concurrency tests
// ===========================================================================

#[test]
fn concurrent_inserts_are_safe() {
    let cache = Arc::new(ArtifactCache::new());
    let id = make_id("domain:conc", "race", "good");

    let handles: Vec<_> = (0..16)
        .map(|i| {
            let cache = Arc::clone(&cache);
            let id = id.clone();
            thread::spawn(move || cache.insert_if_absent_typed(id, Arc::new(i as u64)))
        })
        .collect();

    let values: Vec<u64> = handles.into_iter().map(|h| *h.join().unwrap()).collect();

    // All threads must observe the same winning value.
    let winner = values[0];
    assert!(
        values.iter().all(|v| *v == winner),
        "all threads should see the same cached value"
    );
    assert_eq!(cache.len(), 1);
}

#[test]
fn concurrent_reads_and_writes() {
    let cache = Arc::new(ArtifactCache::new());

    // Pre-populate some entries.
    for i in 0..8 {
        let id = make_id("domain:conc", &format!("rw-{i}"), "good");
        cache.insert_if_absent_typed(id, Arc::new(i as u32));
    }

    let mut handles: Vec<thread::JoinHandle<()>> = Vec::new();

    // Spawn readers for existing keys.
    for i in 0..8 {
        let cache = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            let id = make_id("domain:conc", &format!("rw-{i}"), "good");
            let val = cache.get_typed::<u32>(&id).expect("should exist");
            assert_eq!(*val, i as u32);
        }));
    }

    // Spawn writers for new keys.
    for i in 8..16 {
        let cache = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            let id = make_id("domain:conc", &format!("rw-{i}"), "good");
            cache.insert_if_absent_typed(id, Arc::new(i as u32));
        }));
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }

    assert_eq!(cache.len(), 16);
}

// ===========================================================================
// 4. Property tests (proptest)
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn insert_get_roundtrip(
        label in "[a-zA-Z0-9]{1,20}",
        value in any::<u64>(),
    ) {
        let cache = ArtifactCache::new();
        let id = make_id("domain:prop", &label, "good");

        let inserted = cache.insert_if_absent_typed(id.clone(), Arc::new(value));
        let fetched = cache.get_typed::<u64>(&id).expect("roundtrip should succeed");

        prop_assert_eq!(*inserted, value);
        prop_assert_eq!(*fetched, value);
        prop_assert!(Arc::ptr_eq(&inserted, &fetched));
    }

    #[test]
    fn cache_len_matches_unique_keys(
        labels in prop::collection::vec("[a-zA-Z0-9]{1,12}", 1..50),
    ) {
        let cache = ArtifactCache::new();
        let mut unique = HashSet::new();

        for (i, label) in labels.iter().enumerate() {
            let id = make_id("domain:prop", label, "good");
            cache.insert_if_absent_typed(id, Arc::new(i as u64));
            unique.insert(label.clone());
        }

        prop_assert_eq!(cache.len(), unique.len());
    }
}
