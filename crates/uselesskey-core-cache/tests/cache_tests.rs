use std::sync::Arc;
use std::thread;

use proptest::prelude::*;
use uselesskey_core_cache::ArtifactCache;
use uselesskey_core_id::{ArtifactId, DerivationVersion};

fn make_id(label: &str) -> ArtifactId {
    ArtifactId::new(
        "domain:test",
        label,
        b"spec",
        "good",
        DerivationVersion::V1,
    )
}

#[test]
fn concurrent_insert_if_absent_returns_first_value() {
    let cache = Arc::new(ArtifactCache::new());
    let id = make_id("shared");

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let cache = Arc::clone(&cache);
            let id = id.clone();
            thread::spawn(move || cache.insert_if_absent_typed(id, Arc::new(i as u64)))
        })
        .collect();

    let results: Vec<Arc<u64>> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All threads must observe the same winning Arc.
    let first = &results[0];
    for r in &results[1..] {
        assert!(Arc::ptr_eq(first, r));
    }
    assert_eq!(cache.len(), 1);
}

#[test]
fn concurrent_insert_different_keys() {
    let cache = Arc::new(ArtifactCache::new());

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let cache = Arc::clone(&cache);
            let id = make_id(&format!("key-{i}"));
            thread::spawn(move || {
                cache.insert_if_absent_typed(id, Arc::new(i as u64));
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(cache.len(), 10);
    for i in 0..10 {
        let id = make_id(&format!("key-{i}"));
        let val = cache.get_typed::<u64>(&id).expect("key should exist");
        assert_eq!(*val, i as u64);
    }
}

#[test]
fn get_typed_wrong_type_returns_none() {
    let cache = ArtifactCache::new();
    let string_id = make_id("string-val");
    let u64_id = make_id("u64-val");

    cache.insert_if_absent_typed(string_id, Arc::new(String::from("hello")));

    // Different key that was never inserted — should return None.
    assert!(cache.get_typed::<u64>(&u64_id).is_none());
}

#[test]
fn clear_empties_all_entries() {
    let cache = ArtifactCache::new();

    for i in 0..5 {
        let id = make_id(&format!("entry-{i}"));
        cache.insert_if_absent_typed(id, Arc::new(i as u32));
    }

    assert_eq!(cache.len(), 5);
    assert!(!cache.is_empty());

    cache.clear();

    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}

#[test]
fn insert_if_absent_preserves_original() {
    let cache = ArtifactCache::new();
    let id = make_id("sticky");

    let a = cache.insert_if_absent_typed(id.clone(), Arc::new(String::from("A")));
    let b = cache.insert_if_absent_typed(id.clone(), Arc::new(String::from("B")));

    assert!(Arc::ptr_eq(&a, &b));
    assert_eq!(*b, "A");

    let fetched = cache.get_typed::<String>(&id).unwrap();
    assert_eq!(*fetched, "A");
}

proptest! {
    #[test]
    fn proptest_many_insertions_no_panic(labels in prop::collection::vec("[a-z]{1,8}", 1..50)) {
        let cache = ArtifactCache::new();
        for label in &labels {
            let id = make_id(label);
            cache.insert_if_absent_typed(id.clone(), Arc::new(label.clone()));
            let val = cache.get_typed::<String>(&id).unwrap();
            prop_assert_eq!(&*val, label);
        }
        prop_assert!(cache.len() <= labels.len());
        prop_assert!(cache.len() > 0);
    }
}
