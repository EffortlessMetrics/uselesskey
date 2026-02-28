use std::sync::Arc;
use std::thread;

use uselesskey_core_cache::ArtifactCache;
use uselesskey_core_id::{ArtifactId, DerivationVersion};

fn make_id(domain: &'static str, label: &str, variant: &str) -> ArtifactId {
    ArtifactId::new(domain, label, b"spec", variant, DerivationVersion::V1)
}

// ---------------------------------------------------------------------------
// 1. Basic insert and retrieve
// ---------------------------------------------------------------------------

#[test]
fn insert_and_get_typed_returns_value() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "key1", "default");

    let inserted = cache.insert_if_absent_typed(id.clone(), Arc::new(42u64));
    let fetched = cache.get_typed::<u64>(&id).expect("should exist");

    assert_eq!(*inserted, 42);
    assert_eq!(*fetched, 42);
}

#[test]
fn get_typed_returns_none_for_missing_key() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "missing", "default");

    assert!(cache.get_typed::<u32>(&id).is_none());
}

// ---------------------------------------------------------------------------
// 2. Cache hit — same key returns same Arc
// ---------------------------------------------------------------------------

#[test]
fn insert_if_absent_returns_first_value_on_duplicate() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "dup", "default");

    let first = cache.insert_if_absent_typed(id.clone(), Arc::new(String::from("first")));
    let second = cache.insert_if_absent_typed(id.clone(), Arc::new(String::from("second")));

    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(*second, "first");
}

#[test]
fn cache_hit_shares_arc_identity() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "shared", "default");

    cache.insert_if_absent_typed(id.clone(), Arc::new(99i32));

    let a = cache.get_typed::<i32>(&id).unwrap();
    let b = cache.get_typed::<i32>(&id).unwrap();
    assert!(Arc::ptr_eq(&a, &b));
}

// ---------------------------------------------------------------------------
// 3. Cache clearing
// ---------------------------------------------------------------------------

#[test]
fn clear_removes_all_entries() {
    let cache = ArtifactCache::new();

    for i in 0..5 {
        let id = make_id("domain:test", &format!("k{i}"), "default");
        cache.insert_if_absent_typed(id, Arc::new(i));
    }
    assert_eq!(cache.len(), 5);
    assert!(!cache.is_empty());

    cache.clear();

    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}

#[test]
fn get_returns_none_after_clear() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "cleared", "default");

    cache.insert_if_absent_typed(id.clone(), Arc::new(1u8));
    cache.clear();

    assert!(cache.get_typed::<u8>(&id).is_none());
}

#[test]
fn reinsert_after_clear_stores_new_value() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "reinsert", "default");

    cache.insert_if_absent_typed(id.clone(), Arc::new(1u32));
    cache.clear();

    let v = cache.insert_if_absent_typed(id.clone(), Arc::new(2u32));
    assert_eq!(*v, 2);
    assert_eq!(*cache.get_typed::<u32>(&id).unwrap(), 2);
}

// ---------------------------------------------------------------------------
// 4. Type safety — different types under different keys
// ---------------------------------------------------------------------------

#[test]
fn different_keys_hold_different_types() {
    let cache = ArtifactCache::new();

    let id_u32 = make_id("domain:u32", "a", "default");
    let id_str = make_id("domain:str", "b", "default");
    let id_vec = make_id("domain:vec", "c", "default");

    cache.insert_if_absent_typed(id_u32.clone(), Arc::new(10u32));
    cache.insert_if_absent_typed(id_str.clone(), Arc::new(String::from("hello")));
    cache.insert_if_absent_typed(id_vec.clone(), Arc::new(vec![1u8, 2, 3]));

    assert_eq!(*cache.get_typed::<u32>(&id_u32).unwrap(), 10);
    assert_eq!(*cache.get_typed::<String>(&id_str).unwrap(), "hello");
    assert_eq!(*cache.get_typed::<Vec<u8>>(&id_vec).unwrap(), vec![1, 2, 3]);
}

#[test]
#[should_panic(expected = "artifact type mismatch")]
fn type_mismatch_on_get_panics() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "mismatch", "default");

    cache.insert_if_absent_typed(id.clone(), Arc::new(42u32));
    let _ = cache.get_typed::<String>(&id);
}

// ---------------------------------------------------------------------------
// 5. Concurrent access
// ---------------------------------------------------------------------------

#[test]
fn concurrent_inserts_converge_to_single_value() {
    let cache = Arc::new(ArtifactCache::new());
    let id = make_id("domain:race", "shared", "default");

    let handles: Vec<_> = (0..8)
        .map(|i| {
            let cache = Arc::clone(&cache);
            let id = id.clone();
            thread::spawn(move || cache.insert_if_absent_typed(id, Arc::new(i as u64)))
        })
        .collect();

    let results: Vec<u64> = handles.into_iter().map(|h| *h.join().unwrap()).collect();

    // All threads must observe the same winning value.
    let first = results[0];
    assert!(results.iter().all(|v| *v == first));
    assert_eq!(cache.len(), 1);
}

#[test]
fn concurrent_reads_while_inserting() {
    let cache = Arc::new(ArtifactCache::new());
    let id = make_id("domain:rw", "concurrent", "default");

    cache.insert_if_absent_typed(id.clone(), Arc::new(77u32));

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let cache = Arc::clone(&cache);
            let id = id.clone();
            thread::spawn(move || *cache.get_typed::<u32>(&id).unwrap())
        })
        .collect();

    for h in handles {
        assert_eq!(h.join().unwrap(), 77);
    }
}

#[test]
fn concurrent_inserts_across_distinct_keys() {
    let cache = Arc::new(ArtifactCache::new());

    let handles: Vec<_> = (0..16)
        .map(|i| {
            let cache = Arc::clone(&cache);
            thread::spawn(move || {
                let id = make_id("domain:multi", &format!("key{i}"), "default");
                cache.insert_if_absent_typed(id, Arc::new(i as u32));
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(cache.len(), 16);
}

// ---------------------------------------------------------------------------
// 6. Edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_label_and_variant_work() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:edge", "", "");

    let v = cache.insert_if_absent_typed(id.clone(), Arc::new(1u8));
    assert_eq!(*v, 1);
    assert_eq!(*cache.get_typed::<u8>(&id).unwrap(), 1);
}

#[test]
fn large_value_stored_and_retrieved() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:large", "big", "default");

    let big = vec![0xAAu8; 1_000_000];
    cache.insert_if_absent_typed(id.clone(), Arc::new(big.clone()));

    let fetched = cache.get_typed::<Vec<u8>>(&id).unwrap();
    assert_eq!(fetched.len(), 1_000_000);
    assert_eq!(*fetched, big);
}

#[test]
fn new_cache_is_empty() {
    let cache = ArtifactCache::new();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}

#[test]
fn default_creates_empty_cache() {
    let cache = ArtifactCache::default();
    assert!(cache.is_empty());
}

#[test]
fn distinct_variants_are_separate_keys() {
    let cache = ArtifactCache::new();
    let id_a = make_id("domain:test", "same_label", "variant_a");
    let id_b = make_id("domain:test", "same_label", "variant_b");

    cache.insert_if_absent_typed(id_a.clone(), Arc::new(1u32));
    cache.insert_if_absent_typed(id_b.clone(), Arc::new(2u32));

    assert_eq!(*cache.get_typed::<u32>(&id_a).unwrap(), 1);
    assert_eq!(*cache.get_typed::<u32>(&id_b).unwrap(), 2);
    assert_eq!(cache.len(), 2);
}

#[test]
fn distinct_domains_are_separate_keys() {
    let cache = ArtifactCache::new();
    let id_a = make_id("domain:alpha", "label", "default");
    let id_b = make_id("domain:beta", "label", "default");

    cache.insert_if_absent_typed(id_a.clone(), Arc::new(10u32));
    cache.insert_if_absent_typed(id_b.clone(), Arc::new(20u32));

    assert_eq!(*cache.get_typed::<u32>(&id_a).unwrap(), 10);
    assert_eq!(*cache.get_typed::<u32>(&id_b).unwrap(), 20);
    assert_eq!(cache.len(), 2);
}
