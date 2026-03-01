use std::sync::Arc;
use std::thread;

use rstest::rstest;
use uselesskey_core_cache::ArtifactCache;
use uselesskey_core_id::{ArtifactId, DerivationVersion};

fn make_id(domain: &'static str, label: &str, variant: &str) -> ArtifactId {
    ArtifactId::new(domain, label, b"spec", variant, DerivationVersion::V1)
}

// ── insert and retrieve ──────────────────────────────────────────────

#[test]
fn insert_and_retrieve_u32() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "key", "good");

    cache.insert_if_absent_typed(id.clone(), Arc::new(42u32));
    let got = cache.get_typed::<u32>(&id).expect("should exist");
    assert_eq!(*got, 42u32);
}

#[test]
fn insert_and_retrieve_string() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "key", "good");

    cache.insert_if_absent_typed(id.clone(), Arc::new(String::from("hello")));
    let got = cache.get_typed::<String>(&id).expect("should exist");
    assert_eq!(*got, "hello");
}

#[test]
fn get_typed_returns_none_for_absent_key() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "missing", "good");
    assert!(cache.get_typed::<u32>(&id).is_none());
}

// ── cache hits return same Arc ───────────────────────────────────────

#[test]
fn cache_hit_returns_same_arc() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "key", "good");

    let first = cache.insert_if_absent_typed(id.clone(), Arc::new(99u64));
    let second = cache.insert_if_absent_typed(id.clone(), Arc::new(100u64));
    let fetched = cache.get_typed::<u64>(&id).unwrap();

    assert!(Arc::ptr_eq(&first, &second));
    assert!(Arc::ptr_eq(&first, &fetched));
    assert_eq!(*fetched, 99u64);
}

// ── different keys produce different entries ──────────────────────────

#[rstest]
#[case("label-a", "label-b")]
#[case("x", "y")]
fn different_labels_produce_different_entries(#[case] label_a: &str, #[case] label_b: &str) {
    let cache = ArtifactCache::new();
    let id_a = make_id("domain:test", label_a, "good");
    let id_b = make_id("domain:test", label_b, "good");

    cache.insert_if_absent_typed(id_a.clone(), Arc::new(1u32));
    cache.insert_if_absent_typed(id_b.clone(), Arc::new(2u32));

    assert_eq!(*cache.get_typed::<u32>(&id_a).unwrap(), 1);
    assert_eq!(*cache.get_typed::<u32>(&id_b).unwrap(), 2);
    assert_eq!(cache.len(), 2);
}

#[test]
fn different_variants_produce_different_entries() {
    let cache = ArtifactCache::new();
    let id_good = make_id("domain:test", "key", "good");
    let id_bad = make_id("domain:test", "key", "corrupt:v1");

    cache.insert_if_absent_typed(id_good.clone(), Arc::new(10u32));
    cache.insert_if_absent_typed(id_bad.clone(), Arc::new(20u32));

    assert_eq!(*cache.get_typed::<u32>(&id_good).unwrap(), 10);
    assert_eq!(*cache.get_typed::<u32>(&id_bad).unwrap(), 20);
}

#[test]
fn different_domains_produce_different_entries() {
    let cache = ArtifactCache::new();
    let id_rsa = make_id("domain:rsa", "key", "good");
    let id_ec = make_id("domain:ecdsa", "key", "good");

    cache.insert_if_absent_typed(id_rsa.clone(), Arc::new(100u32));
    cache.insert_if_absent_typed(id_ec.clone(), Arc::new(200u32));

    assert_eq!(*cache.get_typed::<u32>(&id_rsa).unwrap(), 100);
    assert_eq!(*cache.get_typed::<u32>(&id_ec).unwrap(), 200);
}

// ── type safety (correct downcasting) ────────────────────────────────

#[test]
#[should_panic(expected = "artifact type mismatch")]
fn get_typed_wrong_type_panics() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "key", "good");

    cache.insert_if_absent_typed(id.clone(), Arc::new(42u32));
    let _ = cache.get_typed::<String>(&id);
}

// ── concurrent access (basic thread safety) ──────────────────────────

#[test]
fn concurrent_inserts_are_safe() {
    let cache = Arc::new(ArtifactCache::new());
    let mut handles = Vec::new();

    for i in 0..8 {
        let cache = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            let id = make_id("domain:test", &format!("thread-{i}"), "good");
            cache.insert_if_absent_typed(id.clone(), Arc::new(i as u32));
            let got = cache.get_typed::<u32>(&id).unwrap();
            assert_eq!(*got, i as u32);
        }));
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }

    assert_eq!(cache.len(), 8);
}

#[test]
fn concurrent_reads_on_same_key() {
    let cache = Arc::new(ArtifactCache::new());
    let id = make_id("domain:test", "shared", "good");
    cache.insert_if_absent_typed(id.clone(), Arc::new(777u64));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let cache = Arc::clone(&cache);
        let id = id.clone();
        handles.push(thread::spawn(move || {
            let val = cache.get_typed::<u64>(&id).unwrap();
            assert_eq!(*val, 777u64);
        }));
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }
}

// ── len / is_empty / clear ───────────────────────────────────────────

#[test]
fn new_cache_is_empty() {
    let cache = ArtifactCache::new();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}

#[test]
fn clear_removes_all_entries() {
    let cache = ArtifactCache::new();
    for i in 0..5 {
        let id = make_id("domain:test", &format!("k{i}"), "good");
        cache.insert_if_absent_typed(id, Arc::new(i));
    }
    assert_eq!(cache.len(), 5);

    cache.clear();
    assert!(cache.is_empty());
}

// ── Debug impl ───────────────────────────────────────────────────────

#[test]
fn debug_does_not_leak_values() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "secret-key", "good");
    cache.insert_if_absent_typed(id, Arc::new(String::from("SUPER_SECRET")));

    let dbg = format!("{cache:?}");
    assert!(dbg.contains("ArtifactCache"));
    assert!(!dbg.contains("SUPER_SECRET"));
}

// ── Default impl ─────────────────────────────────────────────────────

#[test]
fn default_creates_empty_cache() {
    let cache = ArtifactCache::default();
    assert!(cache.is_empty());
}
