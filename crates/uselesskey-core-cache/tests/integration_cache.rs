use std::sync::Arc;

use uselesskey_core_cache::ArtifactCache;
use uselesskey_core_id::{ArtifactId, DerivationVersion};

fn make_id(label: &str) -> ArtifactId {
    ArtifactId::new("domain:test", label, b"spec", "good", DerivationVersion::V1)
}

#[test]
fn basic_insert_and_retrieve() {
    let cache = ArtifactCache::new();
    let id = make_id("basic");

    let inserted = cache.insert_if_absent_typed(id.clone(), Arc::new(42u64));
    let retrieved = cache.get_typed::<u64>(&id).expect("should exist");

    assert_eq!(*inserted, 42);
    assert_eq!(*retrieved, 42);
    assert_eq!(cache.len(), 1);
}

#[test]
#[should_panic(expected = "type mismatch")]
fn type_safety_wrong_downcast_panics() {
    let cache = ArtifactCache::new();
    let id = make_id("typed");

    cache.insert_if_absent_typed(id.clone(), Arc::new(99u64));
    // Attempt to retrieve as String should panic
    let _ = cache.get_typed::<String>(&id);
}

#[test]
fn empty_cache_returns_none() {
    let cache = ArtifactCache::new();
    let id = make_id("missing");

    assert!(cache.get_typed::<u64>(&id).is_none());
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}

#[test]
fn cache_preserves_arc_identity() {
    let cache = ArtifactCache::new();
    let id = make_id("arc-id");
    let original = Arc::new(String::from("hello"));

    let returned = cache.insert_if_absent_typed(id.clone(), Arc::clone(&original));
    let fetched = cache.get_typed::<String>(&id).unwrap();

    assert!(Arc::ptr_eq(&original, &returned));
    assert!(Arc::ptr_eq(&original, &fetched));
}

#[test]
fn cache_works_with_many_entries() {
    let cache = ArtifactCache::new();

    for i in 0..1_000 {
        let id = make_id(&format!("entry-{i}"));
        cache.insert_if_absent_typed(id, Arc::new(i as u64));
    }

    assert_eq!(cache.len(), 1_000);

    // Spot-check some entries
    for i in [0, 42, 500, 999] {
        let id = make_id(&format!("entry-{i}"));
        let val = cache.get_typed::<u64>(&id).expect("should exist");
        assert_eq!(*val, i as u64);
    }
}

#[test]
fn cache_with_complex_value_types() {
    #[derive(Debug, PartialEq)]
    struct KeyPair {
        public: Vec<u8>,
        private: Vec<u8>,
        algorithm: String,
    }

    let cache = ArtifactCache::new();
    let id = make_id("complex");

    let kp = KeyPair {
        public: vec![1, 2, 3],
        private: vec![4, 5, 6],
        algorithm: "RS256".into(),
    };

    let inserted = cache.insert_if_absent_typed(id.clone(), Arc::new(kp));
    let retrieved = cache.get_typed::<KeyPair>(&id).unwrap();

    assert!(Arc::ptr_eq(&inserted, &retrieved));
    assert_eq!(retrieved.algorithm, "RS256");
    assert_eq!(retrieved.public, vec![1, 2, 3]);
}
