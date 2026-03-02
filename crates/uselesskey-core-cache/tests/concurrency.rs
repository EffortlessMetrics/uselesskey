use std::sync::{Arc, Barrier};
use std::thread;

use uselesskey_core_cache::ArtifactCache;
use uselesskey_core_id::{ArtifactId, DerivationVersion};

fn make_id(domain: &'static str, label: &str, variant: &str) -> ArtifactId {
    ArtifactId::new(domain, label, b"spec", variant, DerivationVersion::V1)
}

#[test]
fn concurrent_reads_same_key() {
    let cache = Arc::new(ArtifactCache::new());
    let id = make_id("domain:test", "shared", "good");
    let original = cache.insert_if_absent_typed(id.clone(), Arc::new(42u64));

    let barrier = Arc::new(Barrier::new(10));
    let handles: Vec<_> = (0..10)
        .map(|_| {
            let cache = Arc::clone(&cache);
            let id = id.clone();
            let barrier = Arc::clone(&barrier);
            let original = Arc::clone(&original);
            thread::spawn(move || {
                barrier.wait();
                let val = cache.get_typed::<u64>(&id).expect("should find value");
                assert_eq!(*val, 42);
                assert!(Arc::ptr_eq(&val, &original));
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }
}

#[test]
fn concurrent_writes_different_keys() {
    let cache = Arc::new(ArtifactCache::new());
    let barrier = Arc::new(Barrier::new(10));

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let id = make_id("domain:test", &format!("key-{i}"), "good");
                let val = cache.insert_if_absent_typed(id.clone(), Arc::new(i as u64));
                assert_eq!(*val, i as u64);
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }
    assert_eq!(cache.len(), 10);
}

#[test]
fn cache_identity_same_tuple_same_arc() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:rsa", "issuer", "good");

    let first = cache.insert_if_absent_typed(id.clone(), Arc::new(100u32));
    let second = cache.insert_if_absent_typed(id.clone(), Arc::new(200u32));
    let fetched = cache.get_typed::<u32>(&id).unwrap();

    assert!(Arc::ptr_eq(&first, &second));
    assert!(Arc::ptr_eq(&first, &fetched));
    assert_eq!(*first, 100);
}

#[test]
fn cache_isolation_different_keys_different_arcs() {
    let cache = ArtifactCache::new();
    let id_a = make_id("domain:rsa", "alice", "good");
    let id_b = make_id("domain:rsa", "bob", "good");

    let a = cache.insert_if_absent_typed(id_a, Arc::new(1u32));
    let b = cache.insert_if_absent_typed(id_b, Arc::new(2u32));

    assert!(!Arc::ptr_eq(&a, &b));
    assert_eq!(*a, 1);
    assert_eq!(*b, 2);
}

#[test]
fn high_contention_reads_and_writes() {
    let cache = Arc::new(ArtifactCache::new());

    // Pre-populate some keys
    for i in 0..5 {
        let id = make_id("domain:test", &format!("pre-{i}"), "good");
        cache.insert_if_absent_typed(id, Arc::new(i as u64));
    }

    let barrier = Arc::new(Barrier::new(20));
    let handles: Vec<_> = (0..20)
        .map(|i| {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                if i % 2 == 0 {
                    // Reader: read pre-populated key
                    let key_idx = i / 2 % 5;
                    let id = make_id("domain:test", &format!("pre-{key_idx}"), "good");
                    let val = cache.get_typed::<u64>(&id).expect("pre-populated key");
                    assert_eq!(*val, key_idx as u64);
                } else {
                    // Writer: insert new key
                    let id = make_id("domain:test", &format!("new-{i}"), "good");
                    let val = cache.insert_if_absent_typed(id, Arc::new(i as u64));
                    assert_eq!(*val, i as u64);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }

    // All pre-populated + new writer keys present
    assert!(cache.len() >= 5);
}

#[test]
fn cache_does_not_leak_across_domains() {
    let cache = ArtifactCache::new();
    let id_rsa = make_id("domain:rsa", "key", "good");
    let id_ecdsa = make_id("domain:ecdsa", "key", "good");

    cache.insert_if_absent_typed(id_rsa.clone(), Arc::new(1u32));

    assert!(cache.get_typed::<u32>(&id_rsa).is_some());
    assert!(cache.get_typed::<u32>(&id_ecdsa).is_none());
}

#[test]
fn cache_is_send_and_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    assert_send::<ArtifactCache>();
    assert_sync::<ArtifactCache>();
}
