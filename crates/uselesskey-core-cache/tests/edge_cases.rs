//! Edge-case and boundary tests for ArtifactCache.

#![cfg(feature = "std")]

use std::sync::Arc;
use std::thread;

use uselesskey_core_cache::ArtifactCache;
use uselesskey_core_id::{ArtifactId, DerivationVersion};

fn make_id(label: &str) -> ArtifactId {
    ArtifactId::new(
        "domain:test",
        label,
        b"spec",
        "default",
        DerivationVersion::V1,
    )
}

// ── Concurrent insert_if_absent_typed ───────────────────────────────

#[test]
fn concurrent_insert_if_absent_all_see_same_value() {
    let cache = Arc::new(ArtifactCache::new());
    let id = make_id("shared");

    let handles: Vec<_> = (0..32)
        .map(|i| {
            let cache = Arc::clone(&cache);
            let id = id.clone();
            thread::spawn(move || {
                let val = Arc::new(i as u64);
                let result = cache.insert_if_absent_typed::<u64>(id, val);
                *result
            })
        })
        .collect();

    let results: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    // All threads must see the same "winner" value
    assert!(results.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn concurrent_reads_and_writes_no_panic() {
    let cache = Arc::new(ArtifactCache::new());

    // Pre-populate
    for i in 0..100 {
        let id = make_id(&format!("key-{i}"));
        cache.insert_if_absent_typed::<u64>(id, Arc::new(i as u64));
    }

    let handles: Vec<_> = (0..16)
        .map(|t| {
            let cache = Arc::clone(&cache);
            thread::spawn(move || {
                for i in 0..100 {
                    let id = make_id(&format!("key-{i}"));
                    if t % 2 == 0 {
                        // Reader
                        let val = cache.get_typed::<u64>(&id);
                        assert!(val.is_some());
                    } else {
                        // Writer (should return existing)
                        let val = cache.insert_if_absent_typed::<u64>(id, Arc::new(999));
                        assert_eq!(*val, i as u64); // first value wins
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

// ── Empty cache operations ──────────────────────────────────────────

#[test]
fn get_from_empty_cache_returns_none() {
    let cache = ArtifactCache::new();
    let id = make_id("nonexistent");
    assert!(cache.get_typed::<u64>(&id).is_none());
}

#[test]
fn empty_cache_len_is_zero() {
    let cache = ArtifactCache::new();
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}

// ── Many entries ────────────────────────────────────────────────────

#[test]
fn cache_handles_many_entries() {
    let cache = ArtifactCache::new();
    for i in 0..1000 {
        let id = make_id(&format!("entry-{i}"));
        cache.insert_if_absent_typed::<u64>(id, Arc::new(i));
    }
    assert_eq!(cache.len(), 1000);

    // Verify retrieval
    for i in 0..1000 {
        let id = make_id(&format!("entry-{i}"));
        let val = cache.get_typed::<u64>(&id).unwrap();
        assert_eq!(*val, i);
    }
}

// ── Clear with concurrent readers ───────────────────────────────────

#[test]
fn clear_while_reading_does_not_panic() {
    let cache = Arc::new(ArtifactCache::new());
    for i in 0..50 {
        let id = make_id(&format!("item-{i}"));
        cache.insert_if_absent_typed::<u64>(id, Arc::new(i as u64));
    }

    let handles: Vec<_> = (0..8)
        .map(|t| {
            let cache = Arc::clone(&cache);
            thread::spawn(move || {
                for _ in 0..100 {
                    if t == 0 {
                        cache.clear();
                    } else {
                        let id = make_id(&format!("item-{}", t % 50));
                        let _ = cache.get_typed::<u64>(&id); // may be None after clear
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

// ── Unicode and special keys ────────────────────────────────────────

#[test]
fn cache_with_unicode_label() {
    let cache = ArtifactCache::new();
    let id = make_id("日本語🔑");
    cache.insert_if_absent_typed::<String>(id.clone(), Arc::new("value".to_string()));
    let val = cache.get_typed::<String>(&id).unwrap();
    assert_eq!(&*val, "value");
}

#[test]
fn cache_with_empty_label() {
    let cache = ArtifactCache::new();
    let id = make_id("");
    cache.insert_if_absent_typed::<u64>(id.clone(), Arc::new(42));
    assert_eq!(*cache.get_typed::<u64>(&id).unwrap(), 42);
}

// ── Debug format ────────────────────────────────────────────────────

#[test]
fn debug_shows_type_and_count() {
    let cache = ArtifactCache::new();
    let dbg = format!("{cache:?}");
    assert!(dbg.contains("ArtifactCache"));
    assert!(dbg.contains("0"), "should show count of zero");
}

#[test]
fn debug_after_inserts_shows_count() {
    let cache = ArtifactCache::new();
    cache.insert_if_absent_typed::<u64>(make_id("a"), Arc::new(1));
    cache.insert_if_absent_typed::<u64>(make_id("b"), Arc::new(2));
    let dbg = format!("{cache:?}");
    assert!(dbg.contains("2"), "should show count of 2");
}
