//! Performance and correctness tests for `ArtifactCache`.
//!
//! Focuses on cache-hit efficiency, scalability under load,
//! correct key differentiation across all identity tuple fields,
//! and concurrent access safety.

#![cfg(feature = "std")]

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use uselesskey_core_cache::ArtifactCache;
use uselesskey_core_id::{ArtifactId, DerivationVersion};

fn make_id(domain: &'static str, label: &str, spec: &[u8], variant: &str) -> ArtifactId {
    ArtifactId::new(domain, label, spec, variant, DerivationVersion::V1)
}

fn simple_id(label: &str) -> ArtifactId {
    make_id("domain:test", label, b"spec", "good")
}

// ── 1. Cache hits return the exact same Arc (pointer equality) ──────

#[test]
fn cache_hit_returns_identical_arc_pointer() {
    let cache = ArtifactCache::new();
    let id = simple_id("ptr-eq");

    let original = Arc::new(vec![1u8, 2, 3]);
    let inserted = cache.insert_if_absent_typed(id.clone(), Arc::clone(&original));

    // insert_if_absent returns the same Arc as the first insertion
    assert!(Arc::ptr_eq(&original, &inserted));

    // Subsequent insert with a *different* value still returns the original
    let duplicate = cache.insert_if_absent_typed(id.clone(), Arc::new(vec![9u8, 9, 9]));
    assert!(Arc::ptr_eq(&original, &duplicate));

    // get_typed also returns the same pointer
    let fetched = cache.get_typed::<Vec<u8>>(&id).unwrap();
    assert!(Arc::ptr_eq(&original, &fetched));

    // Repeated get_typed calls all return the same pointer
    for _ in 0..50 {
        let again = cache.get_typed::<Vec<u8>>(&id).unwrap();
        assert!(Arc::ptr_eq(&original, &again));
    }
}

// ── 2. Repeated access is near-zero cost after first generation ─────

#[test]
fn repeated_cache_hits_are_fast() {
    let cache = ArtifactCache::new();
    let id = simple_id("perf-hit");

    // Simulate "first generation" by inserting a heavyweight value
    let big_value = Arc::new(vec![0u8; 64 * 1024]); // 64 KiB
    cache.insert_if_absent_typed(id.clone(), big_value);

    // Now measure 100 consecutive cache hits
    let start = Instant::now();
    for _ in 0..100 {
        let val = cache.get_typed::<Vec<u8>>(&id).unwrap();
        assert_eq!(val.len(), 64 * 1024);
    }
    let elapsed = start.elapsed();

    // 100 lookups should complete well under 50ms on any reasonable hardware.
    // This threshold is deliberately generous to avoid flaky CI.
    assert!(
        elapsed.as_millis() < 50,
        "100 cache hits took {elapsed:?}, expected < 50ms"
    );
}

#[test]
fn insert_if_absent_skips_allocation_on_hit() {
    let cache = ArtifactCache::new();
    let id = simple_id("alloc-skip");

    let first = cache.insert_if_absent_typed(id.clone(), Arc::new(42u64));

    // Measure 100 redundant inserts (all should be no-ops)
    let start = Instant::now();
    for i in 0..100 {
        let winner = cache.insert_if_absent_typed(id.clone(), Arc::new(i as u64));
        assert_eq!(*winner, 42u64);
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 50,
        "100 redundant inserts took {elapsed:?}, expected < 50ms"
    );

    // Only one entry in the cache
    assert_eq!(cache.len(), 1);
    assert!(Arc::ptr_eq(&first, &cache.get_typed::<u64>(&id).unwrap()));
}

// ── 3. Many different labels (1000+) doesn't OOM or degrade ─────────

#[test]
fn cache_scales_to_many_entries_without_degradation() {
    let cache = ArtifactCache::new();
    let count = 2_000;

    // Insert 2000 entries
    let insert_start = Instant::now();
    for i in 0..count {
        let id = simple_id(&format!("scale-{i}"));
        cache.insert_if_absent_typed(id, Arc::new(i as u64));
    }
    let insert_elapsed = insert_start.elapsed();

    assert_eq!(cache.len(), count);

    // Read all 2000 back and verify correctness
    let read_start = Instant::now();
    for i in 0..count {
        let id = simple_id(&format!("scale-{i}"));
        let val = cache.get_typed::<u64>(&id).expect("entry must exist");
        assert_eq!(*val, i as u64);
    }
    let read_elapsed = read_start.elapsed();

    // Generous bounds: 2000 inserts and 2000 reads should each be < 2s
    assert!(
        insert_elapsed.as_secs() < 2,
        "2000 inserts took {insert_elapsed:?}"
    );
    assert!(
        read_elapsed.as_secs() < 2,
        "2000 reads took {read_elapsed:?}"
    );
}

#[test]
fn cache_with_1000_labels_all_retrievable() {
    let cache = ArtifactCache::new();

    for i in 0..1_000 {
        let id = simple_id(&format!("label-{i}"));
        cache.insert_if_absent_typed(id, Arc::new(format!("value-{i}")));
    }

    assert_eq!(cache.len(), 1_000);

    // Spot-check a selection of entries
    for i in [0, 1, 42, 100, 499, 500, 999] {
        let id = simple_id(&format!("label-{i}"));
        let val = cache.get_typed::<String>(&id).unwrap();
        assert_eq!(*val, format!("value-{i}"));
    }
}

// ── 4. clear_cache properly empties all entries ─────────────────────

#[test]
fn clear_empties_all_entries_and_allows_reuse() {
    let cache = ArtifactCache::new();

    // Populate with diverse entries
    for i in 0..100 {
        let id = simple_id(&format!("clear-{i}"));
        cache.insert_if_absent_typed(id, Arc::new(i as u64));
    }
    assert_eq!(cache.len(), 100);
    assert!(!cache.is_empty());

    // Clear
    cache.clear();
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());

    // Every key should now return None
    for i in 0..100 {
        let id = simple_id(&format!("clear-{i}"));
        assert!(
            cache.get_typed::<u64>(&id).is_none(),
            "key clear-{i} should be absent after clear"
        );
    }

    // Re-inserting after clear works and produces fresh entries
    let id = simple_id("clear-0");
    let new_val = cache.insert_if_absent_typed(id.clone(), Arc::new(999u64));
    assert_eq!(*new_val, 999);
    assert_eq!(cache.len(), 1);
}

#[test]
fn clear_then_reinsert_gives_new_arc() {
    let cache = ArtifactCache::new();
    let id = simple_id("clear-arc");

    let first = cache.insert_if_absent_typed(id.clone(), Arc::new(1u32));
    cache.clear();

    let second = cache.insert_if_absent_typed(id.clone(), Arc::new(2u32));

    // After clear, the new insertion produces a different Arc
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(*first, 1);
    assert_eq!(*second, 2);
}

// ── 5. Cache keys differentiated by (domain, label, spec, variant) ──

#[test]
fn keys_differ_by_domain() {
    let cache = ArtifactCache::new();
    let id_rsa = make_id("domain:rsa", "key", b"RS256", "good");
    let id_ec = make_id("domain:ecdsa", "key", b"RS256", "good");

    cache.insert_if_absent_typed(id_rsa.clone(), Arc::new(1u32));
    cache.insert_if_absent_typed(id_ec.clone(), Arc::new(2u32));

    assert_eq!(cache.len(), 2);
    assert_eq!(*cache.get_typed::<u32>(&id_rsa).unwrap(), 1);
    assert_eq!(*cache.get_typed::<u32>(&id_ec).unwrap(), 2);
}

#[test]
fn keys_differ_by_label() {
    let cache = ArtifactCache::new();
    let id_alice = make_id("domain:rsa", "alice", b"RS256", "good");
    let id_bob = make_id("domain:rsa", "bob", b"RS256", "good");

    cache.insert_if_absent_typed(id_alice.clone(), Arc::new(10u32));
    cache.insert_if_absent_typed(id_bob.clone(), Arc::new(20u32));

    assert_eq!(cache.len(), 2);
    assert_eq!(*cache.get_typed::<u32>(&id_alice).unwrap(), 10);
    assert_eq!(*cache.get_typed::<u32>(&id_bob).unwrap(), 20);
}

#[test]
fn keys_differ_by_spec() {
    let cache = ArtifactCache::new();
    let id_256 = make_id("domain:rsa", "issuer", b"RS256", "good");
    let id_384 = make_id("domain:rsa", "issuer", b"RS384", "good");

    cache.insert_if_absent_typed(id_256.clone(), Arc::new(100u32));
    cache.insert_if_absent_typed(id_384.clone(), Arc::new(200u32));

    assert_eq!(cache.len(), 2);
    assert_eq!(*cache.get_typed::<u32>(&id_256).unwrap(), 100);
    assert_eq!(*cache.get_typed::<u32>(&id_384).unwrap(), 200);
}

#[test]
fn keys_differ_by_variant() {
    let cache = ArtifactCache::new();
    let id_good = make_id("domain:rsa", "issuer", b"RS256", "good");
    let id_corrupt = make_id("domain:rsa", "issuer", b"RS256", "corrupt:v1");
    let id_mismatch = make_id("domain:rsa", "issuer", b"RS256", "mismatch");

    cache.insert_if_absent_typed(id_good.clone(), Arc::new(1u32));
    cache.insert_if_absent_typed(id_corrupt.clone(), Arc::new(2u32));
    cache.insert_if_absent_typed(id_mismatch.clone(), Arc::new(3u32));

    assert_eq!(cache.len(), 3);
    assert_eq!(*cache.get_typed::<u32>(&id_good).unwrap(), 1);
    assert_eq!(*cache.get_typed::<u32>(&id_corrupt).unwrap(), 2);
    assert_eq!(*cache.get_typed::<u32>(&id_mismatch).unwrap(), 3);
}

#[test]
fn keys_differ_by_derivation_version() {
    let cache = ArtifactCache::new();
    let id_v1 = ArtifactId::new(
        "domain:rsa",
        "issuer",
        b"RS256",
        "good",
        DerivationVersion::V1,
    );
    let id_v2 = ArtifactId::new(
        "domain:rsa",
        "issuer",
        b"RS256",
        "good",
        DerivationVersion(2),
    );

    cache.insert_if_absent_typed(id_v1.clone(), Arc::new(10u32));
    cache.insert_if_absent_typed(id_v2.clone(), Arc::new(20u32));

    assert_eq!(cache.len(), 2);
    assert_eq!(*cache.get_typed::<u32>(&id_v1).unwrap(), 10);
    assert_eq!(*cache.get_typed::<u32>(&id_v2).unwrap(), 20);
}

#[test]
fn identical_tuple_maps_to_same_entry() {
    let cache = ArtifactCache::new();

    // Two independently constructed IDs with the same tuple
    let id1 = make_id("domain:rsa", "issuer", b"RS256", "good");
    let id2 = make_id("domain:rsa", "issuer", b"RS256", "good");

    let first = cache.insert_if_absent_typed(id1, Arc::new(42u32));
    let second = cache.insert_if_absent_typed(id2, Arc::new(99u32));

    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(*second, 42);
    assert_eq!(cache.len(), 1);
}

#[test]
fn all_five_fields_contribute_to_key_identity() {
    let cache = ArtifactCache::new();

    // Base ID
    let base = ArtifactId::new(
        "domain:rsa",
        "issuer",
        b"RS256",
        "good",
        DerivationVersion::V1,
    );
    cache.insert_if_absent_typed(base.clone(), Arc::new(0u32));

    // Vary each field independently; each must produce a separate cache entry
    let vary_domain = ArtifactId::new(
        "domain:ec",
        "issuer",
        b"RS256",
        "good",
        DerivationVersion::V1,
    );
    let vary_label = ArtifactId::new(
        "domain:rsa",
        "other",
        b"RS256",
        "good",
        DerivationVersion::V1,
    );
    let vary_spec = ArtifactId::new(
        "domain:rsa",
        "issuer",
        b"ES256",
        "good",
        DerivationVersion::V1,
    );
    let vary_variant = ArtifactId::new(
        "domain:rsa",
        "issuer",
        b"RS256",
        "bad",
        DerivationVersion::V1,
    );
    let vary_version = ArtifactId::new(
        "domain:rsa",
        "issuer",
        b"RS256",
        "good",
        DerivationVersion(2),
    );

    for (i, id) in [
        vary_domain,
        vary_label,
        vary_spec,
        vary_variant,
        vary_version,
    ]
    .into_iter()
    .enumerate()
    {
        cache.insert_if_absent_typed(id, Arc::new((i as u32) + 1));
    }

    // base + 5 variations = 6 entries
    assert_eq!(cache.len(), 6);

    // Verify each has its own value
    assert_eq!(*cache.get_typed::<u32>(&base).unwrap(), 0);
}

// ── 6. Concurrent access from 8+ threads ────────────────────────────

#[test]
fn concurrent_writes_from_many_threads_all_succeed() {
    let cache = Arc::new(ArtifactCache::new());
    let num_threads = 16;
    let keys_per_thread = 50;
    let barrier = Arc::new(Barrier::new(num_threads));

    let handles: Vec<_> = (0..num_threads)
        .map(|t| {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for k in 0..keys_per_thread {
                    let id = simple_id(&format!("t{t}-k{k}"));
                    let val =
                        cache.insert_if_absent_typed(id.clone(), Arc::new((t * 100 + k) as u64));
                    assert_eq!(*val, (t * 100 + k) as u64);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }

    assert_eq!(cache.len(), num_threads * keys_per_thread);
}

#[test]
fn concurrent_mixed_reads_and_writes_no_panic() {
    let cache = Arc::new(ArtifactCache::new());
    let barrier = Arc::new(Barrier::new(12));

    // Pre-populate some shared keys
    for i in 0..20 {
        let id = simple_id(&format!("shared-{i}"));
        cache.insert_if_absent_typed(id, Arc::new(i as u64));
    }

    let handles: Vec<_> = (0..12)
        .map(|t| {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for round in 0..100 {
                    if t % 3 == 0 {
                        // Reader of shared keys
                        let id = simple_id(&format!("shared-{}", round % 20));
                        let val = cache.get_typed::<u64>(&id);
                        assert!(val.is_some());
                    } else if t % 3 == 1 {
                        // Writer of new keys
                        let id = simple_id(&format!("new-t{t}-r{round}"));
                        cache.insert_if_absent_typed(id, Arc::new(round as u64));
                    } else {
                        // Re-inserter of shared keys (tests insert_if_absent idempotency)
                        let id = simple_id(&format!("shared-{}", round % 20));
                        let val = cache.insert_if_absent_typed(id, Arc::new(999u64));
                        assert_eq!(*val, (round % 20) as u64);
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }

    // All shared keys still present
    for i in 0..20 {
        let id = simple_id(&format!("shared-{i}"));
        assert_eq!(*cache.get_typed::<u64>(&id).unwrap(), i as u64);
    }
}

#[test]
fn concurrent_insert_same_key_all_get_same_arc() {
    let cache = Arc::new(ArtifactCache::new());
    let id = simple_id("race-target");
    let barrier = Arc::new(Barrier::new(8));

    let handles: Vec<_> = (0..8)
        .map(|i| {
            let cache = Arc::clone(&cache);
            let id = id.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                cache.insert_if_absent_typed(id, Arc::new(i as u64))
            })
        })
        .collect();

    let results: Vec<Arc<u64>> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All threads must see the same Arc (pointer equality)
    for pair in results.windows(2) {
        assert!(Arc::ptr_eq(&pair[0], &pair[1]));
    }

    assert_eq!(cache.len(), 1);
}
