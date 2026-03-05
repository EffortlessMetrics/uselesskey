//! Comprehensive tests filling coverage gaps in uselesskey-core-cache.
//!
//! Covers: spec-fingerprint uniqueness, derivation-version uniqueness,
//! property-based invariants, re-insert after clear, multi-type storage,
//! insert type-mismatch panic, Arc refcount semantics, and stress tests.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Barrier};
use std::thread;

use proptest::prelude::*;
use uselesskey_core_cache::ArtifactCache;
use uselesskey_core_id::{ArtifactId, DerivationVersion};

// ── Helpers ────────────────────────────────────────────────────────────

fn make_id(domain: &'static str, label: &str, spec: &[u8], variant: &str) -> ArtifactId {
    ArtifactId::new(domain, label, spec, variant, DerivationVersion::V1)
}

fn make_id_v(label: &str, version: DerivationVersion) -> ArtifactId {
    ArtifactId::new("domain:test", label, b"spec", "good", version)
}

// ── Spec fingerprint uniqueness ────────────────────────────────────────

#[test]
fn different_spec_fingerprints_produce_different_entries() {
    let cache = ArtifactCache::new();
    let id_rs256 = make_id("domain:rsa", "issuer", b"RS256", "good");
    let id_rs384 = make_id("domain:rsa", "issuer", b"RS384", "good");

    cache.insert_if_absent_typed(id_rs256.clone(), Arc::new(256u32));
    cache.insert_if_absent_typed(id_rs384.clone(), Arc::new(384u32));

    assert_eq!(cache.len(), 2);
    assert_eq!(*cache.get_typed::<u32>(&id_rs256).unwrap(), 256);
    assert_eq!(*cache.get_typed::<u32>(&id_rs384).unwrap(), 384);
}

#[test]
fn same_spec_fingerprint_is_same_entry() {
    let cache = ArtifactCache::new();
    let id_a = make_id("domain:rsa", "issuer", b"RS256", "good");
    let id_b = make_id("domain:rsa", "issuer", b"RS256", "good");

    let first = cache.insert_if_absent_typed(id_a.clone(), Arc::new(1u32));
    let second = cache.insert_if_absent_typed(id_b, Arc::new(2u32));

    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(cache.len(), 1);
}

// ── DerivationVersion uniqueness ───────────────────────────────────────

#[test]
fn different_derivation_versions_produce_different_entries() {
    let cache = ArtifactCache::new();
    let id_v1 = make_id_v("key", DerivationVersion::V1);
    let id_v2 = make_id_v("key", DerivationVersion(2));

    cache.insert_if_absent_typed(id_v1.clone(), Arc::new(1u64));
    cache.insert_if_absent_typed(id_v2.clone(), Arc::new(2u64));

    assert_eq!(cache.len(), 2);
    assert_eq!(*cache.get_typed::<u64>(&id_v1).unwrap(), 1);
    assert_eq!(*cache.get_typed::<u64>(&id_v2).unwrap(), 2);
}

// ── Re-insert after clear ──────────────────────────────────────────────

#[test]
fn reinsert_after_clear_yields_new_value() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "key", b"spec", "good");

    cache.insert_if_absent_typed(id.clone(), Arc::new(10u32));
    assert_eq!(*cache.get_typed::<u32>(&id).unwrap(), 10);

    cache.clear();
    assert!(cache.get_typed::<u32>(&id).is_none());

    cache.insert_if_absent_typed(id.clone(), Arc::new(20u32));
    assert_eq!(*cache.get_typed::<u32>(&id).unwrap(), 20);
    assert_eq!(cache.len(), 1);
}

// ── Multiple types in the same cache ───────────────────────────────────

#[test]
fn cache_stores_different_types_under_different_keys() {
    let cache = ArtifactCache::new();
    let id_u32 = make_id("domain:test", "u32-key", b"spec", "good");
    let id_str = make_id("domain:test", "str-key", b"spec", "good");
    let id_vec = make_id("domain:test", "vec-key", b"spec", "good");

    cache.insert_if_absent_typed(id_u32.clone(), Arc::new(42u32));
    cache.insert_if_absent_typed(id_str.clone(), Arc::new(String::from("hello")));
    cache.insert_if_absent_typed(id_vec.clone(), Arc::new(vec![1u8, 2, 3]));

    assert_eq!(cache.len(), 3);
    assert_eq!(*cache.get_typed::<u32>(&id_u32).unwrap(), 42);
    assert_eq!(*cache.get_typed::<String>(&id_str).unwrap(), "hello");
    assert_eq!(*cache.get_typed::<Vec<u8>>(&id_vec).unwrap(), vec![1, 2, 3]);
}

// ── Type mismatch on insert_if_absent_typed ────────────────────────────

#[test]
fn insert_if_absent_with_wrong_type_on_existing_key_panics() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "typed", b"spec", "good");

    cache.insert_if_absent_typed(id.clone(), Arc::new(42u32));

    let result = catch_unwind(AssertUnwindSafe(|| {
        cache.insert_if_absent_typed(id, Arc::new(String::from("wrong")));
    }));
    assert!(result.is_err(), "insert with mismatched type should panic");
}

// ── Arc refcount semantics ─────────────────────────────────────────────

#[test]
fn arc_strong_count_reflects_cache_holding_one_reference() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "refcount", b"spec", "good");
    let val = Arc::new(99u64);

    // Before insertion: only `val` holds a strong ref
    assert_eq!(Arc::strong_count(&val), 1);

    let returned = cache.insert_if_absent_typed(id.clone(), Arc::clone(&val));
    // Cache holds one, `val` holds one, `returned` holds one
    assert_eq!(Arc::strong_count(&val), 3);

    drop(returned);
    assert_eq!(Arc::strong_count(&val), 2); // val + cache

    // get_typed clones out another Arc
    let fetched = cache.get_typed::<u64>(&id).unwrap();
    assert_eq!(Arc::strong_count(&val), 3); // val + cache + fetched

    drop(fetched);
    assert_eq!(Arc::strong_count(&val), 2);
}

#[test]
fn clear_releases_cache_references() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "refcount-clear", b"spec", "good");
    let val = Arc::new(String::from("data"));

    cache.insert_if_absent_typed(id, Arc::clone(&val));
    assert_eq!(Arc::strong_count(&val), 2); // val + cache

    cache.clear();
    assert_eq!(Arc::strong_count(&val), 1); // only val remains
}

// ── All five ArtifactId fields affect cache identity ───────────────────

#[test]
fn all_artifact_id_fields_affect_identity() {
    let cache = ArtifactCache::new();

    let base = ArtifactId::new("domain:a", "label", b"spec", "good", DerivationVersion::V1);
    let diff_domain = ArtifactId::new("domain:b", "label", b"spec", "good", DerivationVersion::V1);
    let diff_label = ArtifactId::new("domain:a", "other", b"spec", "good", DerivationVersion::V1);
    let diff_spec = ArtifactId::new("domain:a", "label", b"alt", "good", DerivationVersion::V1);
    let diff_variant = ArtifactId::new(
        "domain:a",
        "label",
        b"spec",
        "corrupt:v1",
        DerivationVersion::V1,
    );
    let diff_version = ArtifactId::new("domain:a", "label", b"spec", "good", DerivationVersion(2));

    let ids = [
        base,
        diff_domain,
        diff_label,
        diff_spec,
        diff_variant,
        diff_version,
    ];

    for (i, id) in ids.iter().enumerate() {
        cache.insert_if_absent_typed(id.clone(), Arc::new(i as u32));
    }

    assert_eq!(
        cache.len(),
        6,
        "all five fields should produce distinct keys"
    );

    for (i, id) in ids.iter().enumerate() {
        assert_eq!(
            *cache.get_typed::<u32>(id).unwrap(),
            i as u32,
            "field variation {i} should map to its own entry"
        );
    }
}

// ── Concurrent stress: mixed operations ────────────────────────────────

#[test]
fn stress_concurrent_insert_clear_get() {
    let cache = Arc::new(ArtifactCache::new());
    let barrier = Arc::new(Barrier::new(24));

    let handles: Vec<_> = (0..24)
        .map(|t| {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for i in 0..50 {
                    let id = ArtifactId::new(
                        "domain:stress",
                        format!("k-{}", i % 10),
                        b"spec",
                        "good",
                        DerivationVersion::V1,
                    );
                    match t % 3 {
                        0 => {
                            cache.insert_if_absent_typed(id, Arc::new(i as u64));
                        }
                        1 => {
                            let _ = cache.get_typed::<u64>(&id);
                        }
                        _ => {
                            cache.clear();
                        }
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("no thread should panic");
    }
}

// ── Property-based tests ───────────────────────────────────────────────

proptest! {
    #[test]
    fn prop_insert_then_get_returns_inserted_value(val in any::<u64>()) {
        let cache = ArtifactCache::new();
        let id = ArtifactId::new("domain:prop", "key", b"spec", "good", DerivationVersion::V1);

        cache.insert_if_absent_typed(id.clone(), Arc::new(val));
        let got = cache.get_typed::<u64>(&id).unwrap();
        prop_assert_eq!(*got, val);
    }

    #[test]
    fn prop_first_insert_always_wins(a in any::<u64>(), b in any::<u64>()) {
        let cache = ArtifactCache::new();
        let id = ArtifactId::new("domain:prop", "race", b"spec", "good", DerivationVersion::V1);

        let first = cache.insert_if_absent_typed(id.clone(), Arc::new(a));
        let second = cache.insert_if_absent_typed(id, Arc::new(b));
        prop_assert_eq!(*first, a);
        prop_assert_eq!(*second, a);
        prop_assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn prop_distinct_labels_never_collide(label_a in "[a-z]{1,8}", label_b in "[a-z]{1,8}") {
        prop_assume!(label_a != label_b);

        let cache = ArtifactCache::new();
        let id_a = ArtifactId::new("domain:prop", &label_a, b"spec", "good", DerivationVersion::V1);
        let id_b = ArtifactId::new("domain:prop", &label_b, b"spec", "good", DerivationVersion::V1);

        cache.insert_if_absent_typed(id_a.clone(), Arc::new(1u32));
        cache.insert_if_absent_typed(id_b.clone(), Arc::new(2u32));

        prop_assert_eq!(cache.len(), 2);
        prop_assert_eq!(*cache.get_typed::<u32>(&id_a).unwrap(), 1);
        prop_assert_eq!(*cache.get_typed::<u32>(&id_b).unwrap(), 2);
    }

    #[test]
    fn prop_clear_always_empties(n in 1usize..50) {
        let cache = ArtifactCache::new();
        for i in 0..n {
            let id = ArtifactId::new("domain:prop", format!("k{i}"), b"spec", "good", DerivationVersion::V1);
            cache.insert_if_absent_typed(id, Arc::new(i as u64));
        }
        prop_assert_eq!(cache.len(), n);

        cache.clear();
        prop_assert!(cache.is_empty());
        prop_assert_eq!(cache.len(), 0);
    }

    #[test]
    fn prop_len_equals_distinct_insertions(n in 1usize..100) {
        let cache = ArtifactCache::new();
        for i in 0..n {
            let id = ArtifactId::new("domain:prop", format!("entry-{i}"), b"spec", "good", DerivationVersion::V1);
            cache.insert_if_absent_typed(id, Arc::new(i as u64));
        }
        prop_assert_eq!(cache.len(), n);
    }
}

// ── Zero-sized type storage ────────────────────────────────────────────

#[test]
fn cache_stores_and_retrieves_unit_type() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "zst", b"spec", "good");

    cache.insert_if_absent_typed(id.clone(), Arc::new(()));
    let got = cache.get_typed::<()>(&id);
    assert!(got.is_some());
}

// ── Repeated clear is idempotent ───────────────────────────────────────

#[test]
fn double_clear_is_safe() {
    let cache = ArtifactCache::new();
    let id = make_id("domain:test", "key", b"spec", "good");
    cache.insert_if_absent_typed(id, Arc::new(42u32));

    cache.clear();
    cache.clear();
    assert!(cache.is_empty());
}
