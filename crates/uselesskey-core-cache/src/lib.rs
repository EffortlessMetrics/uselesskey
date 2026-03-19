//! Per-factory artifact cache keyed by [`ArtifactId`].
//!
//! Stores generated fixtures behind `Arc<dyn Any>` so expensive key generation
//! (especially RSA) only happens once per unique identity tuple. Thread-safe:
//! uses `DashMap` with `std`, `spin::Mutex` without.
//!
//! The primary type is [`ArtifactCache`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::any::Any;
use core::fmt;
#[cfg(feature = "std")]
use dashmap::DashMap;
#[cfg(not(feature = "std"))]
use spin::Mutex;

use uselesskey_core_id::ArtifactId;

type CacheValue = Arc<dyn Any + Send + Sync>;

#[cfg(feature = "std")]
type Cache = DashMap<ArtifactId, CacheValue>;

#[cfg(not(feature = "std"))]
type Cache = Mutex<BTreeMap<ArtifactId, CacheValue>>;

/// Cache keyed by [`ArtifactId`] that stores typed values behind `Arc<dyn Any>`.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use uselesskey_core_cache::ArtifactCache;
/// use uselesskey_core_id::{ArtifactId, DerivationVersion};
///
/// let cache = ArtifactCache::new();
/// let id = ArtifactId::new("domain:rsa", "issuer", b"RS256", "good", DerivationVersion::V1);
///
/// // Insert once, retrieve many times
/// cache.insert_if_absent_typed(id.clone(), Arc::new(42u32));
/// let value = cache.get_typed::<u32>(&id).unwrap();
/// assert_eq!(*value, 42);
/// ```
pub struct ArtifactCache {
    inner: Cache,
}

impl fmt::Debug for ArtifactCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArtifactCache")
            .field("len", &self.len())
            .finish()
    }
}

impl ArtifactCache {
    /// Create an empty artifact cache.
    pub fn new() -> Self {
        Self { inner: new_cache() }
    }

    /// Number of cache entries.
    pub fn len(&self) -> usize {
        cache_len(&self.inner)
    }

    /// Returns `true` when there are no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove all entries from the cache.
    pub fn clear(&self) {
        cache_clear(&self.inner);
    }

    /// Retrieve a typed value by id.
    ///
    /// Panics if the id exists with a different concrete type.
    pub fn get_typed<T>(&self, id: &ArtifactId) -> Option<Arc<T>>
    where
        T: Any + Send + Sync + 'static,
    {
        cache_get(&self.inner, id).map(|entry| downcast_or_panic::<T>(entry, id))
    }

    /// Insert a typed value if the id is vacant and return the winning cached value.
    ///
    /// Panics if an existing value for the same id has a different concrete type.
    pub fn insert_if_absent_typed<T>(&self, id: ArtifactId, value: Arc<T>) -> Arc<T>
    where
        T: Any + Send + Sync + 'static,
    {
        let value_any: CacheValue = value;
        let winner = cache_insert_if_absent(&self.inner, id.clone(), value_any);
        downcast_or_panic::<T>(winner, &id)
    }
}

impl Default for ArtifactCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
fn new_cache() -> Cache {
    DashMap::new()
}

#[cfg(not(feature = "std"))]
fn new_cache() -> Cache {
    Mutex::new(BTreeMap::new())
}

#[cfg(feature = "std")]
fn cache_len(cache: &Cache) -> usize {
    cache.len()
}

#[cfg(not(feature = "std"))]
fn cache_len(cache: &Cache) -> usize {
    cache.lock().len()
}

#[cfg(feature = "std")]
fn cache_clear(cache: &Cache) {
    cache.clear();
}

#[cfg(not(feature = "std"))]
fn cache_clear(cache: &Cache) {
    cache.lock().clear();
}

#[cfg(feature = "std")]
fn cache_get(cache: &Cache, id: &ArtifactId) -> Option<CacheValue> {
    cache.get(id).map(|entry| entry.value().clone())
}

#[cfg(not(feature = "std"))]
fn cache_get(cache: &Cache, id: &ArtifactId) -> Option<CacheValue> {
    cache.lock().get(id).cloned()
}

#[cfg(feature = "std")]
fn cache_insert_if_absent(cache: &Cache, id: ArtifactId, value: CacheValue) -> CacheValue {
    cache.entry(id).or_insert(value).value().clone()
}

#[cfg(not(feature = "std"))]
fn cache_insert_if_absent(cache: &Cache, id: ArtifactId, value: CacheValue) -> CacheValue {
    use alloc::collections::btree_map::Entry;

    let mut guard = cache.lock();
    match guard.entry(id) {
        Entry::Vacant(slot) => slot.insert(value).clone(),
        Entry::Occupied(slot) => slot.get().clone(),
    }
}

/// Downcast a cached `Any` value to the expected fixture type.
///
/// Panics when the cache key maps to a different concrete type.
pub fn downcast_or_panic<T>(arc_any: CacheValue, id: &ArtifactId) -> Arc<T>
where
    T: Any + Send + Sync + 'static,
{
    match arc_any.downcast::<T>() {
        Ok(v) => v,
        Err(_) => {
            panic!(
                "uselesskey-core-cache: artifact type mismatch for domain={} label={} variant={}",
                id.domain, id.label, id.variant
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ArtifactCache, downcast_or_panic};
    use core::any::Any;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use uselesskey_core_id::{ArtifactId, DerivationVersion};

    fn sample_id() -> ArtifactId {
        ArtifactId::new(
            "domain:test",
            "label",
            b"spec",
            "good",
            DerivationVersion::V1,
        )
    }

    #[test]
    fn typed_round_trip() {
        let cache = ArtifactCache::new();
        let id = sample_id();

        let inserted = cache.insert_if_absent_typed(id.clone(), Arc::new(7u32));
        let fetched = cache
            .get_typed::<u32>(&id)
            .expect("value should be retrievable");

        assert_eq!(*inserted, 7);
        assert_eq!(*fetched, 7);
    }

    #[test]
    fn insert_if_absent_keeps_first_value() {
        let cache = ArtifactCache::new();
        let id = sample_id();

        let first = cache.insert_if_absent_typed(id.clone(), Arc::new(11u32));
        let second = cache.insert_if_absent_typed(id, Arc::new(22u32));

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(*second, 11u32);
    }

    #[test]
    fn clear_empties_cache() {
        let cache = ArtifactCache::new();
        let id = sample_id();

        cache.insert_if_absent_typed(id, Arc::new(1u8));
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn debug_includes_type_name_and_len() {
        let cache = ArtifactCache::new();
        cache.insert_if_absent_typed(sample_id(), Arc::new(1u8));

        let dbg = format!("{cache:?}");
        assert!(
            dbg.contains("ArtifactCache"),
            "debug output should include struct name"
        );
        assert!(dbg.contains("len: 1"), "debug output should include len");
    }

    #[test]
    fn get_typed_type_mismatch_panics() {
        let cache = ArtifactCache::new();
        let id = sample_id();
        let _ = cache.insert_if_absent_typed(id.clone(), Arc::new(123u32));

        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = cache.get_typed::<String>(&id);
        }));

        assert!(result.is_err(), "expected panic on type mismatch");
    }

    #[test]
    fn downcast_or_panic_type_mismatch_panics() {
        let id = sample_id();
        let arc_any: Arc<dyn Any + Send + Sync> = Arc::new(123u32);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = downcast_or_panic::<String>(arc_any.clone(), &id);
        }));

        assert!(result.is_err(), "expected panic on type mismatch");
    }

    #[test]
    fn downcast_or_panic_ok_returns_value() {
        let id = sample_id();
        let arc_any: Arc<dyn Any + Send + Sync> = Arc::new(123u32);
        let arc = downcast_or_panic::<u32>(arc_any, &id);
        assert_eq!(*arc, 123u32);
    }

    #[test]
    fn default_creates_empty_cache() {
        let cache = ArtifactCache::default();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn get_typed_missing_key_returns_none() {
        let cache = ArtifactCache::new();
        let id = sample_id();
        assert!(cache.get_typed::<u32>(&id).is_none());
    }

    #[test]
    fn distinct_ids_are_stored_independently() {
        let cache = ArtifactCache::new();
        let id_a = ArtifactId::new("domain:a", "label", b"spec", "good", DerivationVersion::V1);
        let id_b = ArtifactId::new("domain:b", "label", b"spec", "good", DerivationVersion::V1);

        cache.insert_if_absent_typed(id_a.clone(), Arc::new(1u32));
        cache.insert_if_absent_typed(id_b.clone(), Arc::new(2u32));

        assert_eq!(cache.len(), 2);
        assert_eq!(*cache.get_typed::<u32>(&id_a).unwrap(), 1);
        assert_eq!(*cache.get_typed::<u32>(&id_b).unwrap(), 2);
    }

    #[test]
    fn concurrent_inserts_converge() {
        use std::thread;

        let cache = Arc::new(ArtifactCache::new());
        let id = sample_id();

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let cache = Arc::clone(&cache);
                let id = id.clone();
                thread::spawn(move || cache.insert_if_absent_typed(id, Arc::new(i as u32)))
            })
            .collect();

        let results: Vec<u32> = handles.into_iter().map(|h| *h.join().unwrap()).collect();

        // All threads must see the same winning value.
        let first = results[0];
        assert!(results.iter().all(|v| *v == first));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn downcast_or_panic_message_contains_id_fields() {
        let id = ArtifactId::new(
            "domain:msg",
            "my-label",
            b"spec",
            "my-variant",
            DerivationVersion::V1,
        );
        let arc_any: Arc<dyn Any + Send + Sync> = Arc::new(42u32);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = downcast_or_panic::<String>(arc_any.clone(), &id);
        }));
        let err = result.unwrap_err();
        let msg = err.downcast_ref::<String>().unwrap();
        assert!(msg.contains("domain:msg"), "panic should mention domain");
        assert!(msg.contains("my-label"), "panic should mention label");
        assert!(msg.contains("my-variant"), "panic should mention variant");
    }
}
