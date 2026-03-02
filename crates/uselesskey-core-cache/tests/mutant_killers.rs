//! Mutant-killing tests for the artifact cache.

use std::sync::Arc;
use uselesskey_core_cache::ArtifactCache;
use uselesskey_core_id::{ArtifactId, DerivationVersion};

fn id(label: &str) -> ArtifactId {
    ArtifactId::new("domain:test", label, b"spec", "good", DerivationVersion::V1)
}

#[test]
fn new_cache_is_empty_and_has_len_zero() {
    let cache = ArtifactCache::new();
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
}

#[test]
fn insert_increments_len() {
    let cache = ArtifactCache::new();
    cache.insert_if_absent_typed(id("a"), Arc::new(1u32));
    assert_eq!(cache.len(), 1);
    assert!(!cache.is_empty());

    cache.insert_if_absent_typed(id("b"), Arc::new(2u32));
    assert_eq!(cache.len(), 2);
}

#[test]
fn insert_same_id_does_not_increment_len() {
    let cache = ArtifactCache::new();
    cache.insert_if_absent_typed(id("a"), Arc::new(1u32));
    cache.insert_if_absent_typed(id("a"), Arc::new(2u32));
    assert_eq!(cache.len(), 1);
}

#[test]
fn get_typed_returns_none_for_missing() {
    let cache = ArtifactCache::new();
    assert!(cache.get_typed::<u32>(&id("missing")).is_none());
}

#[test]
fn get_typed_returns_correct_value() {
    let cache = ArtifactCache::new();
    cache.insert_if_absent_typed(id("a"), Arc::new(42u32));
    let val = cache.get_typed::<u32>(&id("a")).unwrap();
    assert_eq!(*val, 42);
}

#[test]
fn insert_if_absent_returns_first_value() {
    let cache = ArtifactCache::new();
    let first = cache.insert_if_absent_typed(id("a"), Arc::new(100u32));
    let second = cache.insert_if_absent_typed(id("a"), Arc::new(200u32));
    assert_eq!(*first, 100);
    assert_eq!(*second, 100); // first wins
    assert!(Arc::ptr_eq(&first, &second));
}

#[test]
fn clear_empties_cache_completely() {
    let cache = ArtifactCache::new();
    cache.insert_if_absent_typed(id("a"), Arc::new(1u32));
    cache.insert_if_absent_typed(id("b"), Arc::new(2u32));
    assert_eq!(cache.len(), 2);

    cache.clear();
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
    assert!(cache.get_typed::<u32>(&id("a")).is_none());
    assert!(cache.get_typed::<u32>(&id("b")).is_none());
}

#[test]
fn debug_format_shows_len() {
    let cache = ArtifactCache::new();
    let dbg = format!("{cache:?}");
    assert!(dbg.contains("ArtifactCache"));
    assert!(dbg.contains("len: 0"));

    cache.insert_if_absent_typed(id("x"), Arc::new(1u8));
    let dbg = format!("{cache:?}");
    assert!(dbg.contains("len: 1"));
}

#[test]
fn default_creates_empty_cache() {
    let cache = ArtifactCache::default();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}
