//! Insta snapshot tests for uselesskey-core-cache.
//!
//! Snapshot cache behavior metadata — entry counts, debug output shape.

use serde::Serialize;
use std::sync::Arc;
use uselesskey_core_cache::ArtifactCache;
use uselesskey_core_id::{ArtifactId, DerivationVersion};

fn sample_id(label: &str) -> ArtifactId {
    ArtifactId::new(
        "domain:snapshot",
        label,
        b"spec",
        "good",
        DerivationVersion::V1,
    )
}

#[derive(Serialize)]
struct CacheStateSnapshot {
    len: usize,
    is_empty: bool,
    debug_contains_type_name: bool,
}

#[test]
fn snapshot_cache_empty() {
    let cache = ArtifactCache::new();
    let dbg = format!("{:?}", cache);

    let result = CacheStateSnapshot {
        len: cache.len(),
        is_empty: cache.is_empty(),
        debug_contains_type_name: dbg.contains("ArtifactCache"),
    };

    insta::assert_yaml_snapshot!("cache_empty_state", result);
}

#[test]
fn snapshot_cache_after_inserts() {
    let cache = ArtifactCache::new();
    cache.insert_if_absent_typed(sample_id("key-1"), Arc::new(100u32));
    cache.insert_if_absent_typed(sample_id("key-2"), Arc::new(200u32));
    cache.insert_if_absent_typed(sample_id("key-3"), Arc::new(300u32));

    let dbg = format!("{:?}", cache);

    let result = CacheStateSnapshot {
        len: cache.len(),
        is_empty: cache.is_empty(),
        debug_contains_type_name: dbg.contains("ArtifactCache"),
    };

    insta::assert_yaml_snapshot!("cache_after_inserts", result);
}

#[test]
fn snapshot_cache_insert_if_absent_behavior() {
    #[derive(Serialize)]
    struct InsertBehavior {
        first_insert_value: u32,
        second_insert_attempted: u32,
        cached_value: u32,
        kept_first: bool,
        cache_len: usize,
    }

    let cache = ArtifactCache::new();
    let id = sample_id("dedup");

    let first = cache.insert_if_absent_typed(id.clone(), Arc::new(11u32));
    let second = cache.insert_if_absent_typed(id, Arc::new(22u32));

    let result = InsertBehavior {
        first_insert_value: 11,
        second_insert_attempted: 22,
        cached_value: *second,
        kept_first: *first == *second && *second == 11,
        cache_len: cache.len(),
    };

    insta::assert_yaml_snapshot!("cache_insert_if_absent", result);
}

#[test]
fn snapshot_cache_clear_behavior() {
    #[derive(Serialize)]
    struct ClearBehavior {
        len_before_clear: usize,
        len_after_clear: usize,
        is_empty_after_clear: bool,
    }

    let cache = ArtifactCache::new();
    cache.insert_if_absent_typed(sample_id("a"), Arc::new(1u8));
    cache.insert_if_absent_typed(sample_id("b"), Arc::new(2u8));

    let before = cache.len();
    cache.clear();

    let result = ClearBehavior {
        len_before_clear: before,
        len_after_clear: cache.len(),
        is_empty_after_clear: cache.is_empty(),
    };

    insta::assert_yaml_snapshot!("cache_clear_behavior", result);
}
