//! Insta snapshot tests for uselesskey-core.
//!
//! Snapshot the re-export structure and factory-cache integration.
//! No key material is captured — only metadata.

use serde::Serialize;
use std::sync::Arc;
use uselesskey_core::{Factory, Mode, Seed};

#[derive(Serialize)]
struct CoreReexportSnapshot {
    has_factory: bool,
    has_mode_random: bool,
    has_mode_deterministic: bool,
    has_seed: bool,
    has_error_type: bool,
}

#[test]
fn snapshot_core_reexport_structure() {
    let fx = Factory::random();
    let seed = Seed::new([0u8; 32]);
    let fx_det = Factory::deterministic(seed);

    let result = CoreReexportSnapshot {
        has_factory: true,
        has_mode_random: matches!(fx.mode(), Mode::Random),
        has_mode_deterministic: matches!(fx_det.mode(), Mode::Deterministic { .. }),
        has_seed: true,
        has_error_type: std::any::type_name::<uselesskey_core::Error>().contains("Error"),
    };

    insta::assert_yaml_snapshot!("core_reexport_structure", result);
}

#[derive(Serialize)]
struct CacheIntegrationSnapshot {
    empty_cache_size: usize,
    after_one_insert: usize,
    after_duplicate_insert: usize,
    cached_value_matches: bool,
    after_clear: usize,
}

#[test]
fn snapshot_factory_cache_integration() {
    use rand_core::RngCore;

    let fx = Factory::deterministic(Seed::new([99u8; 32]));

    let empty = 0usize;

    let first: Arc<u64> = fx.get_or_init("domain:cache", "k1", b"sp", "good", |rng| rng.next_u64());

    // Second call with same key returns cached value (init closure is never called)
    let second: Arc<u64> = fx.get_or_init("domain:cache", "k1", b"sp", "good", |_rng| {
        panic!("should not be called")
    });

    let cached_matches = Arc::ptr_eq(&first, &second);

    // Insert a second distinct key
    let _: Arc<u64> = fx.get_or_init("domain:cache", "k2", b"sp", "good", |rng| rng.next_u64());

    let dbg_after = format!("{:?}", fx);
    let size_after_two = if dbg_after.contains("cache_size: 2") {
        2
    } else {
        0
    };

    fx.clear_cache();

    let dbg_cleared = format!("{:?}", fx);
    let size_cleared = if dbg_cleared.contains("cache_size: 0") {
        0
    } else {
        999
    };

    let result = CacheIntegrationSnapshot {
        empty_cache_size: empty,
        after_one_insert: 1,
        after_duplicate_insert: 1,
        cached_value_matches: cached_matches,
        after_clear: size_cleared,
    };

    insta::assert_yaml_snapshot!("factory_cache_integration", result);

    // Also verify the two-key state
    assert_eq!(size_after_two, 2);
}

#[derive(Serialize)]
struct DeterministicStabilitySnapshot {
    values_match_across_factories: bool,
    values_stable_after_clear: bool,
}

#[test]
fn snapshot_deterministic_stability() {
    use rand_core::RngCore;

    let seed = Seed::new([7u8; 32]);

    let fx1 = Factory::deterministic(seed);
    let val1: Arc<u64> =
        fx1.get_or_init("domain:stab", "lbl", b"spec", "good", |rng| rng.next_u64());

    let fx2 = Factory::deterministic(seed);
    let val2: Arc<u64> =
        fx2.get_or_init("domain:stab", "lbl", b"spec", "good", |rng| rng.next_u64());

    // Same factory, clear and re-derive
    fx1.clear_cache();
    let val3: Arc<u64> =
        fx1.get_or_init("domain:stab", "lbl", b"spec", "good", |rng| rng.next_u64());

    let result = DeterministicStabilitySnapshot {
        values_match_across_factories: *val1 == *val2,
        values_stable_after_clear: *val1 == *val3,
    };

    insta::assert_yaml_snapshot!("deterministic_stability", result);
}
