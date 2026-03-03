//! Insta snapshot tests for uselesskey-core-factory.
//!
//! Snapshot factory creation modes, debug format, and deterministic seeding.
//! No key material is captured — only metadata.

use serde::Serialize;
use uselesskey_core_factory::{Factory, Mode};
use uselesskey_core_id::Seed;

#[derive(Serialize)]
struct FactoryModeSnapshot {
    is_random: bool,
    is_deterministic: bool,
    cache_size: usize,
}

#[test]
fn snapshot_factory_random_mode() {
    let fx = Factory::random();

    let result = FactoryModeSnapshot {
        is_random: matches!(fx.mode(), Mode::Random),
        is_deterministic: matches!(fx.mode(), Mode::Deterministic { .. }),
        cache_size: 0,
    };

    insta::assert_yaml_snapshot!("factory_random_mode", result);
}

#[test]
fn snapshot_factory_deterministic_mode() {
    let seed = Seed::new([42u8; 32]);
    let fx = Factory::deterministic(seed);

    let result = FactoryModeSnapshot {
        is_random: matches!(fx.mode(), Mode::Random),
        is_deterministic: matches!(fx.mode(), Mode::Deterministic { .. }),
        cache_size: 0,
    };

    insta::assert_yaml_snapshot!("factory_deterministic_mode", result);
}

#[derive(Serialize)]
struct FactoryDebugSnapshot {
    contains_factory: bool,
    contains_mode: bool,
    contains_cache_size: bool,
    seed_is_redacted: bool,
    no_raw_seed_bytes: bool,
}

#[test]
fn snapshot_factory_debug_random() {
    let fx = Factory::random();
    let dbg = format!("{:?}", fx);

    let result = FactoryDebugSnapshot {
        contains_factory: dbg.contains("Factory"),
        contains_mode: dbg.contains("Random"),
        contains_cache_size: dbg.contains("cache_size"),
        seed_is_redacted: true, // no seed in random mode
        no_raw_seed_bytes: !dbg.contains("[42,"),
    };

    insta::assert_yaml_snapshot!("factory_debug_random", result);
}

#[test]
fn snapshot_factory_debug_deterministic_no_seed_leak() {
    let fx = Factory::deterministic(Seed::new([42u8; 32]));
    let dbg = format!("{:?}", fx);

    let result = FactoryDebugSnapshot {
        contains_factory: dbg.contains("Factory"),
        contains_mode: dbg.contains("Deterministic"),
        contains_cache_size: dbg.contains("cache_size"),
        seed_is_redacted: dbg.contains("redacted"),
        no_raw_seed_bytes: !dbg.contains("[42, 42, 42"),
    };

    insta::assert_yaml_snapshot!("factory_debug_deterministic", result);
}

#[derive(Serialize)]
struct CustomSeedSnapshot {
    deterministic: bool,
    same_seed_same_value: bool,
    different_seed_different_value: bool,
}

#[test]
fn snapshot_factory_custom_seed_determinism() {
    use rand_core::RngCore;
    use std::sync::Arc;

    let seed_a = Seed::new([1u8; 32]);
    let seed_b = Seed::new([2u8; 32]);

    let fx_a1 = Factory::deterministic(seed_a);
    let fx_a2 = Factory::deterministic(seed_a);
    let fx_b = Factory::deterministic(seed_b);

    let val_a1: Arc<u64> =
        fx_a1.get_or_init("domain:snap", "lbl", b"spec", "good", |rng| rng.next_u64());
    let val_a2: Arc<u64> =
        fx_a2.get_or_init("domain:snap", "lbl", b"spec", "good", |rng| rng.next_u64());
    let val_b: Arc<u64> =
        fx_b.get_or_init("domain:snap", "lbl", b"spec", "good", |rng| rng.next_u64());

    let result = CustomSeedSnapshot {
        deterministic: true,
        same_seed_same_value: *val_a1 == *val_a2,
        different_seed_different_value: *val_a1 != *val_b,
    };

    insta::assert_yaml_snapshot!("factory_custom_seed_determinism", result);
}
