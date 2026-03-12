//! Edge-case and boundary tests for Factory.

use std::sync::Arc;
use std::thread;

use uselesskey_core_factory::{Factory, Mode};
use uselesskey_core_id::Seed;

fn seed_u64(seed: Seed) -> u64 {
    let mut buf = [0u8; 8];
    seed.fill_bytes(&mut buf);
    u64::from_le_bytes(buf)
}

fn seed_array<const N: usize>(seed: Seed) -> [u8; N] {
    let mut buf = [0u8; N];
    seed.fill_bytes(&mut buf);
    buf
}

// ── Empty and unusual labels ────────────────────────────────────────

#[test]
fn empty_label_produces_valid_artifact() {
    let fx = Factory::deterministic(Seed::new([1u8; 32]));
    let result: Arc<String> = fx.get_or_init("domain:test", "", b"spec", "default", |seed| {
        hex::encode(&seed_array::<16>(seed))
    });
    assert!(!result.is_empty());
}

#[test]
fn unicode_label_produces_valid_artifact() {
    let fx = Factory::deterministic(Seed::new([2u8; 32]));
    let result: Arc<String> =
        fx.get_or_init("domain:test", "日本語🔑", b"spec", "default", |seed| {
            hex::encode(&seed_array::<16>(seed))
        });
    assert!(!result.is_empty());
}

#[test]
fn very_long_label_produces_valid_artifact() {
    let fx = Factory::deterministic(Seed::new([3u8; 32]));
    let long_label = "x".repeat(10_000);
    let result: Arc<String> =
        fx.get_or_init("domain:test", &long_label, b"spec", "default", |seed| {
            hex::encode(&seed_array::<16>(seed))
        });
    assert!(!result.is_empty());
}

#[test]
fn special_chars_in_label() {
    let fx = Factory::deterministic(Seed::new([4u8; 32]));
    let labels = [
        "label/with/slashes",
        "label\\with\\backslashes",
        "label with spaces",
        "label\twith\ttabs",
        "label\nwith\nnewlines",
        "label&with<special>chars\"'",
        "",
        "null\0byte",
    ];
    for label in labels {
        let result: Arc<u64> = fx.get_or_init("domain:test", label, b"spec", "default", seed_u64);
        let _ = *result; // just verify no panic
    }
}

// ── Seed boundary values ────────────────────────────────────────────

#[test]
fn seed_zero_produces_deterministic_output() {
    let fx1 = Factory::deterministic(Seed::new([0u8; 32]));
    let fx2 = Factory::deterministic(Seed::new([0u8; 32]));
    let a: Arc<u64> = fx1.get_or_init("domain:test", "label", b"spec", "default", seed_u64);
    let b: Arc<u64> = fx2.get_or_init("domain:test", "label", b"spec", "default", seed_u64);
    assert_eq!(*a, *b);
}

#[test]
fn seed_max_produces_deterministic_output() {
    let fx1 = Factory::deterministic(Seed::new([0xFF; 32]));
    let fx2 = Factory::deterministic(Seed::new([0xFF; 32]));
    let a: Arc<u64> = fx1.get_or_init("domain:test", "label", b"spec", "default", seed_u64);
    let b: Arc<u64> = fx2.get_or_init("domain:test", "label", b"spec", "default", seed_u64);
    assert_eq!(*a, *b);
}

#[test]
fn seed_zero_differs_from_seed_max() {
    let fx0 = Factory::deterministic(Seed::new([0u8; 32]));
    let fxf = Factory::deterministic(Seed::new([0xFF; 32]));
    let a: Arc<u64> = fx0.get_or_init("domain:test", "label", b"spec", "default", seed_u64);
    let b: Arc<u64> = fxf.get_or_init("domain:test", "label", b"spec", "default", seed_u64);
    assert_ne!(*a, *b);
}

#[test]
fn seed_one_produces_deterministic_output() {
    let mut seed_bytes = [0u8; 32];
    seed_bytes[31] = 1;
    let fx1 = Factory::deterministic(Seed::new(seed_bytes));
    let fx2 = Factory::deterministic(Seed::new(seed_bytes));
    let a: Arc<u64> = fx1.get_or_init("domain:test", "label", b"spec", "default", seed_u64);
    let b: Arc<u64> = fx2.get_or_init("domain:test", "label", b"spec", "default", seed_u64);
    assert_eq!(*a, *b);
}

// ── Empty spec and variant ──────────────────────────────────────────

#[test]
fn empty_spec_bytes_produces_valid_artifact() {
    let fx = Factory::deterministic(Seed::new([5u8; 32]));
    let result: Arc<u64> = fx.get_or_init("domain:test", "label", b"", "default", seed_u64);
    let _ = *result;
}

#[test]
fn empty_variant_produces_valid_artifact() {
    let fx = Factory::deterministic(Seed::new([6u8; 32]));
    let result: Arc<u64> = fx.get_or_init("domain:test", "label", b"spec", "", seed_u64);
    let _ = *result;
}

// ── Concurrent factory access (stress test) ─────────────────────────

#[test]
fn concurrent_factory_many_threads_same_key() {
    let fx = Factory::deterministic(Seed::new([7u8; 32]));
    let handles: Vec<_> = (0..32)
        .map(|_| {
            let fx = fx.clone();
            thread::spawn(move || {
                let val: Arc<u64> =
                    fx.get_or_init("domain:test", "shared", b"spec", "default", seed_u64);
                *val
            })
        })
        .collect();

    let results: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    // All threads must see the same value
    assert!(results.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn concurrent_factory_different_keys() {
    let fx = Factory::deterministic(Seed::new([8u8; 32]));
    let handles: Vec<_> = (0..16)
        .map(|i| {
            let fx = fx.clone();
            thread::spawn(move || {
                let label = format!("label-{i}");
                let val: Arc<u64> =
                    fx.get_or_init("domain:test", &label, b"spec", "default", seed_u64);
                (label, *val)
            })
        })
        .collect();

    let mut results: Vec<(String, u64)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    results.sort_by_key(|(l, _)| l.clone());

    // Each label should produce a unique value
    let values: std::collections::HashSet<u64> = results.iter().map(|(_, v)| *v).collect();
    assert_eq!(values.len(), 16);
}

// ── Mode::Debug format ──────────────────────────────────────────────

#[test]
fn debug_deterministic_factory_does_not_leak_seed() {
    let fx = Factory::deterministic(Seed::new([0xAB; 32]));
    let dbg = format!("{fx:?}");
    assert!(!dbg.contains("ab"), "Debug must not leak seed bytes");
    assert!(!dbg.contains("AB"), "Debug must not leak seed bytes");
    assert!(dbg.contains("Factory"), "Debug should mention Factory");
}

#[test]
fn debug_random_factory() {
    let fx = Factory::random();
    let dbg = format!("{fx:?}");
    assert!(dbg.contains("Factory"), "Debug should mention Factory");
    assert!(dbg.contains("Random"), "Debug should mention Random mode");
}

// ── Mode access ─────────────────────────────────────────────────────

#[test]
fn mode_returns_random_for_random_factory() {
    let fx = Factory::random();
    assert!(matches!(fx.mode(), Mode::Random));
}

#[test]
fn mode_returns_deterministic_for_deterministic_factory() {
    let fx = Factory::deterministic(Seed::new([1u8; 32]));
    assert!(matches!(fx.mode(), Mode::Deterministic { .. }));
}

// ── Cache clear ─────────────────────────────────────────────────────

#[test]
fn clear_cache_then_regenerate_produces_same_value() {
    let fx = Factory::deterministic(Seed::new([9u8; 32]));
    let a: Arc<u64> = fx.get_or_init("domain:test", "label", b"spec", "default", seed_u64);
    fx.clear_cache();
    let b: Arc<u64> = fx.get_or_init("domain:test", "label", b"spec", "default", seed_u64);
    assert_eq!(
        *a, *b,
        "deterministic regeneration after cache clear must match"
    );
}

// ── Clone shares cache ──────────────────────────────────────────────

#[test]
fn cloned_factory_shares_cache() {
    let fx1 = Factory::deterministic(Seed::new([10u8; 32]));
    let _: Arc<u64> = fx1.get_or_init("domain:test", "label", b"spec", "default", seed_u64);
    let fx2 = fx1.clone();
    // fx2 should see the cached value without calling init
    let val: Arc<u64> = fx2.get_or_init("domain:test", "label", b"spec", "default", |_rng| {
        panic!("init should not be called for cached value");
    });
    let _ = *val;
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
