//! Error path and boundary condition tests for uselesskey-core-factory.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use uselesskey_core_factory::{Factory, Mode};
use uselesskey_core_id::Seed;

fn seed_array<const N: usize>(seed: Seed) -> [u8; N] {
    let mut buf = [0u8; N];
    seed.fill_bytes(&mut buf);
    buf
}

// =========================================================================
// Boundary conditions: empty and unusual labels
// =========================================================================

#[test]
fn empty_label_produces_valid_artifact() {
    let fx = Factory::deterministic(Seed::new([1u8; 32]));
    let val: Arc<u32> = fx.get_or_init("domain:test", "", b"spec", "good", |_rng| 42u32);
    assert_eq!(*val, 42);
}

#[test]
fn zero_length_spec_bytes_produces_valid_artifact() {
    let fx = Factory::deterministic(Seed::new([1u8; 32]));
    let val: Arc<u32> = fx.get_or_init("domain:test", "label", b"", "good", |_rng| 99u32);
    assert_eq!(*val, 99);
}

#[test]
fn empty_domain_produces_valid_artifact() {
    let fx = Factory::deterministic(Seed::new([1u8; 32]));
    let val: Arc<u32> = fx.get_or_init("", "label", b"spec", "good", |_rng| 77u32);
    assert_eq!(*val, 77);
}

#[test]
fn empty_variant_produces_valid_artifact() {
    let fx = Factory::deterministic(Seed::new([1u8; 32]));
    let val: Arc<u32> = fx.get_or_init("domain:test", "label", b"spec", "", |_rng| 55u32);
    assert_eq!(*val, 55);
}

#[test]
fn all_empty_strings_still_produces_artifact() {
    let fx = Factory::deterministic(Seed::new([1u8; 32]));
    let val: Arc<u32> = fx.get_or_init("", "", b"", "", |_rng| 11u32);
    assert_eq!(*val, 11);
}

// =========================================================================
// Extremely long labels
// =========================================================================

#[test]
fn extremely_long_label_does_not_panic() {
    let fx = Factory::deterministic(Seed::new([2u8; 32]));
    let long_label = "a".repeat(10_000);
    let val: Arc<u32> = fx.get_or_init("domain:test", &long_label, b"spec", "good", |_rng| 42u32);
    assert_eq!(*val, 42);
}

#[test]
fn extremely_long_spec_bytes_does_not_panic() {
    let fx = Factory::deterministic(Seed::new([2u8; 32]));
    let long_spec = vec![0xABu8; 10_000];
    let val: Arc<u32> = fx.get_or_init("domain:test", "label", &long_spec, "good", |_rng| 42u32);
    assert_eq!(*val, 42);
}

// =========================================================================
// Type mismatch in cache panics with descriptive message
// =========================================================================

#[test]
fn type_mismatch_panics_not_silent() {
    // Use deterministic mode so this test also runs under `--no-default-features`
    // where `Mode::Random` is intentionally unavailable.
    let fx = Factory::deterministic(Seed::new([9u8; 32]));
    let _ = fx.get_or_init("domain:tm", "label", b"spec", "good", |_rng| 42u32);

    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = fx.get_or_init("domain:tm", "label", b"spec", "good", |_rng| {
            "wrong type".to_string()
        });
    }));

    assert!(result.is_err(), "type mismatch must panic");
}

// =========================================================================
// Deterministic mode: same inputs produce same outputs
// =========================================================================

#[test]
fn different_seeds_produce_different_artifacts() {
    let fx1 = Factory::deterministic(Seed::new([1u8; 32]));
    let fx2 = Factory::deterministic(Seed::new([2u8; 32]));

    let v1: Arc<[u8; 32]> = fx1.get_or_init("domain:test", "label", b"spec", "good", seed_array);
    let v2: Arc<[u8; 32]> = fx2.get_or_init("domain:test", "label", b"spec", "good", seed_array);

    assert_ne!(*v1, *v2, "different seeds must produce different artifacts");
}

// =========================================================================
// Debug output does not leak seed material
// =========================================================================

#[test]
fn debug_output_does_not_contain_seed_bytes() {
    let seed = Seed::new([0xAB; 32]);
    let fx = Factory::deterministic(seed);
    let dbg = format!("{:?}", fx);

    assert!(
        !dbg.contains("171"),
        "debug output must not contain raw seed byte values"
    );
    assert!(dbg.contains("Factory"), "debug should contain struct name");
}

// =========================================================================
// Mode variants
// =========================================================================

#[test]
fn mode_debug_is_descriptive() {
    let random_mode = Mode::Random;
    let det_mode = Mode::Deterministic {
        master: Seed::new([0u8; 32]),
    };

    let random_dbg = format!("{:?}", random_mode);
    let det_dbg = format!("{:?}", det_mode);

    assert!(random_dbg.contains("Random"));
    assert!(det_dbg.contains("Deterministic"));
    // Seed should be redacted
    assert!(det_dbg.contains("redacted"));
}

// =========================================================================
// Cache isolation: different spec bytes produce different cache entries
// =========================================================================

#[test]
fn different_spec_bytes_produce_different_cache_entries() {
    let fx = Factory::deterministic(Seed::new([3u8; 32]));

    let v1: Arc<u32> = fx.get_or_init("d", "l", b"spec-a", "good", |_rng| 1u32);
    let v2: Arc<u32> = fx.get_or_init("d", "l", b"spec-b", "good", |_rng| 2u32);

    assert_ne!(
        *v1, *v2,
        "different spec bytes must produce different entries"
    );
}

#[test]
fn different_variants_produce_different_cache_entries() {
    let fx = Factory::deterministic(Seed::new([3u8; 32]));

    let v1: Arc<u32> = fx.get_or_init("d", "l", b"spec", "good", |_rng| 1u32);
    let v2: Arc<u32> = fx.get_or_init("d", "l", b"spec", "mismatch", |_rng| 2u32);

    assert_ne!(
        *v1, *v2,
        "different variants must produce different entries"
    );
}
