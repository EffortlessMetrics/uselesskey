//! Boundary tests for derivation fallback and `Mode::Random` independence.
//!
//! Complements `determinism_regression.rs` by pinning two specific
//! invariants that have only been exercised indirectly:
//!
//! 1. Unknown `DerivationVersion` values fall through to the v1 derivation.
//! 2. Two distinct `Factory::random()` instances request the same artifact
//!    identity but observe different derived seeds — i.e. `Mode::Random`'s
//!    `seed_for` path is independent of the artifact id.

use std::sync::Arc;

use uselesskey_core::srp::identity::{ArtifactId, DerivationVersion, derive_seed};
use uselesskey_core::{Factory, Seed};

// ── 1. Unknown derivation version falls through to v1 ──────────────────────

#[test]
fn derive_seed_unknown_version_falls_through_to_v1() {
    // High, deliberately unreserved version number. The match arm in
    // `derive_seed` should map this onto the v1 derivation rather than
    // panic or return a placeholder.
    let unknown_a = DerivationVersion(60_000);
    let unknown_b = DerivationVersion(60_001);

    let master = Seed::new([0xAB; 32]);

    let id_v1 = ArtifactId::new(
        "domain:fallback",
        "label",
        b"spec-bytes",
        "variant",
        DerivationVersion::V1,
    );
    let id_unknown_a = ArtifactId {
        derivation_version: unknown_a,
        ..id_v1.clone()
    };
    let id_unknown_b = ArtifactId {
        derivation_version: unknown_b,
        ..id_v1.clone()
    };

    let seed_v1 = derive_seed(&master, &id_v1);
    let seed_unknown_a = derive_seed(&master, &id_unknown_a);
    let seed_unknown_b = derive_seed(&master, &id_unknown_b);

    // The v1 algorithm mixes `derivation_version.0` into the keyed BLAKE3
    // input, so different version tags must produce different outputs.
    assert_ne!(
        seed_v1.bytes(),
        seed_unknown_a.bytes(),
        "unknown version should still mix its tag into the keyed hash"
    );
    assert_ne!(
        seed_unknown_a.bytes(),
        seed_unknown_b.bytes(),
        "adjacent unknown versions must produce distinct outputs (proves the tag is hashed under v1)"
    );

    // Sanity: the fallback is not a placeholder — it returns non-zero bytes.
    assert!(
        seed_unknown_a.bytes().iter().any(|&b| b != 0),
        "fallback derivation must produce real hash bytes, not zeros"
    );
}

#[test]
fn derive_seed_unknown_version_is_deterministic_across_calls() {
    let master = Seed::new([0x5C; 32]);
    let id = ArtifactId::new(
        "domain:fallback",
        "label",
        b"spec",
        "variant",
        DerivationVersion(54_321),
    );

    let a = derive_seed(&master, &id);
    let b = derive_seed(&master, &id);
    assert_eq!(
        a.bytes(),
        b.bytes(),
        "fallback derivation must be deterministic"
    );
}

// ── 2. Mode::Random produces independent outputs across factory instances ──

#[test]
fn random_factories_yield_independent_outputs_for_same_identity() {
    // Two factories, same (domain, label, spec, variant) request — but since
    // each is in `Mode::Random`, `seed_for` reads from `SysRng` and ignores
    // the artifact id. The two derived seeds must therefore differ with
    // overwhelming probability.
    let fx_a = Factory::random();
    let fx_b = Factory::random();

    let bytes_a: Arc<[u8; 32]> = fx_a.get_or_init(
        "domain:random-indep",
        "label",
        b"spec",
        "good",
        capture_seed,
    );
    let bytes_b: Arc<[u8; 32]> = fx_b.get_or_init(
        "domain:random-indep",
        "label",
        b"spec",
        "good",
        capture_seed,
    );

    assert_ne!(
        *bytes_a, *bytes_b,
        "two Mode::Random factories must produce different derived seeds for the same identity"
    );
}

#[test]
fn random_factory_distinct_identities_yield_distinct_seeds() {
    // Within a single random factory, different identities also draw fresh
    // randomness rather than reusing a derived value.
    let fx = Factory::random();

    let a: Arc<[u8; 32]> =
        fx.get_or_init("domain:random-a", "label", b"spec", "good", capture_seed);
    let b: Arc<[u8; 32]> =
        fx.get_or_init("domain:random-b", "label", b"spec", "good", capture_seed);

    assert_ne!(
        *a, *b,
        "Mode::Random must draw fresh OS randomness for each distinct identity"
    );
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn capture_seed(seed: Seed) -> [u8; 32] {
    *seed.bytes()
}
