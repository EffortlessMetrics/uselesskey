//! Determinism regression tests for uselesskey-core.
//!
//! These tests pin the BLAKE3 derivation pipeline and cache behavior at the
//! core level — before any key-type crate is involved. If any of these tests
//! fail, the derivation contract is broken.

use std::sync::Arc;

use uselesskey_core::{ArtifactId, DerivationVersion, Factory, Seed};

/// Helper: build a deterministic factory from the string "42".
fn fx42() -> Factory {
    Factory::deterministic(Seed::from_env_value("42").unwrap())
}

// ── 1. BLAKE3 derivation pinning ──────────────────────────────────────────
//
// We test derivation stability via get_or_init with a closure that captures
// the RNG state (the derived seed feeds ChaCha20Rng). We generate a fixed-
// size byte vector and pin its value.

#[test]
fn determinism_blake3_derivation_produces_stable_rng() {
    use rand_core::RngCore;

    let fx = fx42();
    let bytes: Arc<Vec<u8>> = fx.get_or_init("test:derive-pin", "label", b"spec", "good", |rng| {
        let mut buf = vec![0u8; 16];
        rng.fill_bytes(&mut buf);
        buf
    });

    // A second factory with the same seed must produce identical bytes.
    let fx2 = fx42();
    let bytes2: Arc<Vec<u8>> =
        fx2.get_or_init("test:derive-pin", "label", b"spec", "good", |rng| {
            let mut buf = vec![0u8; 16];
            rng.fill_bytes(&mut buf);
            buf
        });

    assert_eq!(
        *bytes, *bytes2,
        "derived RNG output must be stable across factory instances"
    );

    // Pin the first 4 bytes so any derivation algorithm change is caught.
    let pinned_prefix = [bytes[0], bytes[1], bytes[2], bytes[3]];
    assert_eq!(
        pinned_prefix,
        [0x1c, 0x64, 0xf3, 0x21],
        "BLAKE3 derivation output for seed=42 domain=test:derive-pin label=label must be stable"
    );
}

#[test]
fn determinism_blake3_different_domains_produce_different_output() {
    use rand_core::RngCore;

    let fx = fx42();

    let make_bytes = |domain: &'static str| -> Vec<u8> {
        let arc: Arc<Vec<u8>> = fx.get_or_init(domain, "same", b"spec", "good", |rng| {
            let mut buf = vec![0u8; 16];
            rng.fill_bytes(&mut buf);
            buf
        });
        (*arc).clone()
    };

    let a = make_bytes("test:domain-a");
    let b = make_bytes("test:domain-b");
    assert_ne!(
        a, b,
        "different domains must produce different derived output"
    );
}

#[test]
fn determinism_blake3_different_labels_produce_different_output() {
    use rand_core::RngCore;

    let fx = fx42();

    let make_bytes = |label: &str| -> Vec<u8> {
        // Each call needs a unique cache key, so we use different labels.
        let arc: Arc<Vec<u8>> = fx.get_or_init("test:label-test", label, b"spec", "good", |rng| {
            let mut buf = vec![0u8; 16];
            rng.fill_bytes(&mut buf);
            buf
        });
        (*arc).clone()
    };

    let a = make_bytes("label-a");
    let b = make_bytes("label-b");
    assert_ne!(
        a, b,
        "different labels must produce different derived output"
    );
}

#[test]
fn determinism_blake3_different_specs_produce_different_output() {
    use rand_core::RngCore;

    let fx = fx42();

    let make_bytes = |spec: &[u8]| -> Vec<u8> {
        let arc: Arc<Vec<u8>> = fx.get_or_init("test:spec-test", "label", spec, "good", |rng| {
            let mut buf = vec![0u8; 16];
            rng.fill_bytes(&mut buf);
            buf
        });
        (*arc).clone()
    };

    let a = make_bytes(b"spec-a");
    let b = make_bytes(b"spec-b");
    assert_ne!(
        a, b,
        "different spec bytes must produce different derived output"
    );
}

#[test]
fn determinism_blake3_different_variants_produce_different_output() {
    use rand_core::RngCore;

    let fx = fx42();

    let make_bytes = |variant: &str| -> Vec<u8> {
        let arc: Arc<Vec<u8>> =
            fx.get_or_init("test:variant-test", "label", b"spec", variant, |rng| {
                let mut buf = vec![0u8; 16];
                rng.fill_bytes(&mut buf);
                buf
            });
        (*arc).clone()
    };

    let a = make_bytes("good");
    let b = make_bytes("mismatch");
    assert_ne!(
        a, b,
        "different variants must produce different derived output"
    );
}

// ── 2. ArtifactId fingerprint pinning ─────────────────────────────────────

#[test]
fn determinism_artifact_id_fingerprint_is_stable() {
    let id1 = ArtifactId::new(
        "domain",
        "label",
        b"spec-bytes",
        "good",
        DerivationVersion::V1,
    );
    let id2 = ArtifactId::new(
        "domain",
        "label",
        b"spec-bytes",
        "good",
        DerivationVersion::V1,
    );

    // Fingerprints must be identical for identical inputs.
    assert_eq!(id1.spec_fingerprint, id2.spec_fingerprint);

    // Pin the fingerprint value for b"spec-bytes".
    assert_eq!(
        hex(&id1.spec_fingerprint[..4]),
        "989b1119",
        "spec_fingerprint for b\"spec-bytes\" must be stable (BLAKE3 hash)"
    );
}

#[test]
fn determinism_artifact_id_fingerprint_changes_with_spec() {
    let id_a = ArtifactId::new("d", "l", b"spec-a", "v", DerivationVersion::V1);
    let id_b = ArtifactId::new("d", "l", b"spec-b", "v", DerivationVersion::V1);
    assert_ne!(
        id_a.spec_fingerprint, id_b.spec_fingerprint,
        "different spec bytes must produce different fingerprints"
    );
}

#[test]
fn determinism_artifact_id_fields_preserved() {
    let id = ArtifactId::new(
        "my:domain",
        "my-label",
        b"s",
        "my-variant",
        DerivationVersion::V1,
    );
    assert_eq!(id.domain, "my:domain");
    assert_eq!(id.label, "my-label");
    assert_eq!(id.variant, "my-variant");
    assert_eq!(id.derivation_version, DerivationVersion::V1);
}

// ── 3. Cache identity ─────────────────────────────────────────────────────

#[test]
fn determinism_cache_returns_same_arc_pointer() {
    let fx = fx42();

    let first: Arc<u64> = fx.get_or_init("test:cache-id", "label", b"spec", "good", |_rng| 42u64);
    let second: Arc<u64> = fx.get_or_init("test:cache-id", "label", b"spec", "good", |_rng| 99u64);

    // Must return the same Arc — the init closure should not run a second time.
    assert!(
        Arc::ptr_eq(&first, &second),
        "same (domain, label, spec, variant) must return the same Arc pointer"
    );
    assert_eq!(*first, 42);
}

#[test]
fn determinism_cache_different_keys_are_independent() {
    let fx = fx42();

    let a: Arc<u64> = fx.get_or_init("test:cache-a", "label", b"spec", "good", |_rng| 1u64);
    let b: Arc<u64> = fx.get_or_init("test:cache-b", "label", b"spec", "good", |_rng| 2u64);

    assert!(!Arc::ptr_eq(&a, &b));
    assert_eq!(*a, 1);
    assert_eq!(*b, 2);
}

#[test]
fn determinism_cache_clear_allows_reinit() {
    let fx = fx42();

    let first: Arc<u64> =
        fx.get_or_init("test:cache-clear", "label", b"spec", "good", |_rng| 10u64);
    assert_eq!(*first, 10);

    fx.clear_cache();

    let second: Arc<u64> =
        fx.get_or_init("test:cache-clear", "label", b"spec", "good", |_rng| 20u64);
    // After clear, a new value is generated (but deterministic, so same seed → same value).
    // The Arc pointer should be different since cache was cleared.
    assert!(!Arc::ptr_eq(&first, &second));
}

// ── 4. Seed sensitivity at core level ─────────────────────────────────────

#[test]
fn determinism_adjacent_seeds_produce_different_output() {
    use rand_core::RngCore;

    let fx42 = Factory::deterministic(Seed::from_env_value("42").unwrap());
    let fx43 = Factory::deterministic(Seed::from_env_value("43").unwrap());

    let bytes42: Arc<Vec<u8>> =
        fx42.get_or_init("test:seed-sens", "label", b"spec", "good", |rng| {
            let mut buf = vec![0u8; 32];
            rng.fill_bytes(&mut buf);
            buf
        });

    let bytes43: Arc<Vec<u8>> =
        fx43.get_or_init("test:seed-sens", "label", b"spec", "good", |rng| {
            let mut buf = vec![0u8; 32];
            rng.fill_bytes(&mut buf);
            buf
        });

    assert_ne!(
        *bytes42, *bytes43,
        "adjacent seeds (42 vs 43) must produce different derived output"
    );
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
