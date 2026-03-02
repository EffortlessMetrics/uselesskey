//! Edge-case and boundary tests for ArtifactId and derivation.

#![cfg(feature = "std")]

use std::collections::HashSet;

use uselesskey_core_id::{ArtifactId, DerivationVersion, Seed};

// ── Empty and boundary inputs ───────────────────────────────────────

#[test]
fn empty_label_and_variant_produce_valid_derivation() {
    let master = Seed::new([1u8; 32]);
    let id = ArtifactId::new("domain:test", "", b"spec", "", DerivationVersion::V1);
    let derived = uselesskey_core_id::derive_seed(&master, &id);
    // Must produce a valid seed (not all zeros)
    assert_ne!(derived.bytes(), &[0u8; 32]);
}

#[test]
fn unicode_label_produces_unique_derivation() {
    let master = Seed::new([2u8; 32]);
    let id_ascii = ArtifactId::new("domain:test", "hello", b"spec", "v", DerivationVersion::V1);
    let id_unicode = ArtifactId::new(
        "domain:test",
        "日本語🔑",
        b"spec",
        "v",
        DerivationVersion::V1,
    );

    let d1 = uselesskey_core_id::derive_seed(&master, &id_ascii);
    let d2 = uselesskey_core_id::derive_seed(&master, &id_unicode);
    assert_ne!(d1, d2);
}

#[test]
fn very_long_label_does_not_panic() {
    let master = Seed::new([3u8; 32]);
    let long_label = "a".repeat(100_000);
    let id = ArtifactId::new(
        "domain:test",
        &long_label,
        b"spec",
        "default",
        DerivationVersion::V1,
    );
    let derived = uselesskey_core_id::derive_seed(&master, &id);
    assert_eq!(derived.bytes().len(), 32);
}

#[test]
fn special_characters_in_variant() {
    let master = Seed::new([4u8; 32]);
    let variants = [
        "",
        "default",
        "corrupt:bad_header",
        "mismatch",
        "null\0byte",
        "日本語",
    ];
    let mut derived_set = HashSet::new();
    for variant in variants {
        let id = ArtifactId::new(
            "domain:test",
            "label",
            b"spec",
            variant,
            DerivationVersion::V1,
        );
        let derived = uselesskey_core_id::derive_seed(&master, &id);
        derived_set.insert(*derived.bytes());
    }
    // All unique variants produce unique seeds
    assert_eq!(derived_set.len(), variants.len());
}

// ── Spec fingerprint sensitivity ────────────────────────────────────

#[test]
fn empty_spec_bytes_differs_from_nonempty() {
    let master = Seed::new([5u8; 32]);
    let id_empty = ArtifactId::new("domain:test", "label", b"", "v", DerivationVersion::V1);
    let id_nonempty = ArtifactId::new("domain:test", "label", b"x", "v", DerivationVersion::V1);
    let d1 = uselesskey_core_id::derive_seed(&master, &id_empty);
    let d2 = uselesskey_core_id::derive_seed(&master, &id_nonempty);
    assert_ne!(d1, d2);
}

#[test]
fn single_bit_difference_in_spec_produces_different_seed() {
    let master = Seed::new([6u8; 32]);
    let id1 = ArtifactId::new("domain:test", "label", &[0x00], "v", DerivationVersion::V1);
    let id2 = ArtifactId::new("domain:test", "label", &[0x01], "v", DerivationVersion::V1);
    let d1 = uselesskey_core_id::derive_seed(&master, &id1);
    let d2 = uselesskey_core_id::derive_seed(&master, &id2);
    assert_ne!(d1, d2);
}

// ── Seed boundary values ────────────────────────────────────────────

#[test]
fn derive_seed_with_zero_master() {
    let master = Seed::new([0u8; 32]);
    let id = ArtifactId::new("domain:test", "label", b"spec", "v", DerivationVersion::V1);
    let derived = uselesskey_core_id::derive_seed(&master, &id);
    // Should still produce non-trivial output
    assert_ne!(derived.bytes(), &[0u8; 32]);
}

#[test]
fn derive_seed_with_max_master() {
    let master = Seed::new([0xFF; 32]);
    let id = ArtifactId::new("domain:test", "label", b"spec", "v", DerivationVersion::V1);
    let derived = uselesskey_core_id::derive_seed(&master, &id);
    assert_ne!(derived.bytes(), &[0xFF; 32]);
}

// ── DerivationVersion trait coverage ────────────────────────────────

#[test]
fn derivation_version_v1_debug_display() {
    let v = DerivationVersion::V1;
    let dbg = format!("{v:?}");
    assert!(dbg.contains("1"));
}

#[test]
fn derivation_version_clone_eq() {
    let v1 = DerivationVersion::V1;
    let v2 = v1;
    assert_eq!(v1, v2);
}

#[test]
fn derivation_version_hash_consistent() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let v1 = DerivationVersion::V1;
    let v2 = DerivationVersion::V1;

    let mut h1 = DefaultHasher::new();
    v1.hash(&mut h1);
    let mut h2 = DefaultHasher::new();
    v2.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn derivation_version_ord() {
    let v1 = DerivationVersion(1);
    let v2 = DerivationVersion(2);
    assert!(v1 < v2);
}

// ── ArtifactId trait coverage ───────────────────────────────────────

#[test]
fn artifact_id_eq_requires_all_fields_match() {
    let id1 = ArtifactId::new("domain:a", "label", b"spec", "v", DerivationVersion::V1);
    let id2 = ArtifactId::new("domain:b", "label", b"spec", "v", DerivationVersion::V1);
    assert_ne!(id1, id2, "different domain should differ");
}

#[test]
fn artifact_id_hash_in_set() {
    let mut set = HashSet::new();
    let id1 = ArtifactId::new("d", "label1", b"spec", "v", DerivationVersion::V1);
    let id2 = ArtifactId::new("d", "label2", b"spec", "v", DerivationVersion::V1);
    let id3 = ArtifactId::new("d", "label1", b"spec", "v", DerivationVersion::V1);

    set.insert(id1);
    set.insert(id2);
    set.insert(id3); // duplicate of id1

    assert_eq!(set.len(), 2);
}

#[test]
fn artifact_id_debug_shows_fields() {
    let id = ArtifactId::new(
        "domain:test",
        "my-label",
        b"spec",
        "v1",
        DerivationVersion::V1,
    );
    let dbg = format!("{id:?}");
    assert!(dbg.contains("my-label"), "Debug should show label");
    assert!(dbg.contains("domain:test"), "Debug should show domain");
}
