//! Tests for derived traits on `ArtifactId` and `DerivationVersion`.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeSet, HashSet};
use std::hash::{Hash, Hasher};

use uselesskey_core_id::{ArtifactId, DerivationVersion};

fn hash_of<T: Hash>(val: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    val.hash(&mut hasher);
    hasher.finish()
}

fn make_id(label: &str, variant: &str) -> ArtifactId {
    ArtifactId::new(
        "domain:test",
        label,
        b"spec",
        variant,
        DerivationVersion::V1,
    )
}

// ==================== DerivationVersion ====================

// --- Clone (via Copy) ---

#[test]
fn derivation_version_clone_is_available() {
    let v = DerivationVersion::V1;
    let cloned: DerivationVersion = Clone::clone(&v);
    assert_eq!(v, cloned);
}

#[test]
fn derivation_version_copy() {
    let v = DerivationVersion::V1;
    let copied = v;
    // Original still usable because DerivationVersion is Copy.
    assert_eq!(v, copied);
}

// --- PartialEq / Eq ---

#[test]
fn derivation_version_eq_same() {
    assert_eq!(DerivationVersion(1), DerivationVersion(1));
}

#[test]
fn derivation_version_ne_different() {
    assert_ne!(DerivationVersion(1), DerivationVersion(2));
}

// --- PartialOrd / Ord ---

#[test]
fn derivation_version_ord() {
    assert!(DerivationVersion(1) < DerivationVersion(2));
    assert!(DerivationVersion(3) > DerivationVersion(2));
}

#[test]
fn derivation_version_sort() {
    let mut versions = vec![
        DerivationVersion(3),
        DerivationVersion(1),
        DerivationVersion(2),
    ];
    versions.sort();
    assert_eq!(
        versions,
        vec![
            DerivationVersion(1),
            DerivationVersion(2),
            DerivationVersion(3),
        ]
    );
}

// --- Hash ---

#[test]
fn derivation_version_hash_consistent() {
    let a = DerivationVersion(1);
    let b = DerivationVersion(1);
    assert_eq!(hash_of(&a), hash_of(&b));
}

#[test]
fn derivation_version_hash_differs() {
    let a = DerivationVersion(1);
    let b = DerivationVersion(2);
    assert_ne!(hash_of(&a), hash_of(&b));
}

// --- Debug ---

#[test]
fn derivation_version_debug_contains_type_name() {
    let debug = format!("{:?}", DerivationVersion::V1);
    assert!(debug.contains("DerivationVersion"));
}

#[test]
fn derivation_version_debug_contains_value() {
    let debug = format!("{:?}", DerivationVersion(42));
    assert!(debug.contains("42"));
}

// ==================== ArtifactId ====================

// --- Clone ---

#[test]
fn artifact_id_clone_equals_original() {
    let id = make_id("label", "variant");
    let cloned = id.clone();
    assert_eq!(id, cloned);
}

// --- PartialEq / Eq ---

#[test]
fn artifact_id_eq_same_fields() {
    let a = make_id("label", "variant");
    let b = make_id("label", "variant");
    assert_eq!(a, b);
}

#[test]
fn artifact_id_ne_different_label() {
    let a = make_id("label-a", "variant");
    let b = make_id("label-b", "variant");
    assert_ne!(a, b);
}

#[test]
fn artifact_id_ne_different_variant() {
    let a = make_id("label", "variant-a");
    let b = make_id("label", "variant-b");
    assert_ne!(a, b);
}

#[test]
fn artifact_id_ne_different_domain() {
    let a = ArtifactId::new("domain:a", "l", b"s", "v", DerivationVersion::V1);
    let b = ArtifactId::new("domain:b", "l", b"s", "v", DerivationVersion::V1);
    assert_ne!(a, b);
}

#[test]
fn artifact_id_ne_different_spec() {
    let a = ArtifactId::new("d", "l", b"spec-a", "v", DerivationVersion::V1);
    let b = ArtifactId::new("d", "l", b"spec-b", "v", DerivationVersion::V1);
    assert_ne!(a, b);
}

#[test]
fn artifact_id_ne_different_version() {
    let a = ArtifactId::new("d", "l", b"s", "v", DerivationVersion(1));
    let b = ArtifactId::new("d", "l", b"s", "v", DerivationVersion(2));
    assert_ne!(a, b);
}

// --- Hash ---

#[test]
fn artifact_id_hash_consistent() {
    let a = make_id("label", "variant");
    let b = make_id("label", "variant");
    assert_eq!(hash_of(&a), hash_of(&b));
}

#[test]
fn artifact_id_hash_differs_for_different_ids() {
    let a = make_id("label-a", "variant");
    let b = make_id("label-b", "variant");
    assert_ne!(hash_of(&a), hash_of(&b));
}

#[test]
fn artifact_id_usable_in_hash_set() {
    let mut set = HashSet::new();
    set.insert(make_id("a", "v"));
    set.insert(make_id("a", "v")); // duplicate
    set.insert(make_id("b", "v"));
    assert_eq!(set.len(), 2);
}

// --- PartialOrd / Ord ---

#[test]
fn artifact_id_ord_by_label() {
    let a = make_id("aaa", "v");
    let b = make_id("bbb", "v");
    assert!(a < b);
}

#[test]
fn artifact_id_usable_in_btree_set() {
    let mut set = BTreeSet::new();
    set.insert(make_id("c", "v"));
    set.insert(make_id("a", "v"));
    set.insert(make_id("b", "v"));
    set.insert(make_id("a", "v")); // duplicate
    assert_eq!(set.len(), 3);

    let labels: Vec<_> = set.iter().map(|id| id.label.as_str()).collect();
    assert_eq!(labels, vec!["a", "b", "c"]);
}

// --- Debug ---

#[test]
fn artifact_id_debug_contains_fields() {
    let id = make_id("test-label", "test-variant");
    let debug = format!("{id:?}");
    assert!(debug.contains("ArtifactId"));
    assert!(debug.contains("test-label"));
    assert!(debug.contains("test-variant"));
    assert!(debug.contains("domain:test"));
}

#[test]
fn artifact_id_debug_contains_derivation_version() {
    let id = ArtifactId::new("d", "l", b"s", "v", DerivationVersion(7));
    let debug = format!("{id:?}");
    assert!(debug.contains("7"));
}
