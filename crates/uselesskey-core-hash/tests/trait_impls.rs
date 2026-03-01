//! Tests for trait implementations on the re-exported `blake3::Hash` type.
//!
//! The `uselesskey-core-hash` crate re-exports `blake3::Hash` as its primary
//! output type. These tests verify the expected trait impls are available
//! through the re-export.

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher as StdHasher;

use uselesskey_core_hash::{Hash as Blake3Hash, hash32};

fn std_hash_of(val: &Blake3Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    // blake3::Hash implements std::hash::Hash
    std::hash::Hash::hash(val, &mut hasher);
    hasher.finish()
}

// --- Clone (via Copy) ---

#[test]
fn hash_clone_is_available() {
    let h = hash32(b"test");
    let cloned: Blake3Hash = Clone::clone(&h);
    assert_eq!(h, cloned);
}

#[test]
fn hash_copy_produces_equal_value() {
    let h = hash32(b"test");
    let copied = h;
    // Original still usable because blake3::Hash is Copy.
    assert_eq!(h, copied);
}

// --- PartialEq / Eq ---

#[test]
fn hash_eq_same_input() {
    let a = hash32(b"test");
    let b = hash32(b"test");
    assert_eq!(a, b);
}

#[test]
fn hash_ne_different_input() {
    let a = hash32(b"test-a");
    let b = hash32(b"test-b");
    assert_ne!(a, b);
}

// --- std::hash::Hash ---

#[test]
fn hash_std_hash_consistent() {
    let a = hash32(b"test");
    let b = hash32(b"test");
    assert_eq!(std_hash_of(&a), std_hash_of(&b));
}

#[test]
fn hash_std_hash_differs_for_different_values() {
    let a = hash32(b"test-a");
    let b = hash32(b"test-b");
    assert_ne!(std_hash_of(&a), std_hash_of(&b));
}

#[test]
fn hash_usable_in_hash_set() {
    let mut set = HashSet::new();
    set.insert(hash32(b"a"));
    set.insert(hash32(b"a")); // duplicate
    set.insert(hash32(b"b"));
    assert_eq!(set.len(), 2);
}

// --- Debug / Display ---

#[test]
fn hash_debug_is_nonempty() {
    let h = hash32(b"test");
    let debug = format!("{h:?}");
    assert!(!debug.is_empty());
}

#[test]
fn hash_display_is_hex() {
    let h = hash32(b"test");
    let display = format!("{h}");
    // blake3::Hash Display outputs 64 lowercase hex characters.
    assert_eq!(display.len(), 64);
    assert!(
        display.chars().all(|c| c.is_ascii_hexdigit()),
        "Display should be hex: {display}"
    );
}

#[test]
fn hash_as_bytes_roundtrip() {
    let h = hash32(b"test");
    let bytes = h.as_bytes();
    assert_eq!(bytes.len(), 32);
    // Reconstruct and verify equality
    let reconstructed = Blake3Hash::from_bytes(*bytes);
    assert_eq!(h, reconstructed);
}
