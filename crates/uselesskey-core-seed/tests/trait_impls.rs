//! Tests for derived and manually-implemented traits on the `Seed` type.

use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use uselesskey_core_seed::Seed;

fn hash_of<T: Hash>(val: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    val.hash(&mut hasher);
    hasher.finish()
}

// --- Clone (via Copy — Seed is Copy, so clone is implicit) ---

#[test]
fn seed_clone_is_available() {
    let seed = Seed::new([1u8; 32]);
    // Seed is Copy, so clone is redundant but the trait is still derived.
    let cloned: Seed = Clone::clone(&seed);
    assert_eq!(seed, cloned);
}

#[test]
fn seed_copy_produces_equal_value() {
    let seed = Seed::new([2u8; 32]);
    let copied = seed;
    // Original is still usable because Seed is Copy.
    assert_eq!(seed, copied);
}

// --- PartialEq / Eq ---

#[test]
fn seed_eq_reflexive() {
    let seed = Seed::new([3u8; 32]);
    assert_eq!(seed, seed);
}

#[test]
fn seed_eq_same_bytes() {
    let a = Seed::new([3u8; 32]);
    let b = Seed::new([3u8; 32]);
    assert_eq!(a, b);
}

#[test]
fn seed_ne_different_bytes() {
    let a = Seed::new([3u8; 32]);
    let b = Seed::new([4u8; 32]);
    assert_ne!(a, b);
}

#[test]
fn seed_eq_symmetric() {
    let a = Seed::new([5u8; 32]);
    let b = Seed::new([5u8; 32]);
    assert_eq!(a, b);
    assert_eq!(b, a);
}

// --- Hash ---

#[test]
fn seed_hash_consistent_for_equal_values() {
    let a = Seed::new([5u8; 32]);
    let b = Seed::new([5u8; 32]);
    assert_eq!(hash_of(&a), hash_of(&b));
}

#[test]
fn seed_hash_differs_for_different_values() {
    let a = Seed::new([5u8; 32]);
    let b = Seed::new([6u8; 32]);
    assert_ne!(hash_of(&a), hash_of(&b));
}

#[test]
fn seed_usable_in_hash_set() {
    let mut set = HashSet::new();
    set.insert(Seed::new([7u8; 32]));
    set.insert(Seed::new([7u8; 32])); // duplicate
    set.insert(Seed::new([8u8; 32]));
    assert_eq!(set.len(), 2);
}

// --- Debug (redaction) ---

#[test]
fn seed_debug_does_not_leak_raw_bytes() {
    let seed = Seed::new([0xAB; 32]);
    let debug = format!("{seed:?}");
    // Must not contain hex representation of the byte 0xAB
    assert!(!debug.contains("ab"), "Debug must not leak hex bytes");
    assert!(!debug.contains("AB"), "Debug must not leak hex bytes");
    assert!(
        !debug.contains("171"),
        "Debug must not leak decimal byte values"
    );
}

#[test]
fn seed_debug_mentions_redaction() {
    let seed = Seed::new([0u8; 32]);
    let debug = format!("{seed:?}");
    assert!(
        debug.contains("redacted"),
        "Debug output should mention redaction"
    );
}

#[test]
fn seed_debug_stable_across_different_values() {
    let a = format!("{:?}", Seed::new([0u8; 32]));
    let b = format!("{:?}", Seed::new([0xFF; 32]));
    assert_eq!(a, b, "Debug output must not vary with seed contents");
}

// --- Display not implemented (compile-time guarantee via negative reasoning) ---
// Seed intentionally does not implement Display to prevent accidental leakage.
// We verify Debug is the only formatting trait by checking the redacted output.

#[test]
fn seed_from_env_value_preserves_traits() {
    let seed = Seed::from_env_value("test-passphrase").unwrap();
    let cloned = seed;
    assert_eq!(hash_of(&seed), hash_of(&cloned));
}
