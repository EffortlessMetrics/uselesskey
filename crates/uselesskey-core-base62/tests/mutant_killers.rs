//! Mutant-killing tests for base62 generation.

use uselesskey_core_base62::{BASE62_ALPHABET, random_base62};
use uselesskey_core_seed::Seed;

#[test]
fn base62_alphabet_exact_length() {
    assert_eq!(BASE62_ALPHABET.len(), 62);
}

#[test]
fn base62_alphabet_starts_with_uppercase() {
    assert_eq!(BASE62_ALPHABET[0], b'A');
    assert_eq!(BASE62_ALPHABET[25], b'Z');
}

#[test]
fn base62_alphabet_then_lowercase() {
    assert_eq!(BASE62_ALPHABET[26], b'a');
    assert_eq!(BASE62_ALPHABET[51], b'z');
}

#[test]
fn base62_alphabet_ends_with_digits() {
    assert_eq!(BASE62_ALPHABET[52], b'0');
    assert_eq!(BASE62_ALPHABET[61], b'9');
}

#[test]
fn zero_length_returns_empty() {
    let result = random_base62(Seed::new([1u8; 32]), 0);
    assert_eq!(result, "");
}

#[test]
fn one_char_output() {
    let result = random_base62(Seed::new([1u8; 32]), 1);
    assert_eq!(result.len(), 1);
    assert!(result.bytes().all(|b| BASE62_ALPHABET.contains(&b)));
}

#[test]
fn large_output_is_all_base62() {
    let result = random_base62(Seed::new([42u8; 32]), 1000);
    assert_eq!(result.len(), 1000);
    for ch in result.bytes() {
        assert!(BASE62_ALPHABET.contains(&ch), "non-base62 byte: {ch:#04x}");
    }
}

#[test]
fn deterministic_for_same_seed() {
    let seed = [77u8; 32];
    let a = random_base62(Seed::new(seed), 50);
    let b = random_base62(Seed::new(seed), 50);
    assert_eq!(a, b);
}

/// Pin the exact output for a known seed so mutations to the acceptance
/// threshold (`<` vs `==` vs `<=`) produce a different string and get caught.
#[test]
fn pinned_output_for_known_seed() {
    let seed = [99u8; 32];
    let result = random_base62(Seed::new(seed), 16);
    assert_eq!(result, "niBiKKJ5NhJuezpd");
}
