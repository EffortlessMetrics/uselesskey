#![forbid(unsafe_code)]

use rstest::rstest;
use uselesskey_core_base62::{BASE62_ALPHABET, random_base62};
use uselesskey_core_seed::Seed;

// ---------------------------------------------------------------------------
// Length correctness
// ---------------------------------------------------------------------------

#[rstest]
#[case::zero(0)]
#[case::one(1)]
#[case::small(10)]
#[case::medium(64)]
#[case::large(256)]
#[case::odd(73)]
fn output_has_exact_requested_length(#[case] len: usize) {
    assert_eq!(random_base62(Seed::new([1u8; 32]), len).len(), len);
}

// ---------------------------------------------------------------------------
// Character set
// ---------------------------------------------------------------------------

#[test]
fn output_contains_only_base62_characters() {
    let value = random_base62(Seed::new([42u8; 32]), 512);
    for ch in value.bytes() {
        assert!(
            BASE62_ALPHABET.contains(&ch),
            "unexpected byte {ch:#04x} in output"
        );
    }
}

#[test]
fn base62_alphabet_has_62_entries() {
    assert_eq!(BASE62_ALPHABET.len(), 62);
}

#[test]
fn base62_alphabet_contains_expected_ranges() {
    for b in b'A'..=b'Z' {
        assert!(BASE62_ALPHABET.contains(&b), "missing uppercase {b}");
    }
    for b in b'a'..=b'z' {
        assert!(BASE62_ALPHABET.contains(&b), "missing lowercase {b}");
    }
    for b in b'0'..=b'9' {
        assert!(BASE62_ALPHABET.contains(&b), "missing digit {b}");
    }
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn same_seed_produces_same_output() {
    let seed = [7u8; 32];
    let a = random_base62(Seed::new(seed), 128);
    let b = random_base62(Seed::new(seed), 128);
    assert_eq!(a, b);
}

#[test]
fn different_seeds_produce_different_output() {
    let a = random_base62(Seed::new([1u8; 32]), 64);
    let b = random_base62(Seed::new([2u8; 32]), 64);
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// Edge case: zero-length output is empty string
// ---------------------------------------------------------------------------

#[test]
fn zero_length_returns_empty_string() {
    let value = random_base62(Seed::new([0u8; 32]), 0);
    assert!(value.is_empty());
}
