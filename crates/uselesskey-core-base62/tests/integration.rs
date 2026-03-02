#![forbid(unsafe_code)]

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rstest::rstest;
use uselesskey_core_base62::{BASE62_ALPHABET, random_base62};

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
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    assert_eq!(random_base62(&mut rng, len).len(), len);
}

// ---------------------------------------------------------------------------
// Character set
// ---------------------------------------------------------------------------

#[test]
fn output_contains_only_base62_characters() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let value = random_base62(&mut rng, 512);
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
    let a = random_base62(&mut ChaCha20Rng::from_seed(seed), 128);
    let b = random_base62(&mut ChaCha20Rng::from_seed(seed), 128);
    assert_eq!(a, b);
}

#[test]
fn different_seeds_produce_different_output() {
    let a = random_base62(&mut ChaCha20Rng::from_seed([1u8; 32]), 64);
    let b = random_base62(&mut ChaCha20Rng::from_seed([2u8; 32]), 64);
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// Fallback path — pathological RNG that always returns 0xFF
// ---------------------------------------------------------------------------

struct ConstantHighRng;

impl RngCore for ConstantHighRng {
    fn next_u32(&mut self) -> u32 {
        u32::MAX
    }

    fn next_u64(&mut self) -> u64 {
        u64::MAX
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0xFF);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[test]
fn fallback_path_terminates_for_all_high_bytes() {
    let value = random_base62(&mut ConstantHighRng, 64);
    assert_eq!(value.len(), 64);
    assert!(value.bytes().all(|b| BASE62_ALPHABET.contains(&b)));
}

// ---------------------------------------------------------------------------
// Edge case: zero-length output is empty string
// ---------------------------------------------------------------------------

#[test]
fn zero_length_returns_empty_string() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let value = random_base62(&mut rng, 0);
    assert!(value.is_empty());
}
