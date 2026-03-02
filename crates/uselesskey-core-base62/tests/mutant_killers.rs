//! Mutant-killing tests for base62 generation.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use uselesskey_core_base62::{BASE62_ALPHABET, random_base62};

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
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let result = random_base62(&mut rng, 0);
    assert_eq!(result, "");
}

#[test]
fn one_char_output() {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let result = random_base62(&mut rng, 1);
    assert_eq!(result.len(), 1);
    assert!(result.bytes().all(|b| BASE62_ALPHABET.contains(&b)));
}

#[test]
fn large_output_is_all_base62() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let result = random_base62(&mut rng, 1000);
    assert_eq!(result.len(), 1000);
    for ch in result.bytes() {
        assert!(BASE62_ALPHABET.contains(&ch), "non-base62 byte: {ch:#04x}");
    }
}

#[test]
fn fallback_path_maps_all_255_bytes() {
    // A constant-255 RNG forces fallback path (255 >= 248 = ACCEPT_MAX)
    struct Const255;
    impl RngCore for Const255 {
        fn next_u32(&mut self) -> u32 {
            0xFFFF_FFFF
        }
        fn next_u64(&mut self) -> u64 {
            0xFFFF_FFFF_FFFF_FFFF
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(255);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    let value = random_base62(&mut Const255, 10);
    assert_eq!(value.len(), 10);
    // 255 % 62 = 7 -> BASE62_ALPHABET[7] = 'H'
    assert!(
        value.chars().all(|c| c == 'H'),
        "expected all H, got {value}"
    );
}

#[test]
fn deterministic_for_same_seed() {
    let seed = [77u8; 32];
    let a = random_base62(&mut ChaCha20Rng::from_seed(seed), 50);
    let b = random_base62(&mut ChaCha20Rng::from_seed(seed), 50);
    assert_eq!(a, b);
}
