//! Edge-case and boundary tests for base62 generation.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use uselesskey_core_base62::{BASE62_ALPHABET, random_base62};

#[test]
fn zero_length_produces_empty_string() {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
    let result = random_base62(&mut rng, 0);
    assert!(result.is_empty());
}

#[test]
fn length_one_produces_single_base62_char() {
    let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
    let result = random_base62(&mut rng, 1);
    assert_eq!(result.len(), 1);
    assert!(BASE62_ALPHABET.contains(&result.as_bytes()[0]));
}

#[test]
fn large_length_produces_correct_length() {
    let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
    let result = random_base62(&mut rng, 10_000);
    assert_eq!(result.len(), 10_000);
    assert!(result.bytes().all(|b| BASE62_ALPHABET.contains(&b)));
}

#[test]
fn different_seeds_produce_different_strings() {
    let a = random_base62(&mut ChaCha20Rng::from_seed([1u8; 32]), 64);
    let b = random_base62(&mut ChaCha20Rng::from_seed([2u8; 32]), 64);
    assert_ne!(a, b);
}

#[test]
fn same_seed_is_deterministic() {
    let seed = [42u8; 32];
    let a = random_base62(&mut ChaCha20Rng::from_seed(seed), 128);
    let b = random_base62(&mut ChaCha20Rng::from_seed(seed), 128);
    assert_eq!(a, b);
}

#[test]
fn output_contains_no_non_ascii() {
    let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
    let result = random_base62(&mut rng, 1000);
    assert!(result.is_ascii());
}

#[test]
fn base62_alphabet_has_62_chars() {
    assert_eq!(BASE62_ALPHABET.len(), 62);
}

#[test]
fn base62_alphabet_is_all_alphanumeric() {
    for &b in BASE62_ALPHABET.iter() {
        assert!(
            (b as char).is_ascii_alphanumeric(),
            "non-alphanumeric byte in alphabet: {b}"
        );
    }
}
