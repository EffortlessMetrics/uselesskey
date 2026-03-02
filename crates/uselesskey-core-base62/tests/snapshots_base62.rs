//! Insta snapshot tests for uselesskey-core-base62.
//!
//! Snapshot base62 token shapes and lengths — no actual random content.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use uselesskey_core_base62::{BASE62_ALPHABET, random_base62};

#[derive(Serialize)]
struct Base62Shape {
    requested_len: usize,
    actual_len: usize,
    all_base62_chars: bool,
    alphabet_size: usize,
}

#[test]
fn snapshot_base62_various_lengths() {
    let seed = [42u8; 32];
    let lengths = [0, 1, 16, 32, 64, 128];

    let results: Vec<Base62Shape> = lengths
        .iter()
        .map(|&len| {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let value = random_base62(&mut rng, len);
            Base62Shape {
                requested_len: len,
                actual_len: value.len(),
                all_base62_chars: value.bytes().all(|b| BASE62_ALPHABET.contains(&b)),
                alphabet_size: BASE62_ALPHABET.len(),
            }
        })
        .collect();

    insta::assert_yaml_snapshot!("base62_shapes", results);
}

#[test]
fn snapshot_base62_determinism() {
    let seed = [7u8; 32];

    #[derive(Serialize)]
    struct DeterminismCheck {
        seed_byte: u8,
        length: usize,
        outputs_match: bool,
    }

    let mut rng_a = ChaCha20Rng::from_seed(seed);
    let mut rng_b = ChaCha20Rng::from_seed(seed);
    let a = random_base62(&mut rng_a, 48);
    let b = random_base62(&mut rng_b, 48);

    let result = DeterminismCheck {
        seed_byte: 7,
        length: 48,
        outputs_match: a == b,
    };

    insta::assert_yaml_snapshot!("base62_determinism", result);
}

#[test]
fn snapshot_base62_alphabet_metadata() {
    #[derive(Serialize)]
    struct AlphabetMeta {
        alphabet_len: usize,
        starts_with: char,
        ends_with: char,
        contains_uppercase: bool,
        contains_lowercase: bool,
        contains_digits: bool,
    }

    let result = AlphabetMeta {
        alphabet_len: BASE62_ALPHABET.len(),
        starts_with: BASE62_ALPHABET[0] as char,
        ends_with: BASE62_ALPHABET[61] as char,
        contains_uppercase: BASE62_ALPHABET.iter().any(|b| b.is_ascii_uppercase()),
        contains_lowercase: BASE62_ALPHABET.iter().any(|b| b.is_ascii_lowercase()),
        contains_digits: BASE62_ALPHABET.iter().any(|b| b.is_ascii_digit()),
    };

    insta::assert_yaml_snapshot!("base62_alphabet_metadata", result);
}
