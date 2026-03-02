#![forbid(unsafe_code)]

//! Base62 generation primitives for test fixtures.
//!
//! Provides deterministic, RNG-driven generation of base62 strings without
//! modulo bias under normal RNG behavior. Used internally by token fixture
//! crates to produce realistic-looking API keys and bearer tokens.
//!
//! # Examples
//!
//! ```
//! use rand_chacha::ChaCha20Rng;
//! use rand_core::SeedableRng;
//! use uselesskey_core_base62::random_base62;
//!
//! let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
//! let value = random_base62(&mut rng, 24);
//! assert_eq!(value.len(), 24);
//! assert!(value.chars().all(|c| c.is_ascii_alphanumeric()));
//! ```
//!
//! # This is a test utility
//!
//! This crate is part of the [uselesskey](https://crates.io/crates/uselesskey)
//! test-fixture ecosystem. It is **not** intended for production use.

use rand_core::RngCore;

/// Base62 alphabet used by fixture generators.
pub const BASE62_ALPHABET: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const ACCEPT_MAX: u8 = 248; // 62 * 4; accept 0..=247 for unbiased mod 62

/// Generate a random base62 string of the requested length.
///
/// Uses rejection sampling to avoid modulo bias for normal RNG outputs.
/// Includes a deterministic bounded fallback path to avoid hangs with
/// pathological RNGs that never emit acceptable bytes.
pub fn random_base62(rng: &mut impl RngCore, len: usize) -> String {
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];

    while out.len() < len {
        rng.fill_bytes(&mut buf);
        let before = out.len();

        for &b in &buf {
            if b < ACCEPT_MAX {
                out.push(BASE62_ALPHABET[(b % 62) as usize] as char);
                if out.len() == len {
                    break;
                }
            }
        }

        if out.len() == before {
            for &b in &buf {
                out.push(BASE62_ALPHABET[(b as usize) % 62] as char);
                if out.len() == len {
                    break;
                }
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::{BASE62_ALPHABET, random_base62};
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    #[test]
    fn generates_requested_length() {
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        assert_eq!(random_base62(&mut rng, 0).len(), 0);
        assert_eq!(random_base62(&mut rng, 73).len(), 73);
    }

    #[test]
    fn uses_only_base62_chars() {
        let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
        let value = random_base62(&mut rng, 256);
        assert!(value.bytes().all(|b| BASE62_ALPHABET.contains(&b)));
    }

    #[test]
    fn deterministic_for_seeded_rng() {
        let seed = [7u8; 32];
        let a = random_base62(&mut ChaCha20Rng::from_seed(seed), 96);
        let b = random_base62(&mut ChaCha20Rng::from_seed(seed), 96);
        assert_eq!(a, b);
    }

    #[test]
    fn fallback_path_terminates_for_constant_rng() {
        struct ConstantRng;

        impl RngCore for ConstantRng {
            fn next_u32(&mut self) -> u32 {
                u32::from_le_bytes([255, 255, 255, 255])
            }

            fn next_u64(&mut self) -> u64 {
                u64::from_le_bytes([255, 255, 255, 255, 255, 255, 255, 255])
            }

            fn fill_bytes(&mut self, dest: &mut [u8]) {
                dest.fill(255);
            }

            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }

        let mut rng = ConstantRng;
        let value = random_base62(&mut rng, 32);
        assert_eq!(value.len(), 32);
        assert!(value.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
