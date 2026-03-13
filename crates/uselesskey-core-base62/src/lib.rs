#![forbid(unsafe_code)]

//! Base62 generation primitives for test fixtures.
//!
//! Provides deterministic, seed-driven generation of base62 strings without
//! modulo bias under normal RNG behavior.

use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};
use uselesskey_core_seed::Seed;

/// Base62 alphabet used by fixture generators.
pub const BASE62_ALPHABET: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const ACCEPT_MAX: u8 = 248; // 62 * 4; accept 0..=247 for unbiased mod 62

/// Generate a deterministic base62 string from the provided seed.
///
/// Uses rejection sampling to avoid modulo bias for normal RNG outputs.
/// Includes a deterministic bounded fallback path to avoid hangs with
/// pathological RNGs that never emit acceptable bytes.
pub fn random_base62(seed: Seed, len: usize) -> String {
    let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
    random_base62_with_rng(&mut rng, len)
}

fn random_base62_with_rng(rng: &mut impl Rng, len: usize) -> String {
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
    use super::{BASE62_ALPHABET, random_base62, random_base62_with_rng};
    use rand_chacha10::ChaCha20Rng;
    use rand_core10::{Infallible, SeedableRng, TryRng};
    use uselesskey_core_seed::Seed;

    #[test]
    fn generates_requested_length() {
        assert_eq!(random_base62(Seed::new([1u8; 32]), 0).len(), 0);
        assert_eq!(random_base62(Seed::new([1u8; 32]), 73).len(), 73);
    }

    #[test]
    fn uses_only_base62_chars() {
        let value = random_base62(Seed::new([2u8; 32]), 256);
        assert!(value.bytes().all(|b| BASE62_ALPHABET.contains(&b)));
    }

    #[test]
    fn deterministic_for_seeded_rng() {
        let seed = [7u8; 32];
        let a = random_base62(Seed::new(seed), 96);
        let b = random_base62(Seed::new(seed), 96);
        assert_eq!(a, b);
    }

    #[test]
    fn fallback_path_terminates_for_constant_rng() {
        struct ConstantRng;

        impl TryRng for ConstantRng {
            type Error = Infallible;

            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(u32::from_le_bytes([255, 255, 255, 255]))
            }

            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(u64::from_le_bytes([255, 255, 255, 255, 255, 255, 255, 255]))
            }

            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }

        impl ConstantRng {
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                dest.fill(255);
            }
        }

        let mut rng = ConstantRng;
        let value = random_base62_with_rng(&mut rng, 32);
        assert_eq!(value.len(), 32);
        assert!(value.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn output_uses_diverse_alphabet() {
        // Catches `% 62` → `/ 62` mutation: division would yield only
        // indices 0–3, producing at most 4 distinct characters.
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let out = random_base62_with_rng(&mut rng, 256);
        let unique: std::collections::HashSet<char> = out.chars().collect();
        assert!(
            unique.len() > 10,
            "expected diverse output, got {} unique chars",
            unique.len()
        );
    }

    #[test]
    fn fallback_path_uses_modulo_not_division() {
        // All bytes = 255 → rejected by accept path → fallback runs.
        // Correct: (255 % 62) = 7 → alphabet[7] = 'H'.
        // Mutation / 62: (255 / 62) = 4 → alphabet[4] = 'E'.
        struct AllMaxRng;

        impl TryRng for AllMaxRng {
            type Error = Infallible;

            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(u32::MAX)
            }

            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(u64::MAX)
            }

            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }

        impl AllMaxRng {
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                dest.fill(255);
            }
        }

        let mut rng = AllMaxRng;
        let out = random_base62_with_rng(&mut rng, 4);
        // 255 % 62 = 7, BASE62_ALPHABET[7] = 'H'
        assert!(
            out.chars().all(|c| c == 'H'),
            "expected all 'H' from fallback, got {out}"
        );
    }
}
