#![forbid(unsafe_code)]

//! Random text-shape helpers shared across uselesskey fixture crates.

use rand_core::RngCore;

/// Generate a random base62 string of the requested length.
pub fn random_base62(rng: &mut impl RngCore, len: usize) -> String {
    const BASE62: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const ACCEPT_MAX: u8 = 248; // 62 * 4; accept 0..=247 for unbiased mod 62

    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];

    while out.len() < len {
        rng.fill_bytes(&mut buf);
        let before = out.len();
        for &b in &buf {
            if b < ACCEPT_MAX {
                out.push(BASE62[(b % 62) as usize] as char);
                if out.len() == len {
                    break;
                }
            }
        }

        // Progress guarantee for pathological RNGs (e.g. constant values that are always rejected).
        // Keep fallback bounded and deterministic to avoid hangs while preserving unbiased path for normal RNGs.
        if out.len() == before {
            for &b in &buf {
                out.push(BASE62[(b as usize) % 62] as char);
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
    use proptest::prelude::*;
    use rand_chacha::{ChaCha20Rng, rand_core::RngCore};
    use rand_core::SeedableRng;

    use super::random_base62;

    #[test]
    fn random_base62_length_and_charset() {
        let mut rng = ChaCha20Rng::from_seed([17u8; 32]);
        let value = random_base62(&mut rng, 64);
        assert_eq!(value.len(), 64);
        assert!(value.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn random_base62_rejects_biased_bytes() {
        struct ByteSeqRng {
            bytes: [u8; 5],
            pos: usize,
        }

        impl ByteSeqRng {
            fn next_byte(&mut self) -> u8 {
                let b = self.bytes[self.pos % self.bytes.len()];
                self.pos += 1;
                b
            }
        }

        impl RngCore for ByteSeqRng {
            fn next_u32(&mut self) -> u32 {
                u32::from_le_bytes([
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                ])
            }

            fn next_u64(&mut self) -> u64 {
                u64::from_le_bytes([
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                    self.next_byte(),
                ])
            }

            fn fill_bytes(&mut self, dst: &mut [u8]) {
                for b in dst {
                    *b = self.next_byte();
                }
            }

            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dst);
                Ok(())
            }
        }

        let mut rng = ByteSeqRng {
            bytes: [248, 249, 250, 0, 247],
            pos: 0,
        };
        let value = random_base62(&mut rng, 5);
        assert_eq!(value.len(), 5);
        assert!(value.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn random_base62_constant_rng_terminates() {
        struct ConstantRng(u8);

        impl RngCore for ConstantRng {
            fn next_u32(&mut self) -> u32 {
                u32::from_le_bytes([self.0; 4])
            }

            fn next_u64(&mut self) -> u64 {
                u64::from_le_bytes([self.0; 8])
            }

            fn fill_bytes(&mut self, dst: &mut [u8]) {
                for b in dst {
                    *b = self.0;
                }
            }

            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dst);
                Ok(())
            }
        }

        let mut rng = ConstantRng(255);
        let value = random_base62(&mut rng, 32);
        assert_eq!(value.len(), 32);
        assert!(value.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    proptest! {
        #[test]
        fn prop_random_base62_exact_length(seed in any::<[u8; 32]>(), len in 0usize..512) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let s = random_base62(&mut rng, len);
            prop_assert_eq!(s.len(), len);
        }

        #[test]
        fn prop_random_base62_valid_charset(seed in any::<[u8; 32]>(), len in 1usize..256) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let s = random_base62(&mut rng, len);
            prop_assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
        }
    }
}
