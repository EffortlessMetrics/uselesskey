#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
//! Seed parsing and redaction primitives for uselesskey.
//!
//! Provides the [`Seed`] type that wraps 32 bytes of entropy used for
//! deterministic fixture derivation. Implements `Debug` with redaction
//! to prevent accidental leakage of seed material in logs.

extern crate alloc;

use alloc::string::String;
use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};

/// Seed bytes derived from user input for deterministic fixtures.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct Seed(pub(crate) [u8; 32]);

impl Seed {
    /// Create a seed from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Access raw seed bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive a seed from plain text.
    ///
    /// This hashes the provided text verbatim with BLAKE3. Unlike
    /// [`Seed::from_env_value`], it does not trim whitespace or interpret
    /// 64-character strings as hex.
    pub fn from_text(text: &str) -> Self {
        Self(*blake3::hash(text.as_bytes()).as_bytes())
    }

    /// Fill the destination buffer with deterministic bytes derived from this seed.
    ///
    /// This keeps RNG implementation details private while allowing callers to
    /// derive stable byte sequences from seed material.
    pub fn fill_bytes(&self, dest: &mut [u8]) {
        let mut rng = ChaCha20Rng::from_seed(self.0);
        rng.fill_bytes(dest);
    }

    /// Derive a seed from a user-provided string.
    ///
    /// Accepted formats:
    /// - 64-char hex (with optional `0x` prefix)
    /// - any other string (hashed with BLAKE3)
    pub fn from_env_value(value: &str) -> Result<Self, String> {
        let v = value.trim();
        let hex = v
            .strip_prefix("0x")
            .or_else(|| v.strip_prefix("0X"))
            .unwrap_or(v);

        if hex.len() == 64 {
            return parse_hex_32(hex).map(Self);
        }

        Ok(Self::from_text(v))
    }
}

impl core::fmt::Debug for Seed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Seed(**redacted**)")
    }
}

fn parse_hex_32(hex: &str) -> Result<[u8; 32], String> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    if hex.len() != 64 {
        return Err(alloc::format!("expected 64 hex chars, got {}", hex.len()));
    }

    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];

    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = val(chunk[0])
            .ok_or_else(|| alloc::format!("invalid hex char: {}", chunk[0] as char))?;
        let lo = val(chunk[1])
            .ok_or_else(|| alloc::format!("invalid hex char: {}", chunk[1] as char))?;
        out[i] = (hi << 4) | lo;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{Seed, parse_hex_32};

    #[test]
    fn seed_debug_is_redacted() {
        let seed = Seed::new([7u8; 32]);
        assert_eq!(format!("{:?}", seed), "Seed(**redacted**)");
    }

    #[test]
    fn parse_hex_32_rejects_wrong_length() {
        let err = parse_hex_32("abcd").unwrap_err();
        assert!(err.contains("expected 64 hex chars"));
    }

    #[test]
    fn parse_hex_32_rejects_invalid_char() {
        let mut s = "0".repeat(64);
        s.replace_range(10..11, "g");

        let err = parse_hex_32(&s).unwrap_err();
        assert!(err.contains("invalid hex char"));
    }

    #[test]
    fn seed_from_env_value_parses_hex_with_prefix_and_whitespace() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let seed = Seed::from_env_value(&format!("  {hex}  ")).unwrap();
        assert_eq!(seed.bytes()[31], 1);
        assert!(seed.bytes()[..31].iter().all(|b| *b == 0));
    }

    #[test]
    fn seed_from_env_value_parses_uppercase_hex() {
        let hex = "F".repeat(64);
        let seed = Seed::from_env_value(&hex).unwrap();
        assert!(seed.bytes().iter().all(|b| *b == 0xFF));
    }

    #[test]
    fn seed_from_env_value_parses_hex_with_uppercase_prefix() {
        let hex = format!("0X{}", "ab".repeat(32));
        let seed = Seed::from_env_value(&hex).unwrap();
        assert!(seed.bytes().iter().all(|b| *b == 0xAB));
    }

    #[test]
    fn string_seed_is_hashed_with_blake3() {
        let seed = Seed::from_env_value("  deterministic-seed-value  ").unwrap();
        let expected = blake3::hash("deterministic-seed-value".as_bytes());
        assert_eq!(seed.bytes(), expected.as_bytes());
    }

    #[test]
    fn from_text_hashes_verbatim_input() {
        let text = "  deterministic-seed-value  ";
        let seed = Seed::from_text(text);
        let expected = blake3::hash(text.as_bytes());
        assert_eq!(seed.bytes(), expected.as_bytes());
        assert_ne!(seed, Seed::from_env_value(text).unwrap());
    }

    #[test]
    fn from_text_does_not_parse_hex_shaped_strings() {
        let text = "ab".repeat(32);
        let seed = Seed::from_text(&text);
        let expected = blake3::hash(text.as_bytes());
        assert_eq!(seed.bytes(), expected.as_bytes());
        assert_ne!(seed, Seed::from_env_value(&text).unwrap());
    }

    #[test]
    fn parse_hex_32_lowercase_valid() {
        let hex = "aa".repeat(32);
        let result = parse_hex_32(&hex).unwrap();
        assert!(result.iter().all(|b| *b == 0xAA));
    }

    #[test]
    fn parse_hex_32_mixed_case_valid() {
        let hex = "aAbBcCdDeEfF".repeat(5);
        // 60 chars — pad to 64
        let hex = format!("{hex}0000");
        assert_eq!(hex.len(), 64);
        assert!(parse_hex_32(&hex).is_ok());
    }

    #[test]
    fn parse_hex_32_invalid_lo_nibble() {
        // Valid hi nibble, invalid lo nibble at position 1
        let mut hex = "0".repeat(64);
        hex.replace_range(1..2, "z");
        let err = parse_hex_32(&hex).unwrap_err();
        assert!(err.contains("invalid hex char: z"));
    }

    #[test]
    fn seed_equality_and_clone() {
        let a = Seed::new([42u8; 32]);
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a.bytes(), b.bytes());
    }

    #[test]
    fn seed_inequality() {
        let a = Seed::new([1u8; 32]);
        let b = Seed::new([2u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn seed_hash_consistent() {
        use core::hash::{Hash, Hasher};
        let seed = Seed::new([99u8; 32]);

        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        seed.hash(&mut h1);
        let hash1 = h1.finish();

        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        seed.hash(&mut h2);
        assert_eq!(hash1, h2.finish());
    }

    #[test]
    fn fill_bytes_is_seed_stable() {
        let seed = Seed::new([7u8; 32]);
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];

        seed.fill_bytes(&mut a);
        seed.fill_bytes(&mut b);

        assert_eq!(a, b);
    }

    #[test]
    fn fill_bytes_overwrites_destination_buffer() {
        let seed = Seed::new([7u8; 32]);
        let mut out = [0xAA; 16];

        seed.fill_bytes(&mut out);

        assert_ne!(out, [0xAA; 16]);
    }

    #[test]
    fn from_env_value_short_string_uses_blake3() {
        let seed = Seed::from_env_value("abc").unwrap();
        let expected = blake3::hash(b"abc");
        assert_eq!(seed.bytes(), expected.as_bytes());
    }

    #[test]
    fn from_env_value_63_char_non_hex_uses_blake3() {
        // 63 chars — not 64, so falls through to blake3 hashing.
        let input = "a".repeat(63);
        let seed = Seed::from_env_value(&input).unwrap();
        let expected = blake3::hash(input.as_bytes());
        assert_eq!(seed.bytes(), expected.as_bytes());
    }

    #[test]
    fn from_env_value_65_char_non_hex_uses_blake3() {
        // 65 chars — not 64, so falls through to blake3 hashing.
        let input = "a".repeat(65);
        let seed = Seed::from_env_value(&input).unwrap();
        let expected = blake3::hash(input.as_bytes());
        assert_eq!(seed.bytes(), expected.as_bytes());
    }

    #[test]
    fn from_env_value_64_char_invalid_hex_returns_error() {
        // 64 chars but not valid hex — parse_hex_32 error path.
        let input = "g".repeat(64);
        assert!(Seed::from_env_value(&input).is_err());
    }
}
