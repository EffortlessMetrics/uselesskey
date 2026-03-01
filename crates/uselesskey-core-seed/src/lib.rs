#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
//! Seed parsing and redaction primitives for uselesskey.
//!
//! Provides the [`Seed`] type that wraps 32 bytes of entropy used for
//! deterministic fixture derivation. Implements `Debug` with redaction
//! to prevent accidental leakage of seed material in logs.

extern crate alloc;

use alloc::string::String;

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

    /// Derive a seed from a user-provided string.
    ///
    /// Accepted formats:
    /// - 64-char hex (with optional `0x` prefix)
    /// - any other string (hashed with BLAKE3)
    pub fn from_env_value(value: &str) -> Result<Self, String> {
        let v = value.trim();
        let hex = v.strip_prefix("0x").unwrap_or(v);

        if hex.len() == 64 {
            return parse_hex_32(hex).map(Self);
        }

        Ok(Self(*blake3::hash(v.as_bytes()).as_bytes()))
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
    fn string_seed_is_hashed_with_blake3() {
        let seed = Seed::from_env_value("  deterministic-seed-value  ").unwrap();
        let expected = blake3::hash("deterministic-seed-value".as_bytes());
        assert_eq!(seed.bytes(), expected.as_bytes());
    }
}
