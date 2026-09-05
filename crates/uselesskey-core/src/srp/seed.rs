//! Seed parsing and redaction primitives for uselesskey.
//!
//! Provides the [`Seed`] type that wraps 32 bytes of entropy used for
//! deterministic fixture derivation. Implements `Debug` with redaction
//! to prevent accidental leakage of seed material in logs.

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

        if let Some(hex) = hex_seed_candidate(v) {
            return parse_hex_32(hex).map(Self);
        }

        Ok(Self::from_text(v))
    }
}

fn hex_seed_candidate(value: &str) -> Option<&str> {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);

    (hex.len() == 64).then_some(hex)
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

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::{Seed, parse_hex_32};
    use uselesskey_test_support::{TestResult, ensure, ensure_eq, require_ok, require_some};

    #[test]
    fn seed_debug_is_redacted() -> TestResult<()> {
        let seed = Seed::new([7u8; 32]);
        ensure_eq!(format!("{:?}", seed), "Seed(**redacted**)");
        Ok(())
    }

    #[test]
    fn parse_hex_32_rejects_wrong_length() -> TestResult<()> {
        let err = require_some(parse_hex_32("abcd").err(), "short hex must fail")?;
        ensure!(err.contains("expected 64 hex chars"));
        Ok(())
    }

    #[test]
    fn parse_hex_32_rejects_invalid_char() -> TestResult<()> {
        let mut s = "0".repeat(64);
        s.replace_range(10..11, "g");

        let err = require_some(parse_hex_32(&s).err(), "invalid high nibble must fail")?;
        ensure!(err.contains("invalid hex char"));
        Ok(())
    }

    #[test]
    fn seed_from_env_value_parses_hex_with_prefix_and_whitespace() -> TestResult<()> {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let seed = require_ok(Seed::from_env_value(&format!("  {hex}  ")), "prefixed hex")?;
        ensure_eq!(seed.bytes()[31], 1);
        ensure!(seed.bytes()[..31].iter().all(|b| *b == 0));
        Ok(())
    }

    #[test]
    fn seed_from_env_value_parses_uppercase_0x_prefix() -> TestResult<()> {
        let hex = "0X0000000000000000000000000000000000000000000000000000000000000001";
        let seed = require_ok(Seed::from_env_value(hex), "uppercase prefix")?;
        ensure_eq!(seed.bytes()[31], 1);
        ensure!(seed.bytes()[..31].iter().all(|b| *b == 0));
        Ok(())
    }

    #[test]
    fn seed_from_env_value_parses_uppercase_hex() -> TestResult<()> {
        let hex = "F".repeat(64);
        let seed = require_ok(Seed::from_env_value(&hex), "uppercase hex")?;
        ensure!(seed.bytes().iter().all(|b| *b == 0xFF));
        Ok(())
    }

    #[test]
    fn string_seed_is_hashed_with_blake3() -> TestResult<()> {
        let seed = require_ok(
            Seed::from_env_value("  deterministic-seed-value  "),
            "trimmed text seed",
        )?;
        let expected = blake3::hash("deterministic-seed-value".as_bytes());
        ensure_eq!(seed.bytes(), expected.as_bytes());
        Ok(())
    }

    #[test]
    fn from_text_hashes_verbatim_input() -> TestResult<()> {
        let text = "  deterministic-seed-value  ";
        let seed = Seed::from_text(text);
        let expected = blake3::hash(text.as_bytes());
        ensure_eq!(seed.bytes(), expected.as_bytes());
        let env_seed = require_ok(Seed::from_env_value(text), "trimmed text seed")?;
        ensure!(seed != env_seed);
        Ok(())
    }

    #[test]
    fn from_text_does_not_parse_hex_shaped_strings() -> TestResult<()> {
        let text = "ab".repeat(32);
        let seed = Seed::from_text(&text);
        let expected = blake3::hash(text.as_bytes());
        ensure_eq!(seed.bytes(), expected.as_bytes());
        let env_seed = require_ok(Seed::from_env_value(&text), "hex seed")?;
        ensure!(seed != env_seed);
        Ok(())
    }

    #[test]
    fn parse_hex_32_lowercase_valid() -> TestResult<()> {
        let hex = "aa".repeat(32);
        let result = require_ok(parse_hex_32(&hex), "lowercase hex")?;
        ensure!(result.iter().all(|b| *b == 0xAA));
        Ok(())
    }

    #[test]
    fn parse_hex_32_mixed_case_valid() -> TestResult<()> {
        let hex = "aAbBcCdDeEfF".repeat(5);
        // 60 chars — pad to 64
        let hex = format!("{hex}0000");
        ensure_eq!(hex.len(), 64);
        ensure!(parse_hex_32(&hex).is_ok());
        Ok(())
    }

    #[test]
    fn parse_hex_32_invalid_lo_nibble() -> TestResult<()> {
        // Valid hi nibble, invalid lo nibble at position 1
        let mut hex = "0".repeat(64);
        hex.replace_range(1..2, "z");
        let err = require_some(parse_hex_32(&hex).err(), "invalid low nibble must fail")?;
        ensure!(err.contains("invalid hex char: z"));
        Ok(())
    }

    #[test]
    fn seed_equality_and_clone() -> TestResult<()> {
        let a = Seed::new([42u8; 32]);
        let b = a;
        ensure_eq!(a, b);
        ensure_eq!(a.bytes(), b.bytes());
        Ok(())
    }

    #[test]
    fn seed_inequality() -> TestResult<()> {
        let a = Seed::new([1u8; 32]);
        let b = Seed::new([2u8; 32]);
        ensure!(a != b);
        Ok(())
    }

    #[test]
    fn seed_hash_consistent() -> TestResult<()> {
        use core::hash::{Hash, Hasher};
        let seed = Seed::new([99u8; 32]);

        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        seed.hash(&mut h1);
        let hash1 = h1.finish();

        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        seed.hash(&mut h2);
        ensure_eq!(hash1, h2.finish());
        Ok(())
    }

    #[test]
    fn fill_bytes_is_seed_stable() -> TestResult<()> {
        let seed = Seed::new([7u8; 32]);
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];

        seed.fill_bytes(&mut a);
        seed.fill_bytes(&mut b);

        ensure_eq!(a, b);
        Ok(())
    }

    #[test]
    fn fill_bytes_overwrites_destination_buffer() -> TestResult<()> {
        let seed = Seed::new([7u8; 32]);
        let mut out = [0xAA; 16];

        seed.fill_bytes(&mut out);

        ensure!(out != [0xAA; 16]);
        Ok(())
    }

    #[test]
    fn from_env_value_short_string_uses_blake3() -> TestResult<()> {
        let seed = require_ok(Seed::from_env_value("abc"), "short text seed")?;
        let expected = blake3::hash(b"abc");
        ensure_eq!(seed.bytes(), expected.as_bytes());
        Ok(())
    }

    #[test]
    fn from_env_value_63_char_non_hex_uses_blake3() -> TestResult<()> {
        // 63 chars — not 64, so falls through to blake3 hashing.
        let input = "a".repeat(63);
        let seed = require_ok(Seed::from_env_value(&input), "non-hex-length text seed")?;
        let expected = blake3::hash(input.as_bytes());
        ensure_eq!(seed.bytes(), expected.as_bytes());
        Ok(())
    }

    #[test]
    fn from_env_value_65_char_non_hex_uses_blake3() -> TestResult<()> {
        // 65 chars — not 64, so falls through to blake3 hashing.
        let input = "a".repeat(65);
        let seed = require_ok(Seed::from_env_value(&input), "non-hex-length text seed")?;
        let expected = blake3::hash(input.as_bytes());
        ensure_eq!(seed.bytes(), expected.as_bytes());
        Ok(())
    }

    #[test]
    fn from_env_value_short_0x_prefixed_string_hashes_original_input() -> TestResult<()> {
        let input = "0xabc";
        let seed = require_ok(Seed::from_env_value(input), "short prefixed text seed")?;
        let expected = blake3::hash(input.as_bytes());
        ensure_eq!(seed.bytes(), expected.as_bytes());
        Ok(())
    }

    #[test]
    fn from_env_value_invalid_length_0x_prefixed_hex_hashes_original_input() -> TestResult<()> {
        let input = format!("0x{}", "a".repeat(63));
        let seed = require_ok(Seed::from_env_value(&input), "prefixed text seed")?;
        let expected = blake3::hash(input.as_bytes());
        ensure_eq!(seed.bytes(), expected.as_bytes());
        Ok(())
    }

    #[test]
    fn from_env_value_64_char_invalid_hex_returns_error() -> TestResult<()> {
        // 64 chars but not valid hex — parse_hex_32 error path.
        let input = "g".repeat(64);
        ensure!(Seed::from_env_value(&input).is_err());
        Ok(())
    }

    #[test]
    fn parse_hex_32_rejects_invalid_nibbles_at_every_position() -> TestResult<()> {
        for position in 0..64 {
            let mut hex = "0".repeat(64);
            hex.replace_range(position..position + 1, "g");
            let err = require_some(
                parse_hex_32(&hex).err(),
                format!("invalid nibble at position {position} must fail"),
            )?;
            ensure_eq!(err, "invalid hex char: g", "position {position}");
        }
        Ok(())
    }

    #[test]
    fn from_env_value_prefixed_invalid_hex_returns_error() -> TestResult<()> {
        for prefix in ["0x", "0X"] {
            let input = format!("  {prefix}{}g  ", "0".repeat(63));
            let err = require_some(
                Seed::from_env_value(&input).err(),
                "prefixed invalid hex must not fall back to hashing",
            )?;
            ensure_eq!(err, "invalid hex char: g");
        }
        Ok(())
    }

    #[test]
    fn from_env_value_64_byte_non_ascii_input_returns_error() -> TestResult<()> {
        // Dispatch is byte-length based. Non-ASCII bytes must be rejected as
        // invalid hex, not sliced at a UTF-8 boundary or silently hashed.
        let input = "é".repeat(32);
        ensure_eq!(input.len(), 64);
        let err = require_some(
            Seed::from_env_value(&input).err(),
            "64-byte non-ASCII input must fail hex parsing",
        )?;
        ensure!(err.starts_with("invalid hex char:"));
        Ok(())
    }

    #[test]
    fn from_env_value_whitespace_only_hashes_empty_text() -> TestResult<()> {
        let input = " \t\n ";
        let seed = require_ok(Seed::from_env_value(input), "whitespace-only text seed")?;
        ensure_eq!(seed.bytes(), blake3::hash(b"").as_bytes());
        ensure!(seed != Seed::from_text(input));
        Ok(())
    }
}
