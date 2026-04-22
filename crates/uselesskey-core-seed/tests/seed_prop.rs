#![cfg(feature = "std")]

use proptest::prelude::*;

use uselesskey_core_seed::Seed;

proptest! {
    /// Seed::from_env_value() handles arbitrary strings without panicking.
    #[test]
    fn seed_from_env_value_handles_arbitrary_strings(s in ".*") {
        let _ = Seed::from_env_value(&s);
    }

    /// Non-hex lengths always hash and succeed.
    #[test]
    fn seed_from_env_value_non_64_lengths_are_ok(s in "[a-zA-Z0-9!@#$%^&*()]{0,63}|[a-zA-Z0-9!@#$%^&*()]{65,200}") {
        let trimmed = s.trim();
        let after_prefix = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        prop_assume!(after_prefix.len() != 64);
        prop_assert!(Seed::from_env_value(&s).is_ok());
    }

    /// Valid 64-char hex parses to the exact 32-byte value.
    #[test]
    fn seed_from_env_value_valid_hex_roundtrips(hex_bytes in any::<[u8; 32]>()) {
        let hex: String = hex_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let parsed = Seed::from_env_value(&hex).unwrap();
        prop_assert_eq!(parsed.bytes(), &hex_bytes);
    }

    /// Optional 0x prefix remains valid.
    #[test]
    fn seed_from_env_value_valid_hex_with_prefix_roundtrips(hex_bytes in any::<[u8; 32]>()) {
        let hex = format!(
            "0x{}",
            hex_bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
        let parsed = Seed::from_env_value(&hex).unwrap();
        prop_assert_eq!(parsed.bytes(), &hex_bytes);
    }

    /// Optional uppercase 0X prefix remains valid.
    #[test]
    fn seed_from_env_value_valid_hex_with_uppercase_prefix_roundtrips(hex_bytes in any::<[u8; 32]>()) {
        let hex = format!(
            "0X{}",
            hex_bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
        let parsed = Seed::from_env_value(&hex).unwrap();
        prop_assert_eq!(parsed.bytes(), &hex_bytes);
    }
}
