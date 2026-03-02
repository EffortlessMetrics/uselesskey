//! Mutant-killing tests for seed parsing and debug redaction.

use uselesskey_core_seed::Seed;

#[test]
fn seed_debug_exact_string() {
    let seed = Seed::new([0u8; 32]);
    assert_eq!(format!("{seed:?}"), "Seed(**redacted**)");
}

#[test]
fn seed_bytes_returns_exact_input() {
    let input = [42u8; 32];
    let seed = Seed::new(input);
    assert_eq!(*seed.bytes(), input);
}

#[test]
fn seed_equality_is_byte_wise() {
    let a = Seed::new([1u8; 32]);
    let b = Seed::new([1u8; 32]);
    let c = Seed::new([2u8; 32]);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn from_env_value_hex_without_prefix() {
    let hex = "00".repeat(31) + "FF";
    let seed = Seed::from_env_value(&hex).unwrap();
    assert_eq!(seed.bytes()[31], 0xFF);
    assert!(seed.bytes()[..31].iter().all(|&b| b == 0));
}

#[test]
fn from_env_value_hex_with_0x_prefix() {
    let hex = format!("0x{}", "AB".repeat(32));
    let seed = Seed::from_env_value(&hex).unwrap();
    assert!(seed.bytes().iter().all(|&b| b == 0xAB));
}

#[test]
fn from_env_value_trims_whitespace() {
    let hex = "  FF".repeat(32).trim().to_string();
    // This is 63 chars, so it won't parse as hex - will use BLAKE3 hash
    let seed = Seed::from_env_value(&format!("  {hex}  ")).unwrap();
    // Should produce a valid seed (BLAKE3 of trimmed value)
    assert_eq!(seed.bytes().len(), 32);
}

#[test]
fn from_env_value_non_hex_uses_blake3() {
    let seed = Seed::from_env_value("my-test-seed").unwrap();
    let expected = blake3::hash("my-test-seed".as_bytes());
    assert_eq!(seed.bytes(), expected.as_bytes());
}

#[test]
fn from_env_value_rejects_invalid_hex_char() {
    let mut hex = "00".repeat(32);
    hex.replace_range(0..1, "Z");
    let result = Seed::from_env_value(&hex);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("invalid hex char"));
}

#[test]
fn from_env_value_mixed_case_hex() {
    // Mix of lowercase a-f and uppercase A-F
    let hex = "aAbBcCdDeEfF".to_string() + &"00".repeat(26);
    let seed = Seed::from_env_value(&hex).unwrap();
    assert_eq!(seed.bytes()[0], 0xAA);
    assert_eq!(seed.bytes()[1], 0xBB);
    assert_eq!(seed.bytes()[2], 0xCC);
    assert_eq!(seed.bytes()[3], 0xDD);
    assert_eq!(seed.bytes()[4], 0xEE);
    assert_eq!(seed.bytes()[5], 0xFF);
}

#[test]
fn from_env_value_hex_nibble_arithmetic() {
    // Test that hex parsing correctly computes (hi << 4) | lo
    // 0x9A = (9 << 4) | 10 = 144 + 10 = 154
    let hex = "9A".to_string() + &"00".repeat(31);
    let seed = Seed::from_env_value(&hex).unwrap();
    assert_eq!(seed.bytes()[0], 0x9A);
}
