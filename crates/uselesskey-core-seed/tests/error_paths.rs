//! Error path and boundary condition tests for uselesskey-core-seed.

use uselesskey_core_seed::Seed;

// =========================================================================
// Invalid hex strings
// =========================================================================

#[test]
fn from_env_value_rejects_invalid_hex_char_in_64_char_string() {
    // 64 chars but contains 'g' which is not hex
    let mut hex = "0".repeat(64);
    hex.replace_range(0..1, "g");

    let result = Seed::from_env_value(&hex);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("invalid hex char"),
        "error should describe the invalid char, got: {err}"
    );
}

#[test]
fn from_env_value_rejects_hex_prefix_with_invalid_chars() {
    let hex = format!("0x{}", "g".repeat(64));
    let result = Seed::from_env_value(&hex);
    // After stripping 0x, we have 64 'g' chars which aren't valid hex
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.contains("invalid hex char"),
        "expected 'invalid hex char' error, got: {err}"
    );
}

// =========================================================================
// Edge case: empty input is hashed (not rejected)
// =========================================================================

#[test]
fn from_env_value_empty_string_does_not_error() {
    let result = Seed::from_env_value("");
    assert!(
        result.is_ok(),
        "empty string should be hashed, not rejected"
    );
}

#[test]
fn from_env_value_whitespace_only_does_not_error() {
    let result = Seed::from_env_value("   ");
    assert!(
        result.is_ok(),
        "whitespace-only should be hashed (after trim to empty)"
    );
}

// =========================================================================
// Boundary: exactly 64 hex chars
// =========================================================================

#[test]
fn from_env_value_63_hex_chars_is_hashed_not_parsed() {
    // 63 chars: not valid as hex seed, so it gets BLAKE3-hashed
    let hex63 = "a".repeat(63);
    let hashed = Seed::from_env_value(&hex63).unwrap();
    let expected = blake3::hash(hex63.as_bytes());
    assert_eq!(hashed.bytes(), expected.as_bytes());
}

#[test]
fn from_env_value_65_hex_chars_is_hashed_not_parsed() {
    // 65 chars: too long for hex parse, so it gets BLAKE3-hashed
    let hex65 = "a".repeat(65);
    let hashed = Seed::from_env_value(&hex65).unwrap();
    let expected = blake3::hash(hex65.as_bytes());
    assert_eq!(hashed.bytes(), expected.as_bytes());
}

#[test]
fn from_env_value_exactly_64_valid_hex_is_parsed() {
    let hex = "ff".repeat(32);
    assert_eq!(hex.len(), 64);
    let seed = Seed::from_env_value(&hex).unwrap();
    assert!(seed.bytes().iter().all(|b| *b == 0xFF));
}

// =========================================================================
// Debug redaction
// =========================================================================

#[test]
fn seed_debug_never_leaks_bytes() {
    let seed = Seed::new([0xDE; 32]);
    let dbg = format!("{:?}", seed);
    assert!(!dbg.contains("DE"), "seed bytes must not appear in Debug");
    assert!(!dbg.contains("222"), "seed byte decimal must not appear");
    assert!(dbg.contains("redacted"), "Debug must say 'redacted'");
}

// =========================================================================
// Equality and hash consistency
// =========================================================================

#[test]
fn seeds_with_same_bytes_are_equal() {
    let a = Seed::new([42u8; 32]);
    let b = Seed::new([42u8; 32]);
    assert_eq!(a, b);
}

#[test]
fn seeds_with_different_bytes_are_not_equal() {
    let a = Seed::new([1u8; 32]);
    let b = Seed::new([2u8; 32]);
    assert_ne!(a, b);
}

// =========================================================================
// from_env_value with 0x prefix
// =========================================================================

#[test]
fn from_env_value_0x_prefix_strips_correctly() {
    let hex = format!("0x{}", "ab".repeat(32));
    let seed = Seed::from_env_value(&hex).unwrap();
    assert!(seed.bytes().iter().all(|b| *b == 0xAB));
}

#[test]
fn from_env_value_0x_with_short_hex_is_hashed() {
    // "0x" + 62 chars = 62 hex chars after stripping, not 64, so hashed
    let hex = format!("0x{}", "a".repeat(62));
    let result = Seed::from_env_value(&hex).unwrap();
    // After trim and strip, hex part is 62 chars (not 64), so the full value is BLAKE3-hashed
    let expected = blake3::hash(hex.trim().as_bytes());
    assert_eq!(result.bytes(), expected.as_bytes());
}

// =========================================================================
// Mixed case hex
// =========================================================================

#[test]
fn from_env_value_mixed_case_hex_parses() {
    let mut hex = String::new();
    for i in 0..32 {
        if i % 2 == 0 {
            hex.push_str("aB");
        } else {
            hex.push_str("Ab");
        }
    }
    assert_eq!(hex.len(), 64);
    let result = Seed::from_env_value(&hex);
    assert!(result.is_ok(), "mixed-case hex should parse");
}
