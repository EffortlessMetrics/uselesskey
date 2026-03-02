//! Edge-case and boundary tests for Seed.

#![cfg(feature = "std")]

use std::collections::HashSet;

use uselesskey_core_seed::Seed;

// ── Seed boundary values ────────────────────────────────────────────

#[test]
fn seed_all_zeros_is_distinct_from_all_ones() {
    let zero = Seed::new([0u8; 32]);
    let ones = Seed::new([0xFF; 32]);
    assert_ne!(zero, ones);
}

#[test]
fn seed_single_bit_flip_at_each_position_produces_unique_seeds() {
    let base = Seed::new([0u8; 32]);
    let mut seen = HashSet::new();
    seen.insert(*base.bytes());

    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut arr = [0u8; 32];
            arr[byte_idx] |= 1 << bit_idx;
            let seed = Seed::new(arr);
            assert!(
                seen.insert(*seed.bytes()),
                "bit flip at byte {byte_idx} bit {bit_idx} collided"
            );
        }
    }
    // 1 base + 256 single-bit flips = 257 unique seeds
    assert_eq!(seen.len(), 257);
}

// ── from_env_value edge cases ───────────────────────────────────────

#[test]
fn from_env_value_exactly_64_hex_zeros() {
    let hex = "0".repeat(64);
    let seed = Seed::from_env_value(&hex).unwrap();
    assert_eq!(seed.bytes(), &[0u8; 32]);
}

#[test]
fn from_env_value_exactly_64_hex_f() {
    let hex = "f".repeat(64);
    let seed = Seed::from_env_value(&hex).unwrap();
    assert_eq!(seed.bytes(), &[0xFF; 32]);
}

#[test]
fn from_env_value_0x_prefix_64_hex_chars() {
    // "0x" + 64 hex chars = 66 chars, valid hex with prefix
    let hex = "0x".to_owned() + &"ab".repeat(32);
    let seed = Seed::from_env_value(&hex).unwrap();
    assert!(seed.bytes().iter().all(|&b| b == 0xAB));
}

#[test]
fn from_env_value_unicode_string_hashes_consistently() {
    let seed1 = Seed::from_env_value("日本語テスト🔑").unwrap();
    let seed2 = Seed::from_env_value("日本語テスト🔑").unwrap();
    assert_eq!(seed1, seed2);
}

#[test]
fn from_env_value_different_unicode_strings_differ() {
    let seed1 = Seed::from_env_value("日本語").unwrap();
    let seed2 = Seed::from_env_value("中文").unwrap();
    assert_ne!(seed1, seed2);
}

#[test]
fn from_env_value_very_long_string() {
    let long = "x".repeat(100_000);
    let seed = Seed::from_env_value(&long).unwrap();
    // Must produce a valid 32-byte seed
    assert_eq!(seed.bytes().len(), 32);
}

#[test]
fn from_env_value_newlines_in_value() {
    let seed1 = Seed::from_env_value("line1\nline2").unwrap();
    let seed2 = Seed::from_env_value("line1\nline2").unwrap();
    assert_eq!(seed1, seed2);
}

#[test]
fn from_env_value_tab_characters() {
    let seed = Seed::from_env_value("\t\thello\t").unwrap();
    // Trims to "hello" then hashes
    let expected = Seed::from_env_value("hello").unwrap();
    assert_eq!(seed, expected);
}

#[test]
fn from_env_value_invalid_hex_64_chars_returns_error() {
    // 64 chars but not valid hex → parse_hex_32 returns Err
    let not_hex = "g".repeat(64);
    let result = Seed::from_env_value(&not_hex);
    assert!(result.is_err(), "64 non-hex chars should fail");
}

// ── Hash trait in collections ───────────────────────────────────────

#[test]
fn seed_works_as_hashset_key() {
    let mut set = HashSet::new();
    set.insert(Seed::new([1u8; 32]));
    set.insert(Seed::new([2u8; 32]));
    set.insert(Seed::new([1u8; 32])); // duplicate

    assert_eq!(set.len(), 2);
}

#[test]
fn seed_works_as_hashmap_key() {
    use std::collections::HashMap;
    let mut map = HashMap::new();
    let seed = Seed::new([42u8; 32]);
    map.insert(seed, "value");
    assert_eq!(map.get(&seed), Some(&"value"));
}

// ── Debug output safety ─────────────────────────────────────────────

#[test]
fn debug_never_contains_any_byte_representation() {
    let arr = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18,
    ];
    let seed = Seed::new(arr);
    let dbg = format!("{seed:?}");
    assert!(!dbg.contains("dead"), "Debug must not contain hex bytes");
    assert!(!dbg.contains("DEAD"), "Debug must not contain hex bytes");
    assert!(!dbg.contains("cafe"), "Debug must not contain hex bytes");
    assert!(!dbg.contains("babe"), "Debug must not contain hex bytes");
}
