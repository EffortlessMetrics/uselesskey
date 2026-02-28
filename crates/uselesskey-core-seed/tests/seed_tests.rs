#![cfg(feature = "std")]

use uselesskey_core_seed::Seed;

// ── Construction from [u8; 32] ──────────────────────────────────────

#[test]
fn new_from_zero_array() {
    let seed = Seed::new([0u8; 32]);
    assert_eq!(seed.bytes(), &[0u8; 32]);
}

#[test]
fn new_from_max_array() {
    let seed = Seed::new([0xFF; 32]);
    assert_eq!(seed.bytes(), &[0xFF; 32]);
}

#[test]
fn new_from_arbitrary_array() {
    let arr: [u8; 32] = core::array::from_fn(|i| i as u8);
    let seed = Seed::new(arr);
    assert_eq!(seed.bytes(), &arr);
}

#[test]
fn new_from_single_byte_set() {
    let mut arr = [0u8; 32];
    arr[15] = 0xAB;
    let seed = Seed::new(arr);
    assert_eq!(seed.bytes()[15], 0xAB);
    assert!(
        seed.bytes()
            .iter()
            .enumerate()
            .all(|(i, &b)| { if i == 15 { b == 0xAB } else { b == 0 } })
    );
}

// ── .bytes() accessor ───────────────────────────────────────────────

#[test]
fn bytes_returns_reference_to_original() {
    let arr = [42u8; 32];
    let seed = Seed::new(arr);
    let bytes: &[u8; 32] = seed.bytes();
    assert_eq!(bytes, &arr);
    assert_eq!(bytes.len(), 32);
}

// ── Copy semantics ──────────────────────────────────────────────────

#[test]
fn seed_is_copy() {
    let seed1 = Seed::new([1u8; 32]);
    let seed2 = seed1; // copy
    // seed1 is still usable after move (proves Copy)
    assert_eq!(seed1.bytes(), seed2.bytes());
}

#[test]
fn copy_produces_independent_equal_value() {
    let seed1 = Seed::new([99u8; 32]);
    let seed2 = seed1;
    assert_eq!(seed1, seed2);
    assert_eq!(seed1.bytes(), seed2.bytes());
}

// ── Clone ───────────────────────────────────────────────────────────

#[test]
fn clone_produces_identical_bytes() {
    let seed = Seed::new([0xDE; 32]);
    let cloned = seed.clone();
    assert_eq!(seed.bytes(), cloned.bytes());
}

#[test]
fn clone_equals_original() {
    let seed = Seed::new(core::array::from_fn(|i| (i * 7) as u8));
    let cloned = seed.clone();
    assert_eq!(seed, cloned);
}

// ── Debug does NOT leak seed bytes ──────────────────────────────────

#[test]
fn debug_shows_redacted() {
    let seed = Seed::new([0xAB; 32]);
    let dbg = format!("{:?}", seed);
    assert_eq!(dbg, "Seed(**redacted**)");
}

#[test]
fn debug_does_not_contain_hex_bytes() {
    let seed = Seed::new([0xFF; 32]);
    let dbg = format!("{:?}", seed);
    // Must not contain any representation of the actual bytes
    assert!(
        !dbg.contains("ff"),
        "Debug output must not leak byte values"
    );
    assert!(
        !dbg.contains("FF"),
        "Debug output must not leak byte values"
    );
    assert!(
        !dbg.contains("255"),
        "Debug output must not leak byte values"
    );
    assert!(
        !dbg.contains("0xff"),
        "Debug output must not leak byte values"
    );
}

#[test]
fn debug_format_is_stable_across_values() {
    let s1 = format!("{:?}", Seed::new([0u8; 32]));
    let s2 = format!("{:?}", Seed::new([1u8; 32]));
    // Both produce same opaque string — no information leakage
    assert_eq!(s1, s2);
}

// ── PartialEq / Eq ─────────────────────────────────────────────────

#[test]
fn eq_same_bytes() {
    let a = Seed::new([5u8; 32]);
    let b = Seed::new([5u8; 32]);
    assert_eq!(a, b);
}

#[test]
fn ne_different_bytes() {
    let a = Seed::new([0u8; 32]);
    let b = Seed::new([1u8; 32]);
    assert_ne!(a, b);
}

#[test]
fn ne_single_bit_difference() {
    let mut arr = [0u8; 32];
    let a = Seed::new(arr);
    arr[31] = 1;
    let b = Seed::new(arr);
    assert_ne!(a, b);
}

#[test]
fn eq_is_reflexive() {
    let s = Seed::new([77u8; 32]);
    assert_eq!(s, s);
}

#[test]
fn eq_is_symmetric() {
    let a = Seed::new([3u8; 32]);
    let b = Seed::new([3u8; 32]);
    assert_eq!(a, b);
    assert_eq!(b, a);
}

// ── Hash consistency ────────────────────────────────────────────────

#[test]
fn equal_seeds_have_equal_hashes() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let a = Seed::new([10u8; 32]);
    let b = Seed::new([10u8; 32]);

    let mut ha = DefaultHasher::new();
    a.hash(&mut ha);
    let mut hb = DefaultHasher::new();
    b.hash(&mut hb);

    assert_eq!(ha.finish(), hb.finish());
}

#[test]
fn different_seeds_likely_different_hashes() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let a = Seed::new([0u8; 32]);
    let b = Seed::new([1u8; 32]);

    let mut ha = DefaultHasher::new();
    a.hash(&mut ha);
    let mut hb = DefaultHasher::new();
    b.hash(&mut hb);

    assert_ne!(ha.finish(), hb.finish());
}

// ── from_env_value ──────────────────────────────────────────────────

#[test]
fn from_env_value_lowercase_hex() {
    let hex = "aa".repeat(32);
    let seed = Seed::from_env_value(&hex).unwrap();
    assert!(seed.bytes().iter().all(|&b| b == 0xAA));
}

#[test]
fn from_env_value_uppercase_hex() {
    let hex = "BB".repeat(32);
    let seed = Seed::from_env_value(&hex).unwrap();
    assert!(seed.bytes().iter().all(|&b| b == 0xBB));
}

#[test]
fn from_env_value_mixed_case_hex() {
    let hex = "aAbBcCdDeEfF".repeat(5) + "aAbB";
    assert_eq!(hex.len(), 64);
    let seed = Seed::from_env_value(&hex).unwrap();
    assert_eq!(seed.bytes()[0], 0xAA);
    assert_eq!(seed.bytes()[1], 0xBB);
}

#[test]
fn from_env_value_0x_prefix() {
    let hex = "0x".to_owned() + &"00".repeat(31) + "ff";
    let seed = Seed::from_env_value(&hex).unwrap();
    assert_eq!(seed.bytes()[31], 0xFF);
}

#[test]
fn from_env_value_trims_whitespace() {
    let hex = "  ".to_string() + &"ab".repeat(32) + "  ";
    let seed = Seed::from_env_value(&hex).unwrap();
    assert!(seed.bytes().iter().all(|&b| b == 0xAB));
}

#[test]
fn from_env_value_short_string_hashes() {
    let seed = Seed::from_env_value("hello").unwrap();
    let expected = blake3::hash(b"hello");
    assert_eq!(seed.bytes(), expected.as_bytes());
}

#[test]
fn from_env_value_empty_string_hashes() {
    let seed = Seed::from_env_value("").unwrap();
    let expected = blake3::hash(b"");
    assert_eq!(seed.bytes(), expected.as_bytes());
}

#[test]
fn from_env_value_whitespace_only_hashes_empty() {
    // "  " trims to "" which has len 0, not 64, so it hashes ""
    let seed = Seed::from_env_value("  ").unwrap();
    let expected = blake3::hash(b"");
    assert_eq!(seed.bytes(), expected.as_bytes());
}

#[test]
fn from_env_value_63_char_string_hashes() {
    let s = "a".repeat(63);
    let seed = Seed::from_env_value(&s).unwrap();
    let expected = blake3::hash(s.as_bytes());
    assert_eq!(seed.bytes(), expected.as_bytes());
}

#[test]
fn from_env_value_65_char_string_hashes() {
    let s = "a".repeat(65);
    let seed = Seed::from_env_value(&s).unwrap();
    let expected = blake3::hash(s.as_bytes());
    assert_eq!(seed.bytes(), expected.as_bytes());
}

// ── proptest: roundtrip & distinctness ──────────────────────────────

mod prop {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip_bytes(bytes in any::<[u8; 32]>()) {
            let seed = Seed::new(bytes);
            prop_assert_eq!(seed.bytes(), &bytes);
        }

        #[test]
        fn different_arrays_produce_different_seeds(
            a in any::<[u8; 32]>(),
            b in any::<[u8; 32]>(),
        ) {
            prop_assume!(a != b);
            let sa = Seed::new(a);
            let sb = Seed::new(b);
            prop_assert_ne!(sa, sb);
        }

        #[test]
        fn clone_always_equals_original(bytes in any::<[u8; 32]>()) {
            let seed = Seed::new(bytes);
            prop_assert_eq!(seed.clone(), seed);
        }

        #[test]
        fn debug_never_leaks_bytes(bytes in any::<[u8; 32]>()) {
            let dbg = format!("{:?}", Seed::new(bytes));
            prop_assert_eq!(dbg, "Seed(**redacted**)");
        }
    }
}
