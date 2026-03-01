//! Comprehensive tests for `uselesskey-core-x509-derive`.
//!
//! Covers public API surface, determinism guarantees, edge cases,
//! and property-based tests.

use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use time::OffsetDateTime;
use uselesskey_core_hash::Hasher;
use uselesskey_core_x509_derive::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, SERIAL_NUMBER_BYTES, deterministic_base_time,
    deterministic_base_time_from_parts, deterministic_serial_number, write_len_prefixed,
};

// ===========================================================================
// Constants
// ===========================================================================

#[test]
fn epoch_unix_timestamp_is_correct() {
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    assert_eq!(epoch.year(), 2025);
    assert_eq!(epoch.month() as u8, 1);
    assert_eq!(epoch.day(), 1);
    assert_eq!(epoch.hour(), 0);
    assert_eq!(epoch.minute(), 0);
    assert_eq!(epoch.second(), 0);
}

#[test]
fn window_days_is_365() {
    assert_eq!(BASE_TIME_WINDOW_DAYS, 365);
}

#[test]
fn serial_number_bytes_is_16() {
    assert_eq!(SERIAL_NUMBER_BYTES, 16);
}

// ===========================================================================
// deterministic_base_time_from_parts — determinism
// ===========================================================================

#[test]
fn from_parts_determinism_identical_inputs() {
    let parts: &[&[u8]] = &[b"CN=example.com", b"leaf", b"RS256"];
    let a = deterministic_base_time_from_parts(parts);
    let b = deterministic_base_time_from_parts(parts);
    assert_eq!(a, b);
}

#[test]
fn from_parts_determinism_repeated_many_times() {
    let parts: &[&[u8]] = &[b"stable-label"];
    let expected = deterministic_base_time_from_parts(parts);
    for _ in 0..100 {
        assert_eq!(deterministic_base_time_from_parts(parts), expected);
    }
}

// ===========================================================================
// deterministic_base_time_from_parts — edge cases
// ===========================================================================

#[test]
fn from_parts_empty_slice() {
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS - 1));
    let t = deterministic_base_time_from_parts(&[]);
    assert!(t >= epoch && t <= max);
}

#[test]
fn from_parts_single_empty_bytes() {
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS - 1));
    let t = deterministic_base_time_from_parts(&[b""]);
    assert!(t >= epoch && t <= max);
}

#[test]
fn from_parts_many_empty_parts() {
    let a = deterministic_base_time_from_parts(&[b"", b""]);
    let b = deterministic_base_time_from_parts(&[b"", b"", b""]);
    // Different number of empty parts should yield different hashes
    // because each empty part still adds a length prefix (4 zero bytes).
    assert_ne!(a, b);
}

#[test]
fn from_parts_unicode_cn() {
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS - 1));
    let t = deterministic_base_time_from_parts(&["CN=例え.jp".as_bytes()]);
    assert!(t >= epoch && t <= max);
}

#[test]
fn from_parts_special_characters_in_cn() {
    let cases: &[&[u8]] = &[
        b"CN=*.example.com",
        b"CN=test+alias@example.com",
        b"CN=O=Org\\, Inc.",
        b"CN=null\x00byte",
        b"CN=newline\nchar",
    ];
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS - 1));

    for cn in cases {
        let t = deterministic_base_time_from_parts(&[cn]);
        assert!(t >= epoch && t <= max, "out of range for {cn:?}");
    }
}

#[test]
fn from_parts_long_input() {
    let long_label = vec![b'A'; 10_000];
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS - 1));
    let t = deterministic_base_time_from_parts(&[&long_label]);
    assert!(t >= epoch && t <= max);
}

#[test]
fn from_parts_all_256_byte_values() {
    let all_bytes: Vec<u8> = (0..=255).collect();
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS - 1));
    let t = deterministic_base_time_from_parts(&[&all_bytes]);
    assert!(t >= epoch && t <= max);
}

// ===========================================================================
// deterministic_base_time_from_parts — collision resistance
// ===========================================================================

#[test]
fn from_parts_boundary_ambiguity_prevented() {
    let a = deterministic_base_time_from_parts(&[b"ab", b"cd"]);
    let b = deterministic_base_time_from_parts(&[b"a", b"bcd"]);
    let c = deterministic_base_time_from_parts(&[b"abc", b"d"]);
    let d = deterministic_base_time_from_parts(&[b"abcd"]);
    // All four should be distinct.
    let times = [a, b, c, d];
    for i in 0..times.len() {
        for j in (i + 1)..times.len() {
            assert_ne!(times[i], times[j], "collision at ({i}, {j})");
        }
    }
}

#[test]
fn from_parts_order_matters() {
    let a = deterministic_base_time_from_parts(&[b"first", b"second"]);
    let b = deterministic_base_time_from_parts(&[b"second", b"first"]);
    assert_ne!(a, b);
}

#[test]
fn from_parts_trailing_empty_part_changes_result() {
    let a = deterministic_base_time_from_parts(&[b"label"]);
    let b = deterministic_base_time_from_parts(&[b"label", b""]);
    assert_ne!(a, b);
}

// ===========================================================================
// deterministic_base_time_from_parts — output properties
// ===========================================================================

#[test]
fn from_parts_result_is_at_day_boundary() {
    let cases: &[&[&[u8]]] = &[&[b"test1"], &[b"test2", b"extra"], &[b""], &[]];
    for parts in cases {
        let t = deterministic_base_time_from_parts(parts);
        assert_eq!(t.hour(), 0, "non-zero hour for {parts:?}");
        assert_eq!(t.minute(), 0, "non-zero minute for {parts:?}");
        assert_eq!(t.second(), 0, "non-zero second for {parts:?}");
        assert_eq!(t.nanosecond(), 0, "non-zero nanosecond for {parts:?}");
    }
}

// ===========================================================================
// deterministic_base_time — raw Hasher API
// ===========================================================================

#[test]
fn raw_hasher_matches_from_parts() {
    let parts: &[&[u8]] = &[b"one", b"two", b"three"];
    let from_parts = deterministic_base_time_from_parts(parts);

    let mut hasher = Hasher::new();
    for p in parts {
        write_len_prefixed(&mut hasher, p);
    }
    let from_hasher = deterministic_base_time(hasher);
    assert_eq!(from_parts, from_hasher);
}

#[test]
fn raw_hasher_empty_produces_valid_time() {
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS - 1));
    let t = deterministic_base_time(Hasher::new());
    assert!(t >= epoch && t <= max);
}

#[test]
fn raw_hasher_different_content_different_time() {
    let mut h1 = Hasher::new();
    h1.update(b"alpha");
    let mut h2 = Hasher::new();
    h2.update(b"beta");
    assert_ne!(deterministic_base_time(h1), deterministic_base_time(h2));
}

// ===========================================================================
// deterministic_serial_number — basic properties
// ===========================================================================

#[test]
fn serial_number_correct_length() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let serial = deterministic_serial_number(&mut rng);
    assert_eq!(serial.to_bytes().len(), SERIAL_NUMBER_BYTES);
}

#[test]
fn serial_number_high_bit_cleared_all_seeds() {
    for seed_byte in 0u8..=255 {
        let mut rng = ChaCha20Rng::from_seed([seed_byte; 32]);
        let bytes = deterministic_serial_number(&mut rng).to_bytes();
        assert_eq!(bytes[0] & 0x80, 0, "high bit set for seed {seed_byte}");
    }
}

#[test]
fn serial_number_deterministic_same_seed() {
    let seed = [42u8; 32];
    let a = deterministic_serial_number(&mut ChaCha20Rng::from_seed(seed)).to_bytes();
    let b = deterministic_serial_number(&mut ChaCha20Rng::from_seed(seed)).to_bytes();
    assert_eq!(a, b);
}

#[test]
fn serial_number_different_seeds_differ() {
    let a = deterministic_serial_number(&mut ChaCha20Rng::from_seed([1u8; 32])).to_bytes();
    let b = deterministic_serial_number(&mut ChaCha20Rng::from_seed([2u8; 32])).to_bytes();
    assert_ne!(a, b);
}

#[test]
fn serial_number_consecutive_from_same_rng_differ() {
    let mut rng = ChaCha20Rng::from_seed([77u8; 32]);
    let first = deterministic_serial_number(&mut rng).to_bytes();
    let second = deterministic_serial_number(&mut rng).to_bytes();
    assert_ne!(first, second);
}

#[test]
fn serial_number_not_all_zeros() {
    // With overwhelming probability, a random 16-byte serial is non-zero.
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let bytes = deterministic_serial_number(&mut rng).to_bytes();
    assert!(
        bytes.iter().any(|&b| b != 0),
        "serial should not be all zeros"
    );
}

#[test]
fn serial_number_many_consecutive_all_positive() {
    let mut rng = ChaCha20Rng::from_seed([123u8; 32]);
    for i in 0..1000 {
        let bytes = deterministic_serial_number(&mut rng).to_bytes();
        assert_eq!(bytes.len(), SERIAL_NUMBER_BYTES, "wrong length at iter {i}");
        assert_eq!(bytes[0] & 0x80, 0, "high bit set at iter {i}");
    }
}

// ===========================================================================
// write_len_prefixed re-export
// ===========================================================================

#[test]
fn write_len_prefixed_reexport_works() {
    let mut h = Hasher::new();
    write_len_prefixed(&mut h, b"hello");

    let mut manual = Hasher::new();
    manual.update(&5u32.to_be_bytes());
    manual.update(b"hello");

    assert_eq!(h.finalize(), manual.finalize());
}

#[test]
fn write_len_prefixed_empty_data() {
    let mut h = Hasher::new();
    write_len_prefixed(&mut h, b"");

    let mut manual = Hasher::new();
    manual.update(&0u32.to_be_bytes());

    assert_eq!(h.finalize(), manual.finalize());
}

// ===========================================================================
// Property-based tests
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn prop_base_time_always_in_epoch_window(
        label in any::<Vec<u8>>(),
    ) {
        let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
        let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS - 1));
        let t = deterministic_base_time_from_parts(&[&label]);
        prop_assert!(t >= epoch, "base time before epoch");
        prop_assert!(t <= max, "base time after window");
    }

    #[test]
    fn prop_base_time_deterministic(
        parts in prop::collection::vec(any::<Vec<u8>>(), 0..5),
    ) {
        let refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
        let a = deterministic_base_time_from_parts(&refs);
        let b = deterministic_base_time_from_parts(&refs);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn prop_base_time_at_day_boundary(
        label in any::<Vec<u8>>(),
    ) {
        let t = deterministic_base_time_from_parts(&[&label]);
        prop_assert_eq!(t.hour(), 0);
        prop_assert_eq!(t.minute(), 0);
        prop_assert_eq!(t.second(), 0);
        prop_assert_eq!(t.nanosecond(), 0);
    }

    #[test]
    fn prop_boundary_ambiguity_prevented(
        a in any::<Vec<u8>>(),
        b in any::<Vec<u8>>(),
    ) {
        // Concatenation as single part vs two parts should differ
        // (unless both are empty which is tested separately).
        if !a.is_empty() || !b.is_empty() {
            let mut combined = a.clone();
            combined.extend_from_slice(&b);
            let single = deterministic_base_time_from_parts(&[&combined]);
            let split = deterministic_base_time_from_parts(&[&a, &b]);
            prop_assert_ne!(single, split);
        }
    }

    #[test]
    fn prop_serial_number_positive_and_correct_length(
        seed in any::<[u8; 32]>(),
    ) {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let bytes = deterministic_serial_number(&mut rng).to_bytes();
        prop_assert_eq!(bytes.len(), SERIAL_NUMBER_BYTES);
        prop_assert_eq!(bytes[0] & 0x80, 0, "high bit must be cleared");
    }

    #[test]
    fn prop_serial_number_deterministic(
        seed in any::<[u8; 32]>(),
    ) {
        let a = deterministic_serial_number(&mut ChaCha20Rng::from_seed(seed)).to_bytes();
        let b = deterministic_serial_number(&mut ChaCha20Rng::from_seed(seed)).to_bytes();
        prop_assert_eq!(a, b);
    }

    #[test]
    fn prop_from_parts_matches_raw_hasher(
        parts in prop::collection::vec(any::<Vec<u8>>(), 0..6),
    ) {
        let refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
        let from_parts = deterministic_base_time_from_parts(&refs);

        let mut hasher = Hasher::new();
        for p in &refs {
            write_len_prefixed(&mut hasher, p);
        }
        let from_hasher = deterministic_base_time(hasher);
        prop_assert_eq!(from_parts, from_hasher);
    }
}
