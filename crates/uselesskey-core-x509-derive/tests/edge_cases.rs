//! Property-based and edge-case tests for X.509 derivation helpers.

#![forbid(unsafe_code)]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use uselesskey_core_x509_derive::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, SERIAL_NUMBER_BYTES,
    deterministic_base_time_from_parts, deterministic_serial_number,
};

// ---------------------------------------------------------------------------
// Edge cases: empty / single-byte / many parts
// ---------------------------------------------------------------------------

#[test]
fn base_time_empty_parts_is_deterministic() {
    let a = deterministic_base_time_from_parts(&[]);
    let b = deterministic_base_time_from_parts(&[]);
    assert_eq!(a, b);
}

#[test]
fn base_time_single_empty_part_differs_from_no_parts() {
    let no_parts = deterministic_base_time_from_parts(&[]);
    let one_empty = deterministic_base_time_from_parts(&[b""]);
    // Length-prefixed hashing means [empty_slice] ≠ [], because the
    // length prefix (0u32) is still written.
    assert_ne!(no_parts, one_empty);
}

#[test]
fn base_time_many_parts_is_deterministic() {
    let data: Vec<u8> = (0u8..20).collect();
    let parts: Vec<&[u8]> = data.iter().map(std::slice::from_ref).collect();
    let a = deterministic_base_time_from_parts(&parts);
    let b = deterministic_base_time_from_parts(&parts);
    assert_eq!(a, b);
}

#[test]
fn base_time_is_always_within_epoch_window() {
    let epoch = time::OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS));

    // Test many different inputs
    for seed in 0u8..=255 {
        let t = deterministic_base_time_from_parts(&[&[seed]]);
        assert!(t >= epoch, "seed {seed}: time before epoch");
        assert!(t < max, "seed {seed}: time beyond window");
    }
}

// ---------------------------------------------------------------------------
// Serial number edge cases
// ---------------------------------------------------------------------------

#[test]
fn serial_number_high_bit_always_cleared() {
    // Test across many seeds to confirm the high bit is always cleared.
    for seed_byte in 0u8..=255 {
        let mut seed = [0u8; 32];
        seed[0] = seed_byte;
        let mut rng = ChaCha20Rng::from_seed(seed);
        let serial = deterministic_serial_number(&mut rng);
        let bytes = serial.to_bytes();
        assert_eq!(
            bytes[0] & 0x80,
            0,
            "high bit not cleared for seed byte {seed_byte}"
        );
    }
}

#[test]
fn serial_number_length_is_always_fixed() {
    for seed_byte in [0u8, 1, 42, 127, 128, 255] {
        let mut seed = [0u8; 32];
        seed[0] = seed_byte;
        let mut rng = ChaCha20Rng::from_seed(seed);
        let serial = deterministic_serial_number(&mut rng);
        assert_eq!(serial.to_bytes().len(), SERIAL_NUMBER_BYTES);
    }
}

#[test]
fn serial_number_consecutive_calls_differ() {
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let s1 = deterministic_serial_number(&mut rng);
    let s2 = deterministic_serial_number(&mut rng);
    assert_ne!(
        s1.to_bytes(),
        s2.to_bytes(),
        "consecutive serial numbers from same RNG should differ"
    );
}

// ---------------------------------------------------------------------------
// Boundary disambiguation
// ---------------------------------------------------------------------------

#[test]
fn boundary_disambiguation_three_parts() {
    // "a" + "bc" + "d" vs "ab" + "c" + "d" vs "ab" + "cd"
    let t1 = deterministic_base_time_from_parts(&[b"a", b"bc", b"d"]);
    let t2 = deterministic_base_time_from_parts(&[b"ab", b"c", b"d"]);
    let t3 = deterministic_base_time_from_parts(&[b"ab", b"cd"]);
    assert_ne!(t1, t2);
    assert_ne!(t1, t3);
    assert_ne!(t2, t3);
}

#[test]
fn base_time_different_single_parts_differ() {
    let a = deterministic_base_time_from_parts(&[b"alpha"]);
    let b = deterministic_base_time_from_parts(&[b"bravo"]);
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// Constants sanity
// ---------------------------------------------------------------------------

#[test]
fn epoch_is_in_the_past_or_near_present() {
    let epoch = time::OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    // The epoch is 2025-01-01, which should be in the past or very near present.
    assert!(epoch.year() >= 2025);
    assert!(epoch.year() <= 2026);
}

#[test]
fn window_days_is_positive() {
    assert!(BASE_TIME_WINDOW_DAYS > 0);
}

#[test]
fn serial_number_bytes_is_positive() {
    assert!(SERIAL_NUMBER_BYTES > 0);
}
