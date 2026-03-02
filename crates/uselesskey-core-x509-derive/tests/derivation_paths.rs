//! Derivation path tests for uselesskey-core-x509-derive.
//!
//! Covers:
//! - Different part orderings produce different times
//! - Consecutive serial numbers from same RNG differ
//! - Serial number high bit is always cleared across many seeds
//! - Length-prefixed hashing prevents boundary collisions
//! - base_time stays within epoch window for diverse inputs

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::collections::HashSet;
use uselesskey_core_x509_derive::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, SERIAL_NUMBER_BYTES,
    deterministic_base_time_from_parts, deterministic_serial_number,
};

// =========================================================================
// Derivation path diversity: different inputs → different outputs
// =========================================================================

#[test]
fn different_part_orderings_produce_different_times() {
    let a = deterministic_base_time_from_parts(&[b"root", b"leaf"]);
    let b = deterministic_base_time_from_parts(&[b"leaf", b"root"]);
    assert_ne!(a, b, "swapping parts should produce different base times");
}

#[test]
fn adding_extra_part_changes_result() {
    let short = deterministic_base_time_from_parts(&[b"label"]);
    let long = deterministic_base_time_from_parts(&[b"label", b"extra"]);
    assert_ne!(short, long);
}

#[test]
fn empty_vs_empty_part_differ() {
    let none = deterministic_base_time_from_parts(&[]);
    let one_empty = deterministic_base_time_from_parts(&[b""]);
    let two_empty = deterministic_base_time_from_parts(&[b"", b""]);

    assert_ne!(none, one_empty);
    assert_ne!(one_empty, two_empty);
    assert_ne!(none, two_empty);
}

// =========================================================================
// base_time stays within window for diverse inputs
// =========================================================================

#[test]
fn base_time_within_window_for_many_inputs() {
    let epoch = time::OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS));

    for i in 0u32..100 {
        let label = format!("label-{i}");
        let t = deterministic_base_time_from_parts(&[label.as_bytes()]);
        assert!(
            t >= epoch && t < max,
            "base_time for label-{i} out of range"
        );
    }
}

#[test]
fn base_time_distribution_uses_multiple_days() {
    let epoch = time::OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();

    let mut day_offsets = HashSet::new();
    for i in 0u32..50 {
        let label = format!("dist-{i}");
        let t = deterministic_base_time_from_parts(&[label.as_bytes()]);
        let offset = (t - epoch).whole_days();
        day_offsets.insert(offset);
    }

    assert!(
        day_offsets.len() > 5,
        "base_time should distribute across multiple days, got {} unique",
        day_offsets.len()
    );
}

// =========================================================================
// Consecutive serial numbers from same RNG differ
// =========================================================================

#[test]
fn consecutive_serials_from_same_rng_differ() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let s1 = deterministic_serial_number(&mut rng);
    let s2 = deterministic_serial_number(&mut rng);
    let s3 = deterministic_serial_number(&mut rng);

    assert_ne!(s1.to_bytes(), s2.to_bytes());
    assert_ne!(s2.to_bytes(), s3.to_bytes());
    assert_ne!(s1.to_bytes(), s3.to_bytes());
}

#[test]
fn serial_high_bit_cleared_across_many_seeds() {
    for seed_byte in 0u8..=255 {
        let mut rng = ChaCha20Rng::from_seed([seed_byte; 32]);
        let serial = deterministic_serial_number(&mut rng);
        let bytes = serial.to_bytes();
        assert_eq!(
            bytes[0] & 0x80,
            0,
            "serial with seed byte {seed_byte} should have high bit cleared"
        );
        assert_eq!(bytes.len(), SERIAL_NUMBER_BYTES);
    }
}

// =========================================================================
// Length-prefixed hashing prevents boundary collisions
// =========================================================================

#[test]
fn boundary_collision_resistance() {
    // These should all produce different results due to length prefixing
    let cases: Vec<Vec<&[u8]>> = vec![
        vec![b"abc", b"def"],
        vec![b"ab", b"cdef"],
        vec![b"abcd", b"ef"],
        vec![b"a", b"bcdef"],
        vec![b"abcdef"],
    ];

    let results: HashSet<i64> = cases
        .iter()
        .map(|parts| deterministic_base_time_from_parts(parts).unix_timestamp())
        .collect();

    assert_eq!(
        results.len(),
        cases.len(),
        "all boundary permutations should produce distinct times"
    );
}
