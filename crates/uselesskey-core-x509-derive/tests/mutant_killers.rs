//! Mutant-killing tests for X.509 derive helpers.

use time::OffsetDateTime;
use uselesskey_core_seed::Seed;
use uselesskey_core_x509_derive::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, SERIAL_NUMBER_BYTES, deterministic_base_time,
    deterministic_base_time_from_parts, deterministic_serial_number,
};

#[test]
fn epoch_constant_is_2025_01_01() {
    assert_eq!(BASE_TIME_EPOCH_UNIX, 1_735_689_600);
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    assert_eq!(epoch.year(), 2025);
    assert_eq!(epoch.month() as u8, 1);
    assert_eq!(epoch.day(), 1);
}

#[test]
fn window_days_is_365() {
    assert_eq!(BASE_TIME_WINDOW_DAYS, 365);
}

#[test]
fn serial_number_bytes_is_16() {
    assert_eq!(SERIAL_NUMBER_BYTES, 16);
}

#[test]
fn base_time_within_epoch_window() {
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS));

    for i in 0u8..50 {
        let t = deterministic_base_time_from_parts(&[&[i]]);
        assert!(t >= epoch, "base time must be >= epoch, got {t}");
        assert!(t < max, "base time must be < epoch + window, got {t}");
    }
}

#[test]
fn base_time_from_parts_different_parts_different_times() {
    let t1 = deterministic_base_time_from_parts(&[b"label-a"]);
    let t2 = deterministic_base_time_from_parts(&[b"label-b"]);
    // While there's a small chance of collision, with 365 days of range it's extremely unlikely
    assert_ne!(t1, t2);
}

#[test]
fn base_time_from_parts_boundary_safe() {
    let t1 = deterministic_base_time_from_parts(&[b"ab", b"c"]);
    let t2 = deterministic_base_time_from_parts(&[b"a", b"bc"]);
    assert_ne!(
        t1, t2,
        "length-prefixed hashing must prevent boundary ambiguity"
    );
}

#[test]
fn serial_number_is_16_bytes() {
    let rng = Seed::new([7u8; 32]);
    let serial = deterministic_serial_number(rng);
    assert_eq!(serial.to_bytes().len(), SERIAL_NUMBER_BYTES);
}

#[test]
fn serial_number_high_bit_cleared() {
    // Test with multiple seeds to increase confidence
    for seed_byte in 0u8..50 {
        let rng = Seed::new([seed_byte; 32]);
        let serial = deterministic_serial_number(rng);
        let bytes = serial.to_bytes();
        assert_eq!(
            bytes[0] & 0x80,
            0,
            "high bit must be cleared for seed_byte={seed_byte}"
        );
    }
}

#[test]
fn serial_number_deterministic() {
    let a = deterministic_serial_number(Seed::new([42u8; 32]));
    let b = deterministic_serial_number(Seed::new([42u8; 32]));
    assert_eq!(a.to_bytes(), b.to_bytes());
}

#[test]
fn serial_number_different_seeds_differ() {
    let a = deterministic_serial_number(Seed::new([1u8; 32]));
    let b = deterministic_serial_number(Seed::new([2u8; 32]));
    assert_ne!(a.to_bytes(), b.to_bytes());
}

#[test]
fn base_time_hasher_finalize_produces_valid_day_offset() {
    use uselesskey_core_hash::Hasher;
    let hasher = Hasher::new();
    let t = deterministic_base_time(hasher);
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let diff = t - epoch;
    let days = diff.whole_days();
    assert!(days >= 0);
    assert!(days < i64::from(BASE_TIME_WINDOW_DAYS));
}
