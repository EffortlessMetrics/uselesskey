//! Integration tests for `uselesskey-core-x509-derive`.

use uselesskey_core_seed::Seed;
use uselesskey_core_x509_derive::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, SERIAL_NUMBER_BYTES,
    deterministic_base_time_from_parts, deterministic_serial_number, write_len_prefixed,
};

// ── deterministic_base_time_from_parts ───────────────────────────────

#[test]
fn base_time_within_epoch_window() {
    let epoch = time::OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS));

    let t = deterministic_base_time_from_parts(&[b"some-label"]);
    assert!(t >= epoch && t < max);
}

#[test]
fn base_time_deterministic_for_same_input() {
    let a = deterministic_base_time_from_parts(&[b"label", b"leaf"]);
    let b = deterministic_base_time_from_parts(&[b"label", b"leaf"]);
    assert_eq!(a, b);
}

#[test]
fn base_time_differs_for_different_input() {
    let a = deterministic_base_time_from_parts(&[b"label-a"]);
    let b = deterministic_base_time_from_parts(&[b"label-b"]);
    assert_ne!(a, b);
}

#[test]
fn base_time_boundary_safe_avoids_collisions() {
    // "ab" + "c" must differ from "a" + "bc" due to length-prefixed hashing
    let a = deterministic_base_time_from_parts(&[b"ab", b"c"]);
    let b = deterministic_base_time_from_parts(&[b"a", b"bc"]);
    assert_ne!(a, b);
}

#[test]
fn base_time_empty_parts_is_deterministic() {
    let a = deterministic_base_time_from_parts(&[]);
    let b = deterministic_base_time_from_parts(&[]);
    assert_eq!(a, b);
}

#[test]
fn base_time_single_empty_part_differs_from_no_parts() {
    let no_parts = deterministic_base_time_from_parts(&[]);
    let empty_part = deterministic_base_time_from_parts(&[b""]);
    // Length-prefixed encoding: zero parts vs one zero-length part
    assert_ne!(no_parts, empty_part);
}

#[test]
fn base_time_many_parts() {
    let data: Vec<Vec<u8>> = (0..20).map(|i| vec![i as u8]).collect();
    let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
    let a = deterministic_base_time_from_parts(&refs);
    let b = deterministic_base_time_from_parts(&refs);
    assert_eq!(a, b);
}

// ── deterministic_serial_number ──────────────────────────────────────

#[test]
fn serial_number_is_positive() {
    let rng = Seed::new([7u8; 32]);
    let serial = deterministic_serial_number(rng);
    let bytes = serial.to_bytes();
    assert_eq!(
        bytes[0] & 0x80,
        0,
        "high bit must be cleared for positive serial"
    );
}

#[test]
fn serial_number_correct_length() {
    let rng = Seed::new([42u8; 32]);
    let serial = deterministic_serial_number(rng);
    assert_eq!(serial.to_bytes().len(), SERIAL_NUMBER_BYTES);
}

#[test]
fn serial_number_deterministic_from_same_seed() {
    let a = Seed::new([99u8; 32]);
    let b = Seed::new([99u8; 32]);
    assert_eq!(
        deterministic_serial_number(a).to_bytes(),
        deterministic_serial_number(b).to_bytes()
    );
}

#[test]
fn serial_number_varies_across_seeds() {
    let a = Seed::new([1u8; 32]);
    let b = Seed::new([2u8; 32]);
    assert_ne!(
        deterministic_serial_number(a).to_bytes(),
        deterministic_serial_number(b).to_bytes()
    );
}

#[test]
fn serial_number_all_zero_seed() {
    let rng = Seed::new([0u8; 32]);
    let serial = deterministic_serial_number(rng);
    let bytes = serial.to_bytes();
    assert_eq!(bytes.len(), SERIAL_NUMBER_BYTES);
    assert_eq!(bytes[0] & 0x80, 0);
}

#[test]
fn serial_number_all_ones_seed() {
    let rng = Seed::new([0xFF; 32]);
    let serial = deterministic_serial_number(rng);
    let bytes = serial.to_bytes();
    assert_eq!(bytes.len(), SERIAL_NUMBER_BYTES);
    assert_eq!(bytes[0] & 0x80, 0);
}

// ── constants ────────────────────────────────────────────────────────

#[test]
fn epoch_is_2025_01_01() {
    let epoch = time::OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    assert_eq!(epoch.year(), 2025);
    assert_eq!(epoch.month(), time::Month::January);
    assert_eq!(epoch.day(), 1);
}

#[test]
fn window_days_constant() {
    assert_eq!(BASE_TIME_WINDOW_DAYS, 365);
}

#[test]
fn serial_bytes_constant() {
    assert_eq!(SERIAL_NUMBER_BYTES, 16);
}

// ── write_len_prefixed re-export ─────────────────────────────────────

#[test]
fn write_len_prefixed_is_accessible() {
    let mut hasher = uselesskey_core_hash::Hasher::new();
    write_len_prefixed(&mut hasher, b"test-data");
    // Should not panic; the hasher accepted the input
    let _hash = hasher.finalize();
}
