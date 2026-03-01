//! Tests for type properties of values returned by X.509 derivation helpers.
//!
//! The `uselesskey-core-x509-derive` crate returns `time::OffsetDateTime` and
//! `rcgen::SerialNumber` from its public API. These tests verify the returned
//! values satisfy expected trait-level contracts (Eq, Ord, Clone, Debug).

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use uselesskey_core_x509_derive::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, SERIAL_NUMBER_BYTES, deterministic_base_time,
    deterministic_base_time_from_parts, deterministic_serial_number,
};

// ==================== OffsetDateTime trait tests ====================

#[test]
fn base_time_copy_equals_original() {
    let t = deterministic_base_time_from_parts(&[b"label"]);
    let copied = t;
    assert_eq!(t, copied);
}

#[test]
fn base_time_eq_for_same_parts() {
    let a = deterministic_base_time_from_parts(&[b"label", b"leaf"]);
    let b = deterministic_base_time_from_parts(&[b"label", b"leaf"]);
    assert_eq!(a, b);
}

#[test]
fn base_time_ne_for_different_parts() {
    let a = deterministic_base_time_from_parts(&[b"label-a"]);
    let b = deterministic_base_time_from_parts(&[b"label-b"]);
    assert_ne!(a, b);
}

#[test]
fn base_time_ord_is_consistent() {
    let a = deterministic_base_time_from_parts(&[b"alpha"]);
    let b = deterministic_base_time_from_parts(&[b"beta"]);
    let cmp1 = a.cmp(&b);
    let cmp2 = a.cmp(&b);
    assert_eq!(cmp1, cmp2);
}

#[test]
fn base_time_debug_is_nonempty() {
    let t = deterministic_base_time_from_parts(&[b"label"]);
    let debug = format!("{t:?}");
    assert!(!debug.is_empty());
}

#[test]
fn base_time_partial_ord_matches_ord() {
    let a = deterministic_base_time_from_parts(&[b"x"]);
    let b = deterministic_base_time_from_parts(&[b"y"]);
    assert_eq!(a.partial_cmp(&b), Some(a.cmp(&b)));
}

// ==================== SerialNumber trait tests ====================

#[test]
fn serial_number_clone_equals_original() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let serial = deterministic_serial_number(&mut rng);
    let cloned = serial.clone();
    assert_eq!(serial.to_bytes(), cloned.to_bytes());
}

#[test]
fn serial_number_debug_is_nonempty() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let serial = deterministic_serial_number(&mut rng);
    let debug = format!("{serial:?}");
    assert!(!debug.is_empty());
}

#[test]
fn serial_number_deterministic_from_same_seed() {
    let mut rng_a = ChaCha20Rng::from_seed([99u8; 32]);
    let mut rng_b = ChaCha20Rng::from_seed([99u8; 32]);
    let a = deterministic_serial_number(&mut rng_a);
    let b = deterministic_serial_number(&mut rng_b);
    assert_eq!(a.to_bytes(), b.to_bytes());
}

#[test]
fn serial_number_differs_across_seeds() {
    let mut rng_a = ChaCha20Rng::from_seed([1u8; 32]);
    let mut rng_b = ChaCha20Rng::from_seed([2u8; 32]);
    let a = deterministic_serial_number(&mut rng_a);
    let b = deterministic_serial_number(&mut rng_b);
    assert_ne!(a.to_bytes(), b.to_bytes());
}

// ==================== Constants ====================

#[test]
fn epoch_constant_is_2025_01_01() {
    let epoch =
        time::OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).expect("valid epoch");
    assert_eq!(epoch.year(), 2025);
    assert_eq!(epoch.month(), time::Month::January);
    assert_eq!(epoch.day(), 1);
}

#[test]
fn window_days_is_one_year() {
    assert_eq!(BASE_TIME_WINDOW_DAYS, 365);
}

#[test]
fn serial_number_bytes_is_sixteen() {
    assert_eq!(SERIAL_NUMBER_BYTES, 16);
}

// ==================== Hasher (used internally) ====================

#[test]
fn deterministic_base_time_from_hasher_is_stable() {
    let hasher = uselesskey_core_hash::Hasher::new();
    let a = deterministic_base_time(hasher);

    let hasher = uselesskey_core_hash::Hasher::new();
    let b = deterministic_base_time(hasher);

    assert_eq!(a, b);
}
