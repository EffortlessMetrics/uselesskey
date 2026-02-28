//! Integration tests for `uselesskey-core-x509-derive`.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use time::OffsetDateTime;
use uselesskey_core_x509_derive::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, SERIAL_NUMBER_BYTES, deterministic_base_time,
    deterministic_base_time_from_parts, deterministic_serial_number, write_len_prefixed,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn epoch_is_2025_01_01() {
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    assert_eq!(epoch.year(), 2025);
    assert_eq!(epoch.month() as u8, 1);
    assert_eq!(epoch.day(), 1);
}

#[test]
fn window_is_one_year() {
    assert_eq!(BASE_TIME_WINDOW_DAYS, 365);
}

#[test]
fn serial_number_length_is_16() {
    assert_eq!(SERIAL_NUMBER_BYTES, 16);
}

// ---------------------------------------------------------------------------
// Validity period / base-time derivation
// ---------------------------------------------------------------------------

#[test]
fn base_time_from_parts_falls_within_epoch_window() {
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS - 1));

    // Try several different identity tuples
    let cases: &[&[&[u8]]] = &[
        &[b"issuer", b"leaf"],
        &[b"root-ca", b"intermediate", b"RS256", b"2048"],
        &[b""],
        &[b"a"],
        &[b"x", b"x", b"x", b"x", b"x", b"x", b"x", b"x", b"x", b"x"],
    ];
    for parts in cases {
        let t = deterministic_base_time_from_parts(parts);
        assert!(t >= epoch, "base time {t} < epoch {epoch}");
        assert!(t <= max, "base time {t} > max {max}");
    }
}

#[test]
fn base_time_from_empty_parts_is_within_window() {
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS - 1));

    let t = deterministic_base_time_from_parts(&[]);
    assert!(t >= epoch);
    assert!(t <= max);
}

#[test]
fn base_time_is_deterministic_across_calls() {
    let parts: &[&[u8]] = &[b"cn=test", b"leaf", b"P-256"];
    let a = deterministic_base_time_from_parts(parts);
    let b = deterministic_base_time_from_parts(parts);
    assert_eq!(a, b, "same inputs must produce the same base time");
}

#[test]
fn base_time_differs_for_different_labels() {
    let a = deterministic_base_time_from_parts(&[b"issuer-a"]);
    let b = deterministic_base_time_from_parts(&[b"issuer-b"]);
    assert_ne!(
        a, b,
        "different labels should (very likely) produce different base times"
    );
}

#[test]
fn base_time_boundary_ambiguity_is_prevented() {
    // "ab" + "c" must differ from "a" + "bc"
    let a = deterministic_base_time_from_parts(&[b"ab", b"c"]);
    let b = deterministic_base_time_from_parts(&[b"a", b"bc"]);
    assert_ne!(
        a, b,
        "length-prefixed hashing must prevent boundary collisions"
    );
}

#[test]
fn base_time_order_of_parts_matters() {
    let a = deterministic_base_time_from_parts(&[b"issuer", b"subject"]);
    let b = deterministic_base_time_from_parts(&[b"subject", b"issuer"]);
    assert_ne!(a, b, "swapping part order should change the result");
}

#[test]
fn base_time_extra_part_changes_result() {
    let a = deterministic_base_time_from_parts(&[b"label"]);
    let b = deterministic_base_time_from_parts(&[b"label", b""]);
    // Even an empty extra part changes the hash because of the length prefix.
    assert_ne!(a, b, "extra empty part should change the result");
}

#[test]
fn base_time_via_raw_hasher_matches_from_parts() {
    use uselesskey_core_hash::Hasher;

    let parts: &[&[u8]] = &[b"domain", b"label"];
    let from_parts = deterministic_base_time_from_parts(parts);

    let mut hasher = Hasher::new();
    for p in parts {
        write_len_prefixed(&mut hasher, p);
    }
    let from_hasher = deterministic_base_time(hasher);

    assert_eq!(from_parts, from_hasher);
}

#[test]
fn base_time_is_always_at_day_boundary() {
    // The derived time should have zero sub-day components because only
    // whole-day offsets are added to the epoch.
    let t = deterministic_base_time_from_parts(&[b"check-day-boundary"]);
    assert_eq!(t.hour(), 0);
    assert_eq!(t.minute(), 0);
    assert_eq!(t.second(), 0);
    assert_eq!(t.nanosecond(), 0);
}

// ---------------------------------------------------------------------------
// Serial number generation
// ---------------------------------------------------------------------------

#[test]
fn serial_number_has_correct_length() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let serial = deterministic_serial_number(&mut rng);
    assert_eq!(serial.to_bytes().len(), SERIAL_NUMBER_BYTES);
}

#[test]
fn serial_number_high_bit_is_cleared() {
    // Try many seeds to exercise the clearing logic.
    for seed_byte in 0u8..=255 {
        let mut rng = ChaCha20Rng::from_seed([seed_byte; 32]);
        let serial = deterministic_serial_number(&mut rng);
        let bytes = serial.to_bytes();
        assert_eq!(
            bytes[0] & 0x80,
            0,
            "high bit must be cleared for seed {seed_byte}"
        );
    }
}

#[test]
fn serial_number_is_deterministic_for_same_seed() {
    let seed = [99u8; 32];
    let a = deterministic_serial_number(&mut ChaCha20Rng::from_seed(seed));
    let b = deterministic_serial_number(&mut ChaCha20Rng::from_seed(seed));
    assert_eq!(a.to_bytes(), b.to_bytes());
}

#[test]
fn serial_number_differs_for_different_seeds() {
    let a = deterministic_serial_number(&mut ChaCha20Rng::from_seed([10u8; 32]));
    let b = deterministic_serial_number(&mut ChaCha20Rng::from_seed([20u8; 32]));
    assert_ne!(a.to_bytes(), b.to_bytes());
}

#[test]
fn serial_number_consecutive_calls_differ() {
    let mut rng = ChaCha20Rng::from_seed([55u8; 32]);
    let first = deterministic_serial_number(&mut rng);
    let second = deterministic_serial_number(&mut rng);
    assert_ne!(
        first.to_bytes(),
        second.to_bytes(),
        "consecutive serials from the same RNG should differ"
    );
}

// ---------------------------------------------------------------------------
// Subject / issuer name derivation (via from_parts)
// ---------------------------------------------------------------------------

#[test]
fn subject_issuer_pair_produces_unique_times() {
    // Simulates how a fixture crate would derive times for different
    // certificates in the same chain using subject/issuer identity tuples.
    let root = deterministic_base_time_from_parts(&[b"root-ca", b"root-ca", b"RS256"]);
    let intermediate = deterministic_base_time_from_parts(&[b"intermediate", b"root-ca", b"RS256"]);
    let leaf = deterministic_base_time_from_parts(&[b"leaf", b"intermediate", b"RS256"]);

    // All three should be distinct (statistically guaranteed by BLAKE3).
    assert_ne!(root, intermediate);
    assert_ne!(intermediate, leaf);
    assert_ne!(root, leaf);
}

// ---------------------------------------------------------------------------
// write_len_prefixed re-export
// ---------------------------------------------------------------------------

#[test]
fn write_len_prefixed_is_accessible_and_functional() {
    use uselesskey_core_hash::Hasher;

    let mut h1 = Hasher::new();
    write_len_prefixed(&mut h1, b"hello");

    let mut h2 = Hasher::new();
    h2.update(&5u32.to_be_bytes());
    h2.update(b"hello");

    assert_eq!(h1.finalize(), h2.finalize());
}
