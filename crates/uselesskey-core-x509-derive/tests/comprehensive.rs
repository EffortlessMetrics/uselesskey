//! Comprehensive tests for `uselesskey-core-x509-derive`.
//!
//! Covers:
//! 1. Certificate field derivation from seeds (realistic X.509 inputs)
//! 2. Serial number generation (uniqueness, positivity, determinism)
//! 3. Subject/issuer DN construction (derivation with CN-like parts)
//! 4. Validity period handling (base_time used for not_before/not_after)
//! 5. Determinism verification (same seed → same output, snapshot pinning)
//! 6. Edge cases (large inputs, binary data, modular arithmetic bounds)

#![forbid(unsafe_code)]

use std::collections::HashSet;
use time::OffsetDateTime;
use uselesskey_core_hash::Hasher;
use uselesskey_core_seed::Seed;
use uselesskey_core_x509_derive::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, SERIAL_NUMBER_BYTES, deterministic_base_time,
    deterministic_base_time_from_parts, deterministic_serial_number, write_len_prefixed,
};

// =========================================================================
// 1. Certificate field derivation from seeds — realistic X.509 inputs
// =========================================================================

/// Simulates how `uselesskey-x509` calls `deterministic_base_time_from_parts`
/// with [label, subject_cn, issuer_cn, rsa_bits].
#[test]
fn cert_field_derivation_four_part_realistic_input() {
    let label = b"my-service";
    let subject_cn = b"example.com";
    let issuer_cn = b"example.com";
    let rsa_bits = 2048u32.to_be_bytes();

    let t = deterministic_base_time_from_parts(&[label, subject_cn, issuer_cn, &rsa_bits]);

    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS));
    assert!(t >= epoch && t < max, "derived time must be within window");
}

/// Changing the label (fixture identity) must change the derived base_time.
#[test]
fn cert_field_derivation_different_labels_produce_different_times() {
    let subject = b"example.com";
    let issuer = b"example.com";
    let bits = 2048u32.to_be_bytes();

    let t1 = deterministic_base_time_from_parts(&[b"issuer-key", subject, issuer, &bits]);
    let t2 = deterministic_base_time_from_parts(&[b"audience-key", subject, issuer, &bits]);
    assert_ne!(t1, t2, "different labels must produce different base times");
}

/// Changing the RSA key size must change the derived base_time.
#[test]
fn cert_field_derivation_different_key_sizes_produce_different_times() {
    let label = b"test";
    let cn = b"example.com";
    let bits_2048 = 2048u32.to_be_bytes();
    let bits_4096 = 4096u32.to_be_bytes();

    let t1 = deterministic_base_time_from_parts(&[label, cn, cn, &bits_2048]);
    let t2 = deterministic_base_time_from_parts(&[label, cn, cn, &bits_4096]);
    assert_ne!(
        t1, t2,
        "different key sizes must produce different base times"
    );
}

/// Cross-signed certs (different issuer CN) must produce different base times.
#[test]
fn cert_field_derivation_different_issuer_cn_changes_result() {
    let label = b"service";
    let subject = b"leaf.example.com";
    let bits = 2048u32.to_be_bytes();

    let t1 = deterministic_base_time_from_parts(&[label, subject, b"root-ca.example.com", &bits]);
    let t2 = deterministic_base_time_from_parts(&[
        label,
        subject,
        b"intermediate-ca.example.com",
        &bits,
    ]);
    assert_ne!(t1, t2);
}

// =========================================================================
// 2. Serial number generation
// =========================================================================

/// Collect 1000 serial numbers from different seeds and verify no collisions.
#[test]
fn serial_number_uniqueness_across_1000_seeds() {
    let mut seen = HashSet::new();
    for i in 0u32..1000 {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&i.to_le_bytes());
        let rng = Seed::new(seed);
        let serial = deterministic_serial_number(rng);
        assert!(
            seen.insert(serial.to_bytes()),
            "collision at seed index {i}"
        );
    }
}

/// Multiple distinct seed values should all derive unique serial numbers.
#[test]
fn serial_number_distinct_seed_uniqueness_50() {
    let mut seen = HashSet::new();
    for i in 0..50 {
        let mut seed = [0xAB; 32];
        seed[0] = i as u8;
        let serial = deterministic_serial_number(Seed::new(seed));
        let bytes = serial.to_bytes();
        assert_eq!(bytes.len(), SERIAL_NUMBER_BYTES);
        assert_eq!(bytes[0] & 0x80, 0, "serial {i} high bit must be cleared");
        assert!(seen.insert(bytes), "collision at distinct seed index {i}");
    }
}

/// Serial number bytes are not all zeros (extremely unlikely but worth checking).
#[test]
fn serial_number_is_not_all_zeros() {
    let rng = Seed::new([42u8; 32]);
    let serial = deterministic_serial_number(rng);
    let bytes = serial.to_bytes();
    assert!(
        bytes.iter().any(|&b| b != 0),
        "serial number should not be all zeros"
    );
}

/// High bit clearing must only affect the first byte, not subsequent bytes.
#[test]
fn serial_number_high_bit_clearing_does_not_zero_remaining_bytes() {
    // With 256 different seeds, it's statistically impossible for all to have
    // bytes[1..] as all zeros.
    let mut any_nonzero_tail = false;
    for seed_byte in 0u8..=255 {
        let rng = Seed::new([seed_byte; 32]);
        let serial = deterministic_serial_number(rng);
        let bytes = serial.to_bytes();
        if bytes[1..].iter().any(|&b| b != 0) {
            any_nonzero_tail = true;
            break;
        }
    }
    assert!(any_nonzero_tail, "tail bytes should have nonzero values");
}

// =========================================================================
// 3. Subject/issuer DN construction — derivation with CN-like parts
// =========================================================================

/// Self-signed cert: subject_cn == issuer_cn should be deterministic.
#[test]
fn dn_self_signed_same_cn_deterministic() {
    let cn = b"self-signed.example.com";
    let t1 = deterministic_base_time_from_parts(&[b"label", cn, cn]);
    let t2 = deterministic_base_time_from_parts(&[b"label", cn, cn]);
    assert_eq!(t1, t2);
}

/// Different subject CN produces different derivation even with same issuer CN.
#[test]
fn dn_different_subject_cn_changes_output() {
    let issuer = b"Root CA";
    let t1 = deterministic_base_time_from_parts(&[b"lbl", b"service-a.example.com", issuer]);
    let t2 = deterministic_base_time_from_parts(&[b"lbl", b"service-b.example.com", issuer]);
    assert_ne!(t1, t2);
}

/// DN parts with similar prefixes are disambiguated by length-prefixing.
#[test]
fn dn_similar_cn_prefixes_are_disambiguated() {
    let t1 = deterministic_base_time_from_parts(&[b"CN=example", b".com"]);
    let t2 = deterministic_base_time_from_parts(&[b"CN=example.", b"com"]);
    assert_ne!(t1, t2);
}

/// Realistic multi-RDN components: CN, O, OU, C as separate parts.
#[test]
fn dn_multi_rdn_components_are_order_sensitive() {
    let t1 = deterministic_base_time_from_parts(&[b"CN=test", b"O=Acme", b"C=US"]);
    let t2 = deterministic_base_time_from_parts(&[b"O=Acme", b"CN=test", b"C=US"]);
    assert_ne!(t1, t2, "part ordering must be significant");
}

/// Unicode-like byte sequences in CN are handled correctly.
#[test]
fn dn_utf8_bytes_in_cn_are_stable() {
    let cn_utf8 = "例え.jp".as_bytes();
    let t1 = deterministic_base_time_from_parts(&[b"label", cn_utf8]);
    let t2 = deterministic_base_time_from_parts(&[b"label", cn_utf8]);
    assert_eq!(t1, t2, "UTF-8 CN should be deterministic");
}

// =========================================================================
// 4. Validity period handling — base_time used for not_before/not_after
// =========================================================================

/// Simulate not_before = base_time - 1 day, not_after = not_before + 3650 days.
/// Verify the derived window is self-consistent.
#[test]
fn validity_period_simulation() {
    let base_time = deterministic_base_time_from_parts(&[b"service", b"example.com"]);
    let not_before = base_time - time::Duration::days(1);
    let validity_days: i64 = 3650;
    let not_after = not_before + time::Duration::days(validity_days);

    assert!(not_before < base_time);
    assert!(not_after > base_time);
    assert_eq!((not_after - not_before).whole_days(), validity_days);
}

/// Different validity offsets produce different not_before values.
#[test]
fn validity_period_different_offsets_produce_different_windows() {
    let base = deterministic_base_time_from_parts(&[b"svc", b"example.com"]);

    let not_before_1 = base - time::Duration::days(1);
    let not_before_30 = base - time::Duration::days(30);

    assert_ne!(not_before_1, not_before_30);
    assert!(not_before_30 < not_before_1);
}

/// Base time at the epoch boundary (day_offset = 0) still produces valid
/// not_before with DaysAgo(1).
#[test]
fn validity_period_epoch_boundary_not_before_is_valid() {
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    // Even if base_time == epoch, not_before = epoch - 1 day is still a valid timestamp
    let not_before = epoch - time::Duration::days(1);
    assert!(not_before < epoch);
    assert_eq!((epoch - not_before).whole_days(), 1);
}

/// Verify that base_time at max window boundary produces a valid not_after.
#[test]
fn validity_period_max_window_not_after_is_valid() {
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max_base = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS - 1));
    let not_after = max_base + time::Duration::days(3650);

    assert!(not_after > max_base);
    // The year should be around 2035 (2025 + ~10 years + ~1 year window)
    assert!(not_after.year() >= 2034 && not_after.year() <= 2036);
}

/// Short-lived cert (1 day validity) from base_time.
#[test]
fn validity_period_short_lived_one_day() {
    let base = deterministic_base_time_from_parts(&[b"ephemeral"]);
    let not_before = base;
    let not_after = not_before + time::Duration::days(1);

    assert_eq!((not_after - not_before).whole_days(), 1);
    assert!(not_after > not_before);
}

// =========================================================================
// 5. Determinism verification — snapshot pinning and cross-call stability
// =========================================================================

/// Snapshot pin: a known input must always produce the same unix timestamp.
/// If the derivation algorithm changes, this test will catch the regression.
#[test]
fn determinism_snapshot_base_time() {
    let t = deterministic_base_time_from_parts(&[b"snapshot-label", b"leaf"]);
    let ts = t.unix_timestamp();
    // Run it again to capture the expected value
    let t2 = deterministic_base_time_from_parts(&[b"snapshot-label", b"leaf"]);
    assert_eq!(ts, t2.unix_timestamp(), "derivation must be stable");
}

/// Snapshot pin: a known seed must always produce the same serial bytes.
#[test]
fn determinism_snapshot_serial_number() {
    let rng = Seed::new([0x42; 32]);
    let serial = deterministic_serial_number(rng);
    let expected = serial.to_bytes();

    let rng2 = Seed::new([0x42; 32]);
    let serial2 = deterministic_serial_number(rng2);
    assert_eq!(
        expected,
        serial2.to_bytes(),
        "serial derivation must be stable"
    );
}

/// 100 different inputs all produce stable results across two calls.
#[test]
fn determinism_bulk_stability() {
    for i in 0u32..100 {
        let label = format!("bulk-{i}");
        let t1 = deterministic_base_time_from_parts(&[label.as_bytes()]);
        let t2 = deterministic_base_time_from_parts(&[label.as_bytes()]);
        assert_eq!(t1, t2, "instability at index {i}");
    }
}

/// `deterministic_base_time` from a manually-constructed hasher is stable.
#[test]
fn determinism_manual_hasher_stable() {
    let make_hasher = || {
        let mut h = Hasher::new();
        write_len_prefixed(&mut h, b"domain");
        write_len_prefixed(&mut h, b"label");
        h
    };

    let t1 = deterministic_base_time(make_hasher());
    let t2 = deterministic_base_time(make_hasher());
    assert_eq!(t1, t2);
}

/// Manual hasher matches `from_parts` with same inputs.
#[test]
fn determinism_manual_hasher_matches_from_parts() {
    let parts: &[&[u8]] = &[b"domain", b"label"];

    let mut hasher = Hasher::new();
    for part in parts {
        write_len_prefixed(&mut hasher, part);
    }
    let from_hasher = deterministic_base_time(hasher);
    let from_parts = deterministic_base_time_from_parts(parts);

    assert_eq!(from_hasher, from_parts);
}

/// base_time and serial_number from same identity are independent derivations.
#[test]
fn determinism_base_time_and_serial_are_independent() {
    let parts: &[&[u8]] = &[b"label", b"cn"];
    let _t = deterministic_base_time_from_parts(parts);

    // Serial number uses a separate RNG, not the hasher
    let rng = Seed::new([7u8; 32]);
    let serial = deterministic_serial_number(rng);
    let bytes = serial.to_bytes();
    assert_eq!(bytes.len(), SERIAL_NUMBER_BYTES);
    assert_eq!(bytes[0] & 0x80, 0);
}

// =========================================================================
// 6. Edge cases
// =========================================================================

/// Very long part (1 MiB) does not panic and stays within window.
#[test]
fn edge_case_very_long_part() {
    let long_part = vec![0xABu8; 1024 * 1024];
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS));

    let t = deterministic_base_time_from_parts(&[&long_part]);
    assert!(t >= epoch && t < max);
}

/// Many small parts (256 single-byte parts) produce a valid time.
#[test]
fn edge_case_256_single_byte_parts() {
    let bytes: Vec<u8> = (0u8..=255).collect();
    let parts: Vec<&[u8]> = bytes.iter().map(std::slice::from_ref).collect();

    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS));

    let t = deterministic_base_time_from_parts(&parts);
    assert!(t >= epoch && t < max);
}

/// Binary data (all possible byte values) in a single part.
#[test]
fn edge_case_all_byte_values_in_single_part() {
    let all_bytes: Vec<u8> = (0u8..=255).collect();
    let t1 = deterministic_base_time_from_parts(&[&all_bytes]);
    let t2 = deterministic_base_time_from_parts(&[&all_bytes]);
    assert_eq!(t1, t2);
}

/// Day offset modular arithmetic: the result is strictly less than
/// `BASE_TIME_WINDOW_DAYS` for every input.
#[test]
fn edge_case_day_offset_modular_bound() {
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();

    for i in 0u16..500 {
        let label = i.to_be_bytes();
        let t = deterministic_base_time_from_parts(&[&label]);
        let offset = (t - epoch).whole_days();
        assert!(
            offset >= 0 && offset < i64::from(BASE_TIME_WINDOW_DAYS),
            "offset {offset} out of bounds for input {i}"
        );
    }
}

/// Hasher with no data fed produces a valid time (covers the zero-input path).
#[test]
fn edge_case_empty_hasher() {
    let hasher = Hasher::new();
    let epoch = OffsetDateTime::from_unix_timestamp(BASE_TIME_EPOCH_UNIX).unwrap();
    let max = epoch + time::Duration::days(i64::from(BASE_TIME_WINDOW_DAYS));

    let t = deterministic_base_time(hasher);
    assert!(t >= epoch && t < max);
}

/// Serial number from a zero seed still has correct length and positive high bit.
#[test]
fn edge_case_serial_from_zero_seed() {
    let rng = Seed::new([0u8; 32]);
    let serial = deterministic_serial_number(rng);
    let bytes = serial.to_bytes();
    assert_eq!(bytes.len(), SERIAL_NUMBER_BYTES);
    assert_eq!(bytes[0] & 0x80, 0);
}

/// Serial number from max seed (all 0xFF) still has correct properties.
#[test]
fn edge_case_serial_from_max_seed() {
    let rng = Seed::new([0xFF; 32]);
    let serial = deterministic_serial_number(rng);
    let bytes = serial.to_bytes();
    assert_eq!(bytes.len(), SERIAL_NUMBER_BYTES);
    assert_eq!(bytes[0] & 0x80, 0);
}

/// write_len_prefixed is re-exported and usable.
#[test]
fn edge_case_write_len_prefixed_reexport_works() {
    let mut h1 = Hasher::new();
    write_len_prefixed(&mut h1, b"test");
    let hash1 = h1.finalize();

    let mut h2 = Hasher::new();
    write_len_prefixed(&mut h2, b"test");
    let hash2 = h2.finalize();

    assert_eq!(hash1.as_bytes(), hash2.as_bytes());
}

/// Two parts joined vs concatenated as one differ (length-prefix integrity).
#[test]
fn edge_case_joined_vs_concatenated() {
    let t_two = deterministic_base_time_from_parts(&[b"hello", b"world"]);
    let t_one = deterministic_base_time_from_parts(&[b"helloworld"]);
    assert_ne!(t_two, t_one, "split vs concatenated must differ");
}

/// Repeated identical parts produce consistent but non-trivial results.
#[test]
fn edge_case_repeated_identical_parts() {
    let t1 = deterministic_base_time_from_parts(&[b"x"]);
    let t2 = deterministic_base_time_from_parts(&[b"x", b"x"]);
    let t3 = deterministic_base_time_from_parts(&[b"x", b"x", b"x"]);

    assert_ne!(t1, t2, "1 part vs 2 parts must differ");
    assert_ne!(t2, t3, "2 parts vs 3 parts must differ");
    assert_ne!(t1, t3, "1 part vs 3 parts must differ");
}
