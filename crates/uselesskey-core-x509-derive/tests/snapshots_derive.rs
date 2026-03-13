//! Insta snapshot tests for uselesskey-core-x509-derive.
//!
//! These tests snapshot deterministic base-time derivation and
//! serial-number generation to detect unintended changes.

use serde::Serialize;
use uselesskey_core_seed::Seed;
use uselesskey_core_x509_derive::{
    BASE_TIME_EPOCH_UNIX, BASE_TIME_WINDOW_DAYS, SERIAL_NUMBER_BYTES,
    deterministic_base_time_from_parts, deterministic_serial_number,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct Constants {
    base_time_epoch_unix: i64,
    base_time_window_days: u32,
    serial_number_bytes: usize,
}

#[test]
fn snapshot_constants() {
    let c = Constants {
        base_time_epoch_unix: BASE_TIME_EPOCH_UNIX,
        base_time_window_days: BASE_TIME_WINDOW_DAYS,
        serial_number_bytes: SERIAL_NUMBER_BYTES,
    };
    insta::assert_yaml_snapshot!("derive_constants", c);
}

// ---------------------------------------------------------------------------
// Deterministic base-time
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct BaseTimeSnapshot {
    label: &'static str,
    year: i32,
    ordinal_day: u16,
}

fn base_time_snap(label: &'static str, parts: &[&[u8]]) -> BaseTimeSnapshot {
    let t = deterministic_base_time_from_parts(parts);
    BaseTimeSnapshot {
        label,
        year: t.year(),
        ordinal_day: t.ordinal(),
    }
}

#[test]
fn snapshot_base_time_known_inputs() {
    let results: Vec<BaseTimeSnapshot> = vec![
        base_time_snap("leaf-label", &[b"leaf-label", b"leaf"]),
        base_time_snap("root-ca", &[b"root-ca", b"root", b"2048"]),
        base_time_snap("empty-parts", &[]),
        base_time_snap("single-part", &[b"only"]),
    ];
    insta::assert_yaml_snapshot!("base_time_known_inputs", results);
}

#[test]
fn snapshot_base_time_boundary_safety() {
    let a = deterministic_base_time_from_parts(&[b"ab", b"c"]);
    let b = deterministic_base_time_from_parts(&[b"a", b"bc"]);

    #[derive(Serialize)]
    struct BoundarySafety {
        ab_c_ordinal: u16,
        a_bc_ordinal: u16,
        differ: bool,
    }

    let snap = BoundarySafety {
        ab_c_ordinal: a.ordinal(),
        a_bc_ordinal: b.ordinal(),
        differ: a != b,
    };
    insta::assert_yaml_snapshot!("base_time_boundary_safety", snap);
}

// ---------------------------------------------------------------------------
// Deterministic serial number
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct SerialSnapshot {
    seed_byte: u8,
    byte_count: usize,
    high_bit_cleared: bool,
    serial_hex: String,
}

#[test]
fn snapshot_serial_numbers() {
    let results: Vec<SerialSnapshot> = [0u8, 42, 255]
        .into_iter()
        .map(|seed_byte| {
            let rng = Seed::new([seed_byte; 32]);
            let serial = deterministic_serial_number(rng);
            let bytes = serial.to_bytes();
            SerialSnapshot {
                seed_byte,
                byte_count: bytes.len(),
                high_bit_cleared: bytes[0] & 0x80 == 0,
                serial_hex: "[REDACTED]".to_string(),
            }
        })
        .collect();
    insta::assert_yaml_snapshot!("serial_numbers", results);
}

#[test]
fn snapshot_serial_determinism() {
    let rng_a = Seed::new([42u8; 32]);
    let rng_b = Seed::new([42u8; 32]);

    let serial_a = deterministic_serial_number(rng_a);
    let serial_b = deterministic_serial_number(rng_b);

    #[derive(Serialize)]
    struct Determinism {
        same_seed_same_serial: bool,
        byte_count: usize,
    }

    let snap = Determinism {
        same_seed_same_serial: serial_a.to_bytes() == serial_b.to_bytes(),
        byte_count: serial_a.to_bytes().len(),
    };
    insta::assert_yaml_snapshot!("serial_determinism", snap);
}
