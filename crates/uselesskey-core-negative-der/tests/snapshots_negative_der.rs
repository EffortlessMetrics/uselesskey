//! Insta snapshot tests for uselesskey-core-negative-der.
//!
//! Snapshot DER corruption variant shapes — lengths, strategies, determinism.
//! No actual DER content is captured.

use serde::Serialize;
use uselesskey_core_negative_der::{corrupt_der_deterministic, flip_byte, truncate_der};

const SAMPLE_DER: &[u8] = &[0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0x30, 0x40];

#[derive(Serialize)]
struct TruncateShape {
    original_len: usize,
    requested_len: usize,
    result_len: usize,
    was_shortened: bool,
}

#[test]
fn snapshot_truncate_der_shorter() {
    let out = truncate_der(SAMPLE_DER, 3);
    let result = TruncateShape {
        original_len: SAMPLE_DER.len(),
        requested_len: 3,
        result_len: out.len(),
        was_shortened: out.len() < SAMPLE_DER.len(),
    };
    insta::assert_yaml_snapshot!("negative_der_truncate_shorter", result);
}

#[test]
fn snapshot_truncate_der_at_boundary() {
    let out = truncate_der(SAMPLE_DER, SAMPLE_DER.len());
    let result = TruncateShape {
        original_len: SAMPLE_DER.len(),
        requested_len: SAMPLE_DER.len(),
        result_len: out.len(),
        was_shortened: out.len() < SAMPLE_DER.len(),
    };
    insta::assert_yaml_snapshot!("negative_der_truncate_boundary", result);
}

#[test]
fn snapshot_truncate_der_beyond() {
    let out = truncate_der(SAMPLE_DER, SAMPLE_DER.len() + 10);
    let result = TruncateShape {
        original_len: SAMPLE_DER.len(),
        requested_len: SAMPLE_DER.len() + 10,
        result_len: out.len(),
        was_shortened: out.len() < SAMPLE_DER.len(),
    };
    insta::assert_yaml_snapshot!("negative_der_truncate_beyond", result);
}

#[derive(Serialize)]
struct FlipByteShape {
    original_len: usize,
    flip_offset: usize,
    result_len: usize,
    bytes_changed: usize,
}

#[test]
fn snapshot_flip_byte_first() {
    let out = flip_byte(SAMPLE_DER, 0);
    let diffs = out
        .iter()
        .zip(SAMPLE_DER.iter())
        .filter(|(a, b)| a != b)
        .count();
    let result = FlipByteShape {
        original_len: SAMPLE_DER.len(),
        flip_offset: 0,
        result_len: out.len(),
        bytes_changed: diffs,
    };
    insta::assert_yaml_snapshot!("negative_der_flip_first", result);
}

#[test]
fn snapshot_flip_byte_last() {
    let offset = SAMPLE_DER.len() - 1;
    let out = flip_byte(SAMPLE_DER, offset);
    let diffs = out
        .iter()
        .zip(SAMPLE_DER.iter())
        .filter(|(a, b)| a != b)
        .count();
    let result = FlipByteShape {
        original_len: SAMPLE_DER.len(),
        flip_offset: offset,
        result_len: out.len(),
        bytes_changed: diffs,
    };
    insta::assert_yaml_snapshot!("negative_der_flip_last", result);
}

#[test]
fn snapshot_flip_byte_out_of_bounds() {
    let out = flip_byte(SAMPLE_DER, 100);
    let diffs = out
        .iter()
        .zip(SAMPLE_DER.iter())
        .filter(|(a, b)| a != b)
        .count();
    let result = FlipByteShape {
        original_len: SAMPLE_DER.len(),
        flip_offset: 100,
        result_len: out.len(),
        bytes_changed: diffs,
    };
    insta::assert_yaml_snapshot!("negative_der_flip_oob", result);
}

#[derive(Serialize)]
struct DeterministicCorruptShape {
    variant: &'static str,
    original_len: usize,
    result_len: usize,
    differs_from_original: bool,
    is_deterministic: bool,
}

#[test]
fn snapshot_corrupt_deterministic_variant_a() {
    let a = corrupt_der_deterministic(SAMPLE_DER, "corrupt:variant-a");
    let b = corrupt_der_deterministic(SAMPLE_DER, "corrupt:variant-a");
    let result = DeterministicCorruptShape {
        variant: "corrupt:variant-a",
        original_len: SAMPLE_DER.len(),
        result_len: a.len(),
        differs_from_original: a != SAMPLE_DER,
        is_deterministic: a == b,
    };
    insta::assert_yaml_snapshot!("negative_der_deterministic_a", result);
}

#[test]
fn snapshot_corrupt_deterministic_variant_b() {
    let a = corrupt_der_deterministic(SAMPLE_DER, "corrupt:variant-b");
    let b = corrupt_der_deterministic(SAMPLE_DER, "corrupt:variant-b");
    let result = DeterministicCorruptShape {
        variant: "corrupt:variant-b",
        original_len: SAMPLE_DER.len(),
        result_len: a.len(),
        differs_from_original: a != SAMPLE_DER,
        is_deterministic: a == b,
    };
    insta::assert_yaml_snapshot!("negative_der_deterministic_b", result);
}

#[test]
fn snapshot_corrupt_different_variants_differ() {
    let a = corrupt_der_deterministic(SAMPLE_DER, "corrupt:variant-a");
    let b = corrupt_der_deterministic(SAMPLE_DER, "corrupt:variant-b");

    #[derive(Serialize)]
    struct VariantDifference {
        variant_a: &'static str,
        variant_b: &'static str,
        results_differ: bool,
    }

    let result = VariantDifference {
        variant_a: "corrupt:variant-a",
        variant_b: "corrupt:variant-b",
        results_differ: a != b,
    };
    insta::assert_yaml_snapshot!("negative_der_variants_differ", result);
}
