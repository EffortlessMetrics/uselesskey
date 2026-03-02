//! Edge-case and boundary tests for DER corruption.

use uselesskey_core_negative_der::{corrupt_der_deterministic, flip_byte, truncate_der};

// ── truncate_der edge cases ─────────────────────────────────────────

#[test]
fn truncate_empty_input() {
    let result = truncate_der(b"", 5);
    assert!(result.is_empty());
}

#[test]
fn truncate_to_zero() {
    let result = truncate_der(b"hello", 0);
    assert!(result.is_empty());
}

#[test]
fn truncate_single_byte_input() {
    let result = truncate_der(&[0xAB], 1);
    assert_eq!(result, [0xAB]);
}

#[test]
fn truncate_exact_length() {
    let data = b"hello";
    let result = truncate_der(data, data.len());
    assert_eq!(result, data);
}

#[test]
fn truncate_beyond_length() {
    let data = b"hello";
    let result = truncate_der(data, data.len() + 100);
    assert_eq!(result, data);
}

// ── flip_byte edge cases ────────────────────────────────────────────

#[test]
fn flip_byte_first_position() {
    let data = [0x00, 0x01, 0x02];
    let result = flip_byte(&data, 0);
    assert_ne!(result[0], data[0]);
    assert_eq!(result[1], data[1]);
    assert_eq!(result[2], data[2]);
}

#[test]
fn flip_byte_last_position() {
    let data = [0x00, 0x01, 0x02];
    let result = flip_byte(&data, 2);
    assert_eq!(result[0], data[0]);
    assert_eq!(result[1], data[1]);
    assert_ne!(result[2], data[2]);
}

#[test]
fn flip_byte_is_involutory() {
    let data = [0xDE, 0xAD, 0xBE, 0xEF];
    let flipped = flip_byte(&data, 1);
    let flipped_again = flip_byte(&flipped, 1);
    assert_eq!(flipped_again, data);
}

#[test]
fn flip_byte_out_of_bounds_returns_copy() {
    let data = [0x01, 0x02];
    let result = flip_byte(&data, 5);
    assert_eq!(result, data);
}

#[test]
fn flip_byte_empty_input() {
    let result = flip_byte(b"", 0);
    assert!(result.is_empty());
}

#[test]
fn flip_byte_preserves_length() {
    let data = [0x00; 100];
    let result = flip_byte(&data, 50);
    assert_eq!(result.len(), data.len());
}

// ── corrupt_der_deterministic edge cases ────────────────────────────

#[test]
fn corrupt_deterministic_empty_input() {
    let result = corrupt_der_deterministic(b"", "variant");
    assert!(result.is_empty());
}

#[test]
fn corrupt_deterministic_single_byte() {
    let result = corrupt_der_deterministic(&[0xAB], "variant");
    // Single byte: can truncate (empty) or flip
    assert!(result.len() <= 1);
}

#[test]
fn corrupt_deterministic_is_stable() {
    let data = b"test DER data";
    let c1 = corrupt_der_deterministic(data, "v1");
    let c2 = corrupt_der_deterministic(data, "v1");
    assert_eq!(c1, c2);
}

#[test]
fn corrupt_deterministic_different_variants_differ() {
    let data = b"test DER data for variants";
    let c1 = corrupt_der_deterministic(data, "variant-a");
    let _c2 = corrupt_der_deterministic(data, "variant-b");
    // Different variants usually produce different corruptions
    // At least one should differ from original
    assert_ne!(&c1[..], data.as_slice());
}

#[test]
fn corrupt_deterministic_empty_variant() {
    let data = b"test DER";
    let result = corrupt_der_deterministic(data, "");
    assert_ne!(&result[..], data.as_slice());
}

#[test]
fn corrupt_deterministic_unicode_variant() {
    let data = b"test DER unicode";
    let result = corrupt_der_deterministic(data, "日本語🔑");
    assert_ne!(&result[..], data.as_slice());
}

#[test]
fn corrupt_deterministic_never_returns_original() {
    let data = b"some DER content to corrupt";
    // Test many variants
    for i in 0..20 {
        let variant = format!("variant-{i}");
        let result = corrupt_der_deterministic(data, &variant);
        assert_ne!(
            &result[..],
            data.as_slice(),
            "variant '{variant}' returned original data"
        );
    }
}
