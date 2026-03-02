//! Mutant-killing tests for DER corruption logic.

use uselesskey_core_negative_der::{corrupt_der_deterministic, flip_byte, truncate_der};

#[test]
fn truncate_returns_exact_prefix_bytes() {
    let der = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    assert_eq!(truncate_der(&der, 3), vec![0xAA, 0xBB, 0xCC]);
    assert_eq!(truncate_der(&der, 0), vec![]);
    assert_eq!(truncate_der(&der, 5), der);
    assert_eq!(truncate_der(&der, 100), der);
}

#[test]
fn flip_byte_xors_exactly_one_bit() {
    let der = vec![0x00, 0xFF, 0x80];
    // 0x00 ^ 0x01 = 0x01
    assert_eq!(flip_byte(&der, 0), vec![0x01, 0xFF, 0x80]);
    // 0xFF ^ 0x01 = 0xFE
    assert_eq!(flip_byte(&der, 1), vec![0x00, 0xFE, 0x80]);
    // 0x80 ^ 0x01 = 0x81
    assert_eq!(flip_byte(&der, 2), vec![0x00, 0xFF, 0x81]);
}

#[test]
fn flip_byte_out_of_bounds_returns_original() {
    let der = vec![0x30, 0x82];
    assert_eq!(flip_byte(&der, 2), der);
    assert_eq!(flip_byte(&der, 100), der);
}

#[test]
fn flip_byte_empty_returns_empty() {
    let der: Vec<u8> = vec![];
    assert_eq!(flip_byte(&der, 0), der);
}

#[test]
fn corrupt_deterministic_same_variant_same_output() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0xFF, 0xAA];
    let a = corrupt_der_deterministic(&der, "test-v1");
    let b = corrupt_der_deterministic(&der, "test-v1");
    assert_eq!(a, b);
}

#[test]
fn corrupt_deterministic_different_variant_different_output() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0xFF, 0xAA];
    let a = corrupt_der_deterministic(&der, "var-1");
    let b = corrupt_der_deterministic(&der, "var-2");
    assert_ne!(a, b);
}

#[test]
fn corrupt_deterministic_always_differs_from_original() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0xFF, 0xAA];
    // Test multiple variants to ensure none return the original
    for i in 0..20 {
        let variant = format!("v{i}");
        let corrupted = corrupt_der_deterministic(&der, &variant);
        assert_ne!(corrupted, der, "variant {variant} produced original DER");
    }
}

#[test]
fn flip_byte_is_xor_not_or() {
    // 0x01 ^ 0x01 = 0x00, but 0x01 | 0x01 = 0x01
    let data = vec![0x01];
    let result = flip_byte(&data, 0);
    assert_eq!(result[0], 0x00, "flip must use XOR, not OR");

    // 0x03 ^ 0x01 = 0x02, but 0x03 | 0x01 = 0x03
    let data = vec![0x03];
    let result = flip_byte(&data, 0);
    assert_eq!(result[0], 0x02, "flip must use XOR, not OR");
}

#[test]
fn truncate_single_byte_der() {
    let der = vec![0x42];
    assert_eq!(truncate_der(&der, 0), vec![]);
    assert_eq!(truncate_der(&der, 1), vec![0x42]);
}
