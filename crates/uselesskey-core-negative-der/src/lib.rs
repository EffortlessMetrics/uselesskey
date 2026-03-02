#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

//! DER corruption helpers for negative test fixtures.
//!
//! Provides deterministic truncation, byte-flipping, and combined corruption
//! strategies for DER-encoded blobs. Used by higher-level negative fixture
//! crates (`uselesskey-core-negative`) to generate invalid DER artifacts
//! that exercise parser error paths in tests.

extern crate alloc;

use alloc::vec::Vec;

use uselesskey_core_hash::hash32;

pub fn truncate_der(der: &[u8], len: usize) -> Vec<u8> {
    if len >= der.len() {
        return der.to_vec();
    }
    der[..len].to_vec()
}

pub fn flip_byte(der: &[u8], offset: usize) -> Vec<u8> {
    if offset >= der.len() {
        return der.to_vec();
    }

    let mut out = der.to_vec();
    out[offset] ^= 0x01;
    out
}

pub fn corrupt_der_deterministic(der: &[u8], variant: &str) -> Vec<u8> {
    let digest = hash32(variant.as_bytes());
    let bytes = digest.as_bytes();

    match bytes[0] % 3 {
        0 => {
            let len = derived_truncate_len_bytes(der.len(), bytes);
            truncate_der(der, len)
        }
        1 => {
            let offset = derived_offset(der.len(), bytes[1]);
            flip_byte(der, offset)
        }
        _ => {
            let offset = derived_offset(der.len(), bytes[1]);
            let flipped = flip_byte(der, offset);
            let len = derived_truncate_len_bytes(flipped.len(), bytes);
            truncate_der(&flipped, len)
        }
    }
}

fn derived_offset(len: usize, selector: u8) -> usize {
    if len == 0 {
        return 0;
    }
    selector as usize % len
}

fn derived_truncate_len_bytes(len: usize, digest: &[u8; 32]) -> usize {
    if len <= 1 {
        return 0;
    }
    let span = len - 1;
    digest[2] as usize % span
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flip_byte_changes_only_target_offset() {
        let der = vec![0x30, 0x82, 0x01, 0x22];
        let flipped = flip_byte(&der, 0);

        assert_eq!(flipped[0], 0x31);
        assert_eq!(&flipped[1..], &der[1..]);
    }

    #[test]
    fn truncate_der_shortens_when_len_smaller() {
        let der = vec![0x30, 0x82, 0x01, 0x22];
        let truncated = truncate_der(&der, 2);
        assert_eq!(truncated, vec![0x30, 0x82]);
    }

    #[test]
    fn deterministic_der_corruption_is_stable_for_same_variant() {
        let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20];
        let first = corrupt_der_deterministic(&der, "corrupt:variant-a");
        let second = corrupt_der_deterministic(&der, "corrupt:variant-a");
        assert_eq!(first, second);
        assert_ne!(first, der);
    }

    #[test]
    fn derived_truncate_len_bytes_exact_arithmetic() {
        let mut digest = [0u8; 32];
        digest[2] = 0x0B; // 11 % 4 = 3
        assert_eq!(derived_truncate_len_bytes(5, &digest), 3);
    }

    #[test]
    fn derived_truncate_len_bytes_single_returns_zero() {
        let digest = [0u8; 32];
        assert_eq!(derived_truncate_len_bytes(1, &digest), 0);
    }

    #[test]
    fn derived_offset_exact_arithmetic() {
        assert_eq!(derived_offset(5, 7), 2); // 7 % 5 = 2
    }

    #[test]
    fn derived_offset_zero_len_returns_zero() {
        assert_eq!(derived_offset(0, 7), 0);
    }

    #[test]
    fn flip_byte_xor_vs_or_on_set_bit() {
        // XOR: 0x01 ^ 0x01 = 0x00; OR mutation would give 0x01 | 0x01 = 0x01.
        let data = vec![0x01];
        let result = flip_byte(&data, 0);
        assert_eq!(result[0], 0x00);
    }

    #[test]
    fn deterministic_der_arm0_truncation() {
        let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20];
        let variant = find_der_variant(0);
        let out = corrupt_der_deterministic(&der, &variant);
        assert!(out.len() < der.len());
        assert_eq!(&out[..], &der[..out.len()]);
    }

    #[test]
    fn deterministic_der_arm1_flip() {
        let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20];
        let variant = find_der_variant(1);
        let out = corrupt_der_deterministic(&der, &variant);
        assert_eq!(out.len(), der.len());
        let diffs = out.iter().zip(der.iter()).filter(|(a, b)| a != b).count();
        assert_eq!(diffs, 1);
    }

    #[test]
    fn deterministic_der_arm2_flip_truncate() {
        let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20];
        let variant = find_der_variant(2);
        let out = corrupt_der_deterministic(&der, &variant);
        assert!(out.len() < der.len());
    }

    #[test]
    fn deterministic_der_not_constant() {
        let der1 = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20];
        let der2 = vec![0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA];
        let out1 = corrupt_der_deterministic(&der1, "same-variant");
        let out2 = corrupt_der_deterministic(&der2, "same-variant");
        assert_ne!(out1, out2);
    }

    fn find_der_variant(target: u8) -> String {
        use uselesskey_core_hash::hash32;

        for i in 0u64.. {
            let variant = format!("v{i}");
            if hash32(variant.as_bytes()).as_bytes()[0] % 3 == target {
                return variant;
            }
        }
        unreachable!()
    }

    #[test]
    fn truncation_and_flip_produce_distinguishable_results() {
        let der = [0x30, 0x82, 0x01, 0x22, 0x10, 0x20];
        let truncated = truncate_der(&der, 3);
        let flipped = flip_byte(&der, 0);
        assert_ne!(truncated, flipped, "truncation vs flip must differ");
    }

    #[test]
    fn flip_byte_out_of_bounds_returns_original() {
        let der = [0x30, 0x82];
        let result = flip_byte(&der, 99);
        assert_eq!(result, der, "out-of-bounds flip must return original");
    }

    #[test]
    fn truncate_der_larger_len_returns_original() {
        let der = [0x30, 0x82];
        let result = truncate_der(&der, 100);
        assert_eq!(result, der, "oversized truncation must return original");
    }

    #[test]
    fn deterministic_arms_produce_distinguishable_results() {
        let der = [0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0x30, 0x40];
        let arm0 = corrupt_der_deterministic(&der, &find_der_variant(0));
        let arm1 = corrupt_der_deterministic(&der, &find_der_variant(1));
        let arm2 = corrupt_der_deterministic(&der, &find_der_variant(2));

        // arm0 = truncation (shorter), arm1 = flip (same length), arm2 = flip+truncate (shorter)
        assert_ne!(arm0, arm1, "arm0 and arm1 must differ");
        assert_ne!(arm1, arm2, "arm1 and arm2 must differ");
        // arm1 preserves length, arm0 and arm2 do not.
        assert_eq!(arm1.len(), der.len(), "arm1 (flip) preserves length");
        assert!(arm0.len() < der.len(), "arm0 (truncate) shortens");
        assert!(arm2.len() < der.len(), "arm2 (flip+truncate) shortens");
    }

    #[test]
    fn corrupt_der_deterministic_on_empty_input() {
        let der: [u8; 0] = [];
        let result = corrupt_der_deterministic(&der, "variant");
        assert!(result.is_empty(), "corruption of empty input must be empty");
    }
}
