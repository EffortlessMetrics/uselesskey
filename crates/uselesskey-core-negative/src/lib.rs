#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use uselesskey_core_id::hash32;

/// Strategies for corrupting PEM-encoded data.
#[derive(Clone, Copy, Debug)]
pub enum CorruptPem {
    BadHeader,
    BadFooter,
    BadBase64,
    Truncate { bytes: usize },
    ExtraBlankLine,
}

pub fn corrupt_pem(pem: &str, how: CorruptPem) -> String {
    match how {
        CorruptPem::BadHeader => replace_first_line(pem, "-----BEGIN CORRUPTED KEY-----"),
        CorruptPem::BadFooter => replace_last_line(pem, "-----END CORRUPTED KEY-----"),
        CorruptPem::BadBase64 => inject_bad_base64_line(pem),
        CorruptPem::Truncate { bytes } => pem.chars().take(bytes).collect(),
        CorruptPem::ExtraBlankLine => inject_blank_line(pem),
    }
}

pub fn corrupt_pem_deterministic(pem: &str, variant: &str) -> String {
    let digest = hash32(variant.as_bytes());
    let bytes = digest.as_bytes();

    match bytes[0] % 5 {
        0 => corrupt_pem(pem, CorruptPem::BadHeader),
        1 => corrupt_pem(pem, CorruptPem::BadFooter),
        2 => corrupt_pem(pem, CorruptPem::BadBase64),
        3 => corrupt_pem(pem, CorruptPem::ExtraBlankLine),
        _ => {
            let bytes = derived_truncate_len(pem, bytes);
            corrupt_pem(pem, CorruptPem::Truncate { bytes })
        }
    }
}

fn derived_truncate_len(pem: &str, digest: &[u8; 32]) -> usize {
    let chars = pem.chars().count();
    if chars <= 1 {
        return 0;
    }

    let span = chars - 1;
    1 + (u16::from_be_bytes([digest[1], digest[2]]) as usize % span)
}

fn replace_first_line(pem: &str, replacement: &str) -> String {
    let mut lines = pem.lines();
    let _first = lines.next();

    let mut out = String::new();
    out.push_str(replacement);
    out.push('\n');

    for l in lines {
        out.push_str(l);
        out.push('\n');
    }

    out
}

fn replace_last_line(pem: &str, replacement: &str) -> String {
    let mut all: Vec<&str> = pem.lines().collect();
    if all.is_empty() {
        return replacement.to_string();
    }
    let last_idx = all.len() - 1;
    all[last_idx] = replacement;

    let mut out = String::new();
    for l in all {
        out.push_str(l);
        out.push('\n');
    }
    out
}

fn inject_bad_base64_line(pem: &str) -> String {
    let mut lines: Vec<&str> = pem.lines().collect();
    if lines.len() < 3 {
        return alloc::format!("{pem}\nTHIS_IS_NOT_BASE64!!!\n");
    }

    lines.insert(1, "THIS_IS_NOT_BASE64!!!");

    let mut out = String::new();
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
    out
}

fn inject_blank_line(pem: &str) -> String {
    let mut lines: Vec<&str> = pem.lines().collect();
    if lines.len() < 3 {
        return alloc::format!("{pem}\n\n");
    }
    lines.insert(1, "");

    let mut out = String::new();
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
    out
}

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
    use std::collections::HashSet;

    use super::{
        CorruptPem, corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic,
        derived_offset, derived_truncate_len, derived_truncate_len_bytes, flip_byte,
        inject_bad_base64_line, inject_blank_line, truncate_der,
    };
    use uselesskey_core_id::hash32;

    #[test]
    fn bad_header_replaces_first_line() {
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let out = corrupt_pem(pem, CorruptPem::BadHeader);
        assert!(out.starts_with("-----BEGIN CORRUPTED KEY-----\n"));
    }

    #[test]
    fn bad_footer_replaces_last_line() {
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let out = corrupt_pem(pem, CorruptPem::BadFooter);
        assert!(out.contains("-----END CORRUPTED KEY-----\n"));
    }

    #[test]
    fn bad_footer_on_empty_input_returns_replacement() {
        let out = corrupt_pem("", CorruptPem::BadFooter);
        assert_eq!(out, "-----END CORRUPTED KEY-----");
    }

    #[test]
    fn bad_base64_short_input_inserts_line() {
        let out = corrupt_pem("x", CorruptPem::BadBase64);
        assert_eq!(out, "x\nTHIS_IS_NOT_BASE64!!!\n");
    }

    #[test]
    fn extra_blank_line_short_input_appends_newlines() {
        let out = corrupt_pem("x", CorruptPem::ExtraBlankLine);
        assert_eq!(out, "x\n\n");
    }

    #[test]
    fn truncate_variant_limits_length() {
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let out = corrupt_pem(pem, CorruptPem::Truncate { bytes: 10 });
        assert_eq!(out.len(), 10);
    }

    #[test]
    fn deterministic_corruption_is_stable_for_same_variant() {
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let first = corrupt_pem_deterministic(pem, "corrupt:variant-a");
        let second = corrupt_pem_deterministic(pem, "corrupt:variant-a");
        assert_eq!(first, second);
    }

    #[test]
    fn deterministic_corruption_produces_multiple_shapes_across_variants() {
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let variants = ["a", "b", "c", "d", "e", "f", "g", "h"];
        let mut outputs = HashSet::new();
        for v in variants {
            outputs.insert(corrupt_pem_deterministic(pem, v));
        }
        assert!(outputs.len() >= 2);
    }

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

    // ---- variant discovery helpers ----

    /// Find a variant string whose `hash32` first byte % 5 == target.
    fn find_pem_variant(target: u8) -> String {
        for i in 0u64.. {
            let v = format!("v{i}");
            let digest = hash32(v.as_bytes());
            if digest.as_bytes()[0] % 5 == target {
                return v;
            }
        }
        unreachable!()
    }

    /// Find a variant string whose `hash32` first byte % 3 == target.
    fn find_der_variant(target: u8) -> String {
        for i in 0u64.. {
            let v = format!("v{i}");
            let digest = hash32(v.as_bytes());
            if digest.as_bytes()[0] % 3 == target {
                return v;
            }
        }
        unreachable!()
    }

    // ---- derived_truncate_len ----

    #[test]
    fn derived_truncate_len_exact_arithmetic() {
        let pem = "abcde"; // 5 chars
        let mut digest = [0u8; 32];
        digest[1] = 0x00;
        digest[2] = 0x0B; // u16::from_be_bytes([0x00, 0x0B]) = 11, 11 % 4 = 3, 1 + 3 = 4
        assert_eq!(derived_truncate_len(pem, &digest), 4);
    }

    #[test]
    fn derived_truncate_len_single_char_returns_zero() {
        let pem = "x"; // 1 char
        let digest = [0u8; 32];
        assert_eq!(derived_truncate_len(pem, &digest), 0);
    }

    // ---- derived_truncate_len_bytes ----

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

    // ---- derived_offset ----

    #[test]
    fn derived_offset_exact_arithmetic() {
        assert_eq!(derived_offset(5, 7), 2); // 7 % 5 = 2
    }

    #[test]
    fn derived_offset_zero_len_returns_zero() {
        assert_eq!(derived_offset(0, 7), 0);
    }

    // ---- flip_byte ----

    #[test]
    fn flip_byte_xor_vs_or_on_set_bit() {
        // XOR: 0x01 ^ 0x01 = 0x00; OR mutation would give 0x01 | 0x01 = 0x01
        let data = vec![0x01];
        let result = flip_byte(&data, 0);
        assert_eq!(result[0], 0x00);
    }

    // ---- inject_bad_base64_line ----

    #[test]
    fn inject_bad_base64_two_lines_early_return() {
        let pem = "HEADER\nBODY";
        let out = inject_bad_base64_line(pem);
        assert_eq!(out, "HEADER\nBODY\nTHIS_IS_NOT_BASE64!!!\n");
    }

    #[test]
    fn inject_bad_base64_three_lines_inserts() {
        let pem = "HEADER\nBODY\nFOOTER";
        let out = inject_bad_base64_line(pem);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "HEADER");
        assert_eq!(lines[1], "THIS_IS_NOT_BASE64!!!");
        assert_eq!(lines[2], "BODY");
        assert_eq!(lines[3], "FOOTER");
    }

    // ---- inject_blank_line ----

    #[test]
    fn inject_blank_line_two_lines_early_return() {
        let pem = "HEADER\nBODY";
        let out = inject_blank_line(pem);
        assert_eq!(out, "HEADER\nBODY\n\n");
    }

    #[test]
    fn inject_blank_line_three_lines_inserts() {
        let pem = "HEADER\nBODY\nFOOTER";
        let out = inject_blank_line(pem);
        assert!(out.contains("HEADER\n\n"));
    }

    // ---- corrupt_pem_deterministic arm-specific ----

    #[test]
    fn deterministic_pem_arm0_bad_header() {
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let variant = find_pem_variant(0);
        let out = corrupt_pem_deterministic(pem, &variant);
        assert!(out.contains("BEGIN CORRUPTED KEY"));
    }

    #[test]
    fn deterministic_pem_arm1_bad_footer() {
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let variant = find_pem_variant(1);
        let out = corrupt_pem_deterministic(pem, &variant);
        assert!(out.contains("END CORRUPTED KEY"));
    }

    #[test]
    fn deterministic_pem_arm2_bad_base64() {
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let variant = find_pem_variant(2);
        let out = corrupt_pem_deterministic(pem, &variant);
        assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
    }

    #[test]
    fn deterministic_pem_arm3_blank_line() {
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let variant = find_pem_variant(3);
        let out = corrupt_pem_deterministic(pem, &variant);
        assert!(out.contains("BEGIN TEST-----\n\n"));
    }

    #[test]
    fn deterministic_pem_arm4_truncate() {
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let variant = find_pem_variant(4);
        let out = corrupt_pem_deterministic(pem, &variant);
        assert!(out.len() < pem.len());
    }

    // ---- corrupt_der_deterministic arm-specific ----

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
}
