#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

//! PEM-focused negative-fixture corruption helpers.
//!
//! Provides [`CorruptPem`] strategies (bad header, bad footer, bad base64,
//! truncation, extra blank lines) and the [`corrupt_pem`] /
//! [`corrupt_pem_deterministic`] functions. Deterministic corruption derives
//! the strategy from a variant string so the same variant always produces the
//! same corruption shape.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use uselesskey_core_hash::hash32;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

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

    fn find_variant(target: u8) -> String {
        for i in 0u64.. {
            let v = format!("v{i}");
            if hash32(v.as_bytes()).as_bytes()[0] % 5 == target {
                return v;
            }
        }
        unreachable!()
    }

    #[test]
    fn deterministic_pem_arm0_bad_header() {
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let out = corrupt_pem_deterministic(pem, &find_variant(0));
        assert!(out.contains("BEGIN CORRUPTED KEY"));
    }

    #[test]
    fn deterministic_pem_arm1_bad_footer() {
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let out = corrupt_pem_deterministic(pem, &find_variant(1));
        assert!(out.contains("END CORRUPTED KEY"));
    }

    #[test]
    fn deterministic_pem_arm2_bad_base64() {
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let out = corrupt_pem_deterministic(pem, &find_variant(2));
        assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
    }

    #[test]
    fn deterministic_pem_arm3_blank_line() {
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let out = corrupt_pem_deterministic(pem, &find_variant(3));
        assert!(out.contains("BEGIN TEST-----\n\n"));
    }

    #[test]
    fn deterministic_pem_arm4_truncate() {
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let out = corrupt_pem_deterministic(pem, &find_variant(4));
        assert!(out.len() < pem.len());
    }
}
