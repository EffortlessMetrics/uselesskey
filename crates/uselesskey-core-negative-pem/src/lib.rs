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
///
/// # Examples
///
/// ```
/// use uselesskey_core_negative_pem::{CorruptPem, corrupt_pem};
///
/// let pem = "-----BEGIN RSA PRIVATE KEY-----\nAAA=\n-----END RSA PRIVATE KEY-----\n";
/// let bad = corrupt_pem(pem, CorruptPem::BadHeader);
/// assert!(bad.starts_with("-----BEGIN CORRUPTED KEY-----"));
/// ```
#[derive(Clone, Copy, Debug)]
pub enum CorruptPem {
    BadHeader,
    BadFooter,
    BadBase64,
    Truncate { bytes: usize },
    ExtraBlankLine,
}

/// Apply a specific corruption strategy to a PEM string.
///
/// # Examples
///
/// ```
/// use uselesskey_core_negative_pem::{CorruptPem, corrupt_pem};
///
/// let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
///
/// let truncated = corrupt_pem(pem, CorruptPem::Truncate { bytes: 10 });
/// assert_eq!(truncated.len(), 10);
///
/// let bad_footer = corrupt_pem(pem, CorruptPem::BadFooter);
/// assert!(bad_footer.contains("END CORRUPTED KEY"));
/// ```
pub fn corrupt_pem(pem: &str, how: CorruptPem) -> String {
    match how {
        CorruptPem::BadHeader => replace_first_line(pem, "-----BEGIN CORRUPTED KEY-----"),
        CorruptPem::BadFooter => replace_last_line(pem, "-----END CORRUPTED KEY-----"),
        CorruptPem::BadBase64 => inject_bad_base64_line(pem),
        CorruptPem::Truncate { bytes } => pem.chars().take(bytes).collect(),
        CorruptPem::ExtraBlankLine => inject_blank_line(pem),
    }
}

/// Apply a deterministic corruption derived from a variant string.
///
/// The same `variant` always produces the same corruption shape, making
/// negative-fixture tests reproducible.
///
/// # Examples
///
/// ```
/// use uselesskey_core_negative_pem::corrupt_pem_deterministic;
///
/// let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
/// let a = corrupt_pem_deterministic(pem, "corrupt:v1");
/// let b = corrupt_pem_deterministic(pem, "corrupt:v1");
/// assert_eq!(a, b); // deterministic
/// ```
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

    // --- Mutation-killing tests for derived_truncate_len ---

    #[test]
    fn derived_truncate_len_single_char_returns_zero() {
        // Kills mutant: replace derived_truncate_len -> usize with 1
        let pem = "X";
        let digest = [0u8; 32];
        let result = derived_truncate_len(pem, &digest);
        assert_eq!(result, 0, "single-char PEM must truncate to 0");
    }

    #[test]
    fn derived_truncate_len_empty_returns_zero() {
        let pem = "";
        let digest = [0u8; 32];
        let result = derived_truncate_len(pem, &digest);
        assert_eq!(result, 0, "empty PEM must truncate to 0");
    }

    #[test]
    fn derived_truncate_len_two_chars_returns_one() {
        // With chars=2, span=1, so result = 1 + (x % 1) = 1
        // Kills mutants: <= vs >, - vs +, - vs /, + vs *
        let pem = "XY";
        let digest = [0u8; 32];
        let result = derived_truncate_len(pem, &digest);
        assert_eq!(result, 1, "two-char PEM must truncate to exactly 1");
    }

    #[test]
    fn derived_truncate_len_range_is_1_to_chars_minus_1() {
        // For a longer PEM, the result must be in [1, chars)
        // This kills mutants that swap arithmetic operators
        let pem = "ABCDEFGHIJ"; // 10 chars
        for byte1 in 0..=255u8 {
            let mut digest = [0u8; 32];
            digest[1] = byte1;
            let result = derived_truncate_len(pem, &digest);
            assert!(result >= 1, "truncate len must be >= 1, got {result}");
            assert!(
                result < 10,
                "truncate len must be < char count (10), got {result}"
            );
        }
    }

    #[test]
    fn derived_truncate_len_varies_with_digest() {
        // Different digests should produce different truncation lengths (for sufficiently long PEM)
        let pem = "A".repeat(1000);
        let mut results = HashSet::new();
        for i in 0u8..=255 {
            let mut digest = [0u8; 32];
            digest[1] = i;
            results.insert(derived_truncate_len(&pem, &digest));
        }
        assert!(
            results.len() > 1,
            "different digests should produce different truncate lengths"
        );
    }

    // --- Mutation-killing tests for inject_bad_base64_line ---

    #[test]
    fn inject_bad_base64_line_with_exactly_3_lines() {
        // Kills mutant: < vs <= in lines.len() < 3
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let out = inject_bad_base64_line(pem);
        // Should insert after header, so line[1] should be the injected line
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[1], "THIS_IS_NOT_BASE64!!!",
            "bad base64 should be inserted after header"
        );
    }

    #[test]
    fn inject_bad_base64_line_with_2_lines_uses_fallback() {
        let pem = "header\nbody\n";
        let out = inject_bad_base64_line(pem);
        assert!(
            out.contains("THIS_IS_NOT_BASE64!!!"),
            "fallback should still contain bad base64"
        );
    }

    // --- Mutation-killing tests for inject_blank_line ---

    #[test]
    fn inject_blank_line_with_exactly_3_lines() {
        // Kills mutant: < vs > in lines.len() < 3
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let out = inject_blank_line(pem);
        let lines: Vec<&str> = out.lines().collect();
        // After header, there should be an empty line
        assert_eq!(
            lines[1], "",
            "blank line should be inserted after header"
        );
        assert_eq!(lines.len(), 4, "should have 4 lines after insertion");
    }

    #[test]
    fn inject_blank_line_with_2_lines_uses_fallback() {
        let pem = "header\nbody\n";
        let out = inject_blank_line(pem);
        // Fallback appends two newlines
        assert!(
            out.ends_with("\n\n"),
            "fallback should append double newline"
        );
    }
}
