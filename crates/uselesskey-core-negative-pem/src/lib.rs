#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

//! PEM-focused negative fixture corruption helpers for test fixtures.
//!
//! Use [`corrupt_pem`] to apply a specific corruption strategy, or
//! [`corrupt_pem_deterministic`] to let the variant string choose the
//! strategy deterministically.
//!
//! # Examples
//!
//! ```
//! use uselesskey_core_negative_pem::{corrupt_pem, CorruptPem};
//!
//! let pem = "-----BEGIN RSA PRIVATE KEY-----\nABC=\n-----END RSA PRIVATE KEY-----\n";
//!
//! // Replace the header with an invalid one
//! let bad = corrupt_pem(pem, CorruptPem::BadHeader);
//! assert!(bad.starts_with("-----BEGIN CORRUPTED KEY-----"));
//!
//! // Inject invalid base64 so decoders reject it
//! let bad = corrupt_pem(pem, CorruptPem::BadBase64);
//! assert!(bad.contains("THIS_IS_NOT_BASE64!!!"));
//! ```
//!
//! Deterministic corruption picks a strategy from the variant string,
//! producing the same output every time:
//!
//! ```
//! use uselesskey_core_negative_pem::corrupt_pem_deterministic;
//!
//! let pem = "-----BEGIN PUBLIC KEY-----\nABC=\n-----END PUBLIC KEY-----\n";
//! let a = corrupt_pem_deterministic(pem, "corrupt:test-v1");
//! let b = corrupt_pem_deterministic(pem, "corrupt:test-v1");
//! assert_eq!(a, b); // same variant ⇒ same corruption
//! ```

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use uselesskey_core_hash::hash32;

/// Strategies for corrupting PEM-encoded data.
#[derive(Clone, Copy, Debug)]
pub enum CorruptPem {
    /// Replace the `-----BEGIN …-----` line with an invalid header.
    BadHeader,
    /// Replace the `-----END …-----` line with an invalid footer.
    BadFooter,
    /// Inject a non-base64 line into the body so decoders reject the payload.
    BadBase64,
    /// Keep only the first `bytes` characters of the PEM string.
    Truncate {
        /// Maximum number of characters to keep.
        bytes: usize,
    },
    /// Insert a blank line after the header, breaking strict PEM parsers.
    ExtraBlankLine,
}

/// Apply a specific [`CorruptPem`] corruption strategy to the given PEM string.
pub fn corrupt_pem(pem: &str, how: CorruptPem) -> String {
    match how {
        CorruptPem::BadHeader => replace_first_line(pem, "-----BEGIN CORRUPTED KEY-----"),
        CorruptPem::BadFooter => replace_last_line(pem, "-----END CORRUPTED KEY-----"),
        CorruptPem::BadBase64 => inject_bad_base64_line(pem),
        CorruptPem::Truncate { bytes } => truncate_utf8_at_byte_boundary(pem, bytes),
        CorruptPem::ExtraBlankLine => inject_blank_line(pem),
    }
}

/// Choose a corruption strategy deterministically from `variant` and apply it to `pem`.
///
/// The same `(pem, variant)` pair always produces the same corrupted output.
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
    let total_bytes = pem.len();
    if total_bytes <= 1 {
        return 0;
    }

    let span = total_bytes - 1;
    1 + (u16::from_be_bytes([digest[1], digest[2]]) as usize % span)
}

fn truncate_utf8_at_byte_boundary(input: &str, max_bytes: usize) -> String {
    if max_bytes >= input.len() {
        return input.to_string();
    }

    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    input[..end].to_string()
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
    fn truncate_variant_uses_byte_budget_without_breaking_utf8() {
        let pem = "🔐KEY";
        let out = corrupt_pem(pem, CorruptPem::Truncate { bytes: 3 });
        assert_eq!(out, "");

        let out = corrupt_pem(pem, CorruptPem::Truncate { bytes: 4 });
        assert_eq!(out, "🔐");
    }

    #[test]
    fn deterministic_truncate_never_exceeds_input_byte_length() {
        let pem = "🔐A";
        let variant = (0..256)
            .map(|i| alloc::format!("corrupt:truncate:{i}"))
            .find(|candidate| hash32(candidate.as_bytes()).as_bytes()[0] % 5 == 4)
            .expect("a truncate variant should exist");
        let out = corrupt_pem_deterministic(pem, &variant);
        assert!(out.len() <= pem.len());
        assert!(pem.starts_with(&out));
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

    #[test]
    fn bad_base64_inserts_after_header_in_normal_pem() {
        // Catches `< 3` → `== 3` and `<= 3`: those would take the early-return
        // path for a 3-line PEM, appending at end instead of inserting after line 1.
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let out = corrupt_pem(pem, CorruptPem::BadBase64);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "-----BEGIN TEST-----");
        assert_eq!(lines[1], "THIS_IS_NOT_BASE64!!!");
        assert_eq!(lines[2], "AAA=");
    }

    #[test]
    fn bad_base64_two_line_pem_appends() {
        // Catches `< 3` → `> 3`: with `> 3`, a 2-line input would insert
        // instead of taking the early-return append path.
        let pem = "line1\nline2";
        let out = corrupt_pem(pem, CorruptPem::BadBase64);
        assert_eq!(out, "line1\nline2\nTHIS_IS_NOT_BASE64!!!\n");
    }

    #[test]
    fn blank_line_inserts_after_header_in_normal_pem() {
        // Same boundary check as inject_bad_base64_line.
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let out = corrupt_pem(pem, CorruptPem::ExtraBlankLine);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "-----BEGIN TEST-----");
        assert_eq!(lines[1], "");
        assert_eq!(lines[2], "AAA=");
    }

    #[test]
    fn blank_line_two_line_pem_appends() {
        let pem = "line1\nline2";
        let out = corrupt_pem(pem, CorruptPem::ExtraBlankLine);
        assert_eq!(out, "line1\nline2\n\n");
    }

    #[test]
    fn derived_truncate_len_exact_arithmetic() {
        // Catches `return 0`, `return 1`, `+ → *`, and arithmetic mutations
        // on the span / modulo computation.
        let mut digest = [0u8; 32];
        digest[1] = 0x0A;
        digest[2] = 0x0B;
        // chars=10, span=9, u16=0x0A0B=2571, 2571%9=6, result=1+6=7
        assert_eq!(derived_truncate_len("0123456789", &digest), 7);
    }

    #[test]
    fn derived_truncate_len_empty_returns_zero() {
        let digest = [0u8; 32];
        assert_eq!(derived_truncate_len("", &digest), 0);
    }

    #[test]
    fn derived_truncate_len_single_char_returns_zero() {
        let digest = [0xFF; 32];
        assert_eq!(derived_truncate_len("x", &digest), 0);
    }
}
