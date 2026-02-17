use alloc::vec::Vec;

use crate::derive::hash32;

/// Truncate DER bytes to `len` bytes.
///
/// If `len >= der.len()`, returns the original bytes unchanged.
///
/// # Examples
///
/// ```
/// use uselesskey_core::negative::truncate_der;
///
/// let der = vec![0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09];
///
/// // Truncate to 4 bytes
/// let truncated = truncate_der(&der, 4);
/// assert_eq!(truncated, vec![0x30, 0x82, 0x01, 0x22]);
///
/// // Truncate beyond length returns original
/// let same = truncate_der(&der, 100);
/// assert_eq!(same, der);
/// ```
pub fn truncate_der(der: &[u8], len: usize) -> Vec<u8> {
    if len >= der.len() {
        return der.to_vec();
    }
    der[..len].to_vec()
}

/// Flip one byte at `offset` (XOR with `0x01`).
///
/// If `offset` is out of range, returns the original bytes unchanged.
///
/// This is useful for creating DER that is structurally invalid,
/// such as corrupting ASN.1 tags or length bytes.
///
/// # Examples
///
/// ```
/// use uselesskey_core::negative::flip_byte;
///
/// let der = vec![0x30, 0x82, 0x01, 0x22]; // SEQUENCE tag at byte 0
///
/// // Flip the tag byte: 0x30 XOR 0x01 = 0x31
/// let flipped = flip_byte(&der, 0);
/// assert_eq!(flipped[0], 0x31);
/// assert_eq!(flipped[1..], der[1..]); // Rest unchanged
///
/// // Flip at invalid offset returns original
/// let same = flip_byte(&der, 100);
/// assert_eq!(same, der);
/// ```
pub fn flip_byte(der: &[u8], offset: usize) -> Vec<u8> {
    if offset >= der.len() {
        return der.to_vec();
    }

    let mut out = der.to_vec();
    out[offset] ^= 0x01;
    out
}

/// Apply a deterministic DER corruption derived from a variant string.
///
/// This is useful for stable "corrupt:*" fixtures where the corruption pattern
/// should be tied to identity rather than test execution order.
///
/// The mapping is deterministic:
/// same `der` + same `variant` => same corrupted output.
pub fn corrupt_der_deterministic(der: &[u8], variant: &str) -> Vec<u8> {
    let digest = hash32(variant.as_bytes());
    let bytes = digest.as_bytes();

    match bytes[0] % 3 {
        0 => {
            let len = derived_truncate_len(der.len(), bytes);
            truncate_der(der, len)
        }
        1 => {
            let offset = derived_offset(der.len(), bytes[1]);
            flip_byte(der, offset)
        }
        _ => {
            let offset = derived_offset(der.len(), bytes[1]);
            let flipped = flip_byte(der, offset);
            let len = derived_truncate_len(flipped.len(), bytes);
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

fn derived_truncate_len(len: usize, digest: &[u8; 32]) -> usize {
    if len <= 1 {
        return 0;
    }
    // Always truncate by at least one byte.
    let span = len - 1;
    digest[2] as usize % span
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn flip_byte_changes_only_target_offset() {
        let der = vec![0x30, 0x82, 0x01, 0x22];
        let flipped = flip_byte(&der, 0);

        assert_eq!(flipped[0], 0x31);
        assert_eq!(&flipped[1..], &der[1..]);
    }

    #[test]
    fn flip_byte_out_of_range_is_noop() {
        let der = vec![0x30, 0x82, 0x01, 0x22];
        let flipped = flip_byte(&der, 100);
        assert_eq!(flipped, der);
    }

    #[test]
    fn truncate_der_shortens_when_len_smaller() {
        let der = vec![0x30, 0x82, 0x01, 0x22];
        let truncated = truncate_der(&der, 2);
        assert_eq!(truncated, vec![0x30, 0x82]);
    }

    #[test]
    fn truncate_der_len_ge_returns_original() {
        let der = vec![0x30, 0x82, 0x01, 0x22];
        assert_eq!(truncate_der(&der, der.len()), der);
        assert_eq!(truncate_der(&der, der.len() + 10), der);
    }

    #[test]
    fn deterministic_der_corruption_is_stable() {
        let der = vec![0x30, 0x82, 0x01, 0x22, 0x30, 0x0D];
        let first = corrupt_der_deterministic(&der, "corrupt:der:v1");
        let second = corrupt_der_deterministic(&der, "corrupt:der:v1");
        assert_eq!(first, second);
    }

    #[test]
    fn deterministic_der_corruption_varies_across_variants() {
        let der = vec![0x30, 0x82, 0x01, 0x22, 0x30, 0x0D];
        let variants = ["a", "b", "c", "d", "e", "f", "g"];
        let mut outputs = HashSet::new();
        for v in variants {
            outputs.insert(corrupt_der_deterministic(&der, v));
        }
        assert!(outputs.len() >= 2);
    }

    #[test]
    fn deterministic_der_corruption_handles_empty_input() {
        let out = corrupt_der_deterministic(&[], "empty");
        assert!(out.is_empty());
    }
}
