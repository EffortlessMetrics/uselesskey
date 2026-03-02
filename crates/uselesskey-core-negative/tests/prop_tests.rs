//! Property-based tests for `uselesskey-core-negative`.

use proptest::prelude::*;
use uselesskey_core_negative::{
    CorruptPem, corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic, flip_byte,
    truncate_der,
};

const SAMPLE_PEM: &str =
    "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAH\n-----END RSA PRIVATE KEY-----\n";

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    // ── truncate_der ─────────────────────────────────────────────────

    #[test]
    fn truncate_der_length_bounded(
        data in proptest::collection::vec(any::<u8>(), 0..256),
        len in 0usize..512,
    ) {
        let result = truncate_der(&data, len);
        prop_assert!(result.len() <= data.len());
        prop_assert!(result.len() <= len);
        // Result is always a prefix of the original
        prop_assert_eq!(&result[..], &data[..result.len()]);
    }

    #[test]
    fn truncate_der_idempotent_at_full_length(
        data in proptest::collection::vec(any::<u8>(), 1..128),
    ) {
        let result = truncate_der(&data, data.len());
        prop_assert_eq!(result, data);
    }

    // ── flip_byte ────────────────────────────────────────────────────

    #[test]
    fn flip_byte_changes_exactly_one(
        data in proptest::collection::vec(any::<u8>(), 1..128),
        offset in 0usize..128,
    ) {
        let result = flip_byte(&data, offset);
        if offset < data.len() {
            // Exactly one byte should differ
            let diffs = result.iter().zip(data.iter())
                .filter(|(a, b)| a != b)
                .count();
            prop_assert_eq!(diffs, 1);
            prop_assert_ne!(result[offset], data[offset]);
        } else {
            // Out of bounds: unchanged
            prop_assert_eq!(result, data);
        }
    }

    #[test]
    fn flip_byte_preserves_length(
        data in proptest::collection::vec(any::<u8>(), 0..128),
        offset in 0usize..256,
    ) {
        let result = flip_byte(&data, offset);
        prop_assert_eq!(result.len(), data.len());
    }

    // ── corrupt_der_deterministic ────────────────────────────────────

    #[test]
    fn corrupt_der_deterministic_is_stable(
        data in proptest::collection::vec(any::<u8>(), 2..128),
        variant in "[a-z0-9:_-]{1,32}",
    ) {
        let a = corrupt_der_deterministic(&data, &variant);
        let b = corrupt_der_deterministic(&data, &variant);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn corrupt_der_deterministic_differs_from_input(
        data in proptest::collection::vec(any::<u8>(), 2..128),
        variant in "[a-z0-9:_-]{1,32}",
    ) {
        let result = corrupt_der_deterministic(&data, &variant);
        prop_assert_ne!(result, data);
    }

    // ── corrupt_pem ──────────────────────────────────────────────────

    #[test]
    fn corrupt_pem_bad_header_always_replaces(
        label in "[A-Z ]{3,20}",
    ) {
        let pem = format!("-----BEGIN {label}-----\nDATA=\n-----END {label}-----\n");
        let out = corrupt_pem(&pem, CorruptPem::BadHeader);
        prop_assert!(out.starts_with("-----BEGIN CORRUPTED KEY-----"));
    }

    #[test]
    fn corrupt_pem_bad_footer_always_replaces(
        label in "[A-Z ]{3,20}",
    ) {
        let pem = format!("-----BEGIN {label}-----\nDATA=\n-----END {label}-----\n");
        let out = corrupt_pem(&pem, CorruptPem::BadFooter);
        prop_assert!(out.contains("-----END CORRUPTED KEY-----"));
    }

    #[test]
    fn corrupt_pem_bad_base64_injects_marker(
        label in "[A-Z ]{3,20}",
    ) {
        let pem = format!("-----BEGIN {label}-----\nDATA=\n-----END {label}-----\n");
        let out = corrupt_pem(&pem, CorruptPem::BadBase64);
        prop_assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
    }

    #[test]
    fn corrupt_pem_truncate_respects_length(bytes in 0usize..100) {
        let out = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes });
        let expected = bytes.min(SAMPLE_PEM.chars().count());
        prop_assert_eq!(out.chars().count(), expected);
    }

    // ── corrupt_pem_deterministic ────────────────────────────────────

    #[test]
    fn corrupt_pem_deterministic_is_stable(
        variant in "[a-z0-9:_-]{1,32}",
    ) {
        let a = corrupt_pem_deterministic(SAMPLE_PEM, &variant);
        let b = corrupt_pem_deterministic(SAMPLE_PEM, &variant);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn corrupt_pem_deterministic_differs_from_original(
        variant in "[a-z0-9:_-]{1,32}",
    ) {
        let out = corrupt_pem_deterministic(SAMPLE_PEM, &variant);
        prop_assert_ne!(out, SAMPLE_PEM);
    }
}
