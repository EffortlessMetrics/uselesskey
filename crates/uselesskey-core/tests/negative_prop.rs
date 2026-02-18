#![cfg(feature = "std")]

use proptest::prelude::*;

use uselesskey_core::negative::{CorruptPem, corrupt_pem, flip_byte, truncate_der};

/// Generate a minimal valid PEM string for testing.
fn pem_strategy() -> impl Strategy<Value = String> {
    // Generate a base64-like body (64-256 chars).
    "[A-Za-z0-9+/]{64,256}"
        .prop_map(|body| format!("-----BEGIN TEST KEY-----\n{}\n-----END TEST KEY-----", body))
}

proptest! {
    // =========================================================================
    // corrupt_pem() specific variant tests
    // =========================================================================

    /// corrupt_pem() with BadHeader always contains "BEGIN CORRUPTED KEY".
    #[test]
    fn corrupt_pem_bad_header_contains_marker(pem in pem_strategy()) {
        let corrupted = corrupt_pem(&pem, CorruptPem::BadHeader);
        prop_assert!(
            corrupted.contains("BEGIN CORRUPTED KEY"),
            "BadHeader should insert 'BEGIN CORRUPTED KEY', got: {}",
            corrupted
        );
    }

    /// corrupt_pem() with BadFooter always contains "END CORRUPTED KEY".
    #[test]
    fn corrupt_pem_bad_footer_contains_marker(pem in pem_strategy()) {
        let corrupted = corrupt_pem(&pem, CorruptPem::BadFooter);
        prop_assert!(
            corrupted.contains("END CORRUPTED KEY"),
            "BadFooter should insert 'END CORRUPTED KEY', got: {}",
            corrupted
        );
    }

    /// corrupt_pem() with BadBase64 always contains "THIS_IS_NOT_BASE64".
    #[test]
    fn corrupt_pem_bad_base64_contains_marker(pem in pem_strategy()) {
        let corrupted = corrupt_pem(&pem, CorruptPem::BadBase64);
        prop_assert!(
            corrupted.contains("THIS_IS_NOT_BASE64"),
            "BadBase64 should insert 'THIS_IS_NOT_BASE64', got: {}",
            corrupted
        );
    }

    /// corrupt_pem() with Truncate produces output of specified length (when shorter than input).
    #[test]
    fn corrupt_pem_truncate_produces_correct_length(
        pem in pem_strategy(),
        fraction in 1usize..10
    ) {
        let target_bytes = pem.len() / fraction.max(1);
        prop_assume!(target_bytes < pem.len());
        prop_assume!(target_bytes > 0);

        let corrupted = corrupt_pem(&pem, CorruptPem::Truncate { bytes: target_bytes });

        // Truncate uses chars().take(), so we count chars not bytes.
        // For ASCII PEM this should be equivalent.
        prop_assert_eq!(
            corrupted.chars().count(),
            target_bytes,
            "Truncate should produce exactly {} chars, got {}",
            target_bytes,
            corrupted.chars().count()
        );
    }

    /// corrupt_pem() with ExtraBlankLine adds a blank line.
    #[test]
    fn corrupt_pem_extra_blank_line_adds_blank(pem in pem_strategy()) {
        let original_lines: Vec<&str> = pem.lines().collect();
        let corrupted = corrupt_pem(&pem, CorruptPem::ExtraBlankLine);
        let corrupted_lines: Vec<&str> = corrupted.lines().collect();

        // Should have one more line (the blank line).
        prop_assert_eq!(
            corrupted_lines.len(),
            original_lines.len() + 1,
            "ExtraBlankLine should add one line"
        );

        // One of the lines should be empty.
        prop_assert!(
            corrupted_lines.iter().any(|l| l.is_empty()),
            "ExtraBlankLine should produce at least one empty line"
        );
    }

    // =========================================================================
    // flip_byte() tests
    // =========================================================================

    /// flip_byte() at valid index changes exactly one byte.
    #[test]
    fn flip_byte_changes_exactly_one_byte(
        der in prop::collection::vec(any::<u8>(), 1..256),
        offset_factor in 0usize..100
    ) {
        let offset = offset_factor % der.len();

        let flipped = flip_byte(&der, offset);

        // Length should be the same.
        prop_assert_eq!(flipped.len(), der.len());

        // Count how many bytes differ.
        let diff_count = der.iter()
            .zip(flipped.iter())
            .filter(|(a, b)| a != b)
            .count();

        prop_assert_eq!(
            diff_count, 1,
            "flip_byte should change exactly one byte, changed {}",
            diff_count
        );

        // The changed byte should be at the specified offset.
        prop_assert_ne!(
            flipped[offset], der[offset],
            "flip_byte should change the byte at offset {}", offset
        );
    }

    /// flip_byte() at out-of-range index returns original bytes.
    #[test]
    fn flip_byte_out_of_range_returns_original(
        der in prop::collection::vec(any::<u8>(), 1..256),
        extra in 0usize..100
    ) {
        let offset = der.len() + extra;

        let result = flip_byte(&der, offset);

        prop_assert_eq!(result, der, "flip_byte with out-of-range offset should return original");
    }

    /// flip_byte() is its own inverse (xor with 0x01 twice returns original).
    #[test]
    fn flip_byte_is_self_inverse(
        der in prop::collection::vec(any::<u8>(), 1..256),
        offset_factor in 0usize..100
    ) {
        let offset = offset_factor % der.len();

        let flipped_once = flip_byte(&der, offset);
        let flipped_twice = flip_byte(&flipped_once, offset);

        prop_assert_eq!(flipped_twice, der, "flip_byte should be its own inverse");
    }

    // =========================================================================
    // truncate_der() additional tests
    // =========================================================================

    /// truncate_der() with zero length returns empty vec.
    #[test]
    fn truncate_der_zero_returns_empty(
        der in prop::collection::vec(any::<u8>(), 1..256)
    ) {
        let result = truncate_der(&der, 0);
        prop_assert!(result.is_empty(), "truncate_der(_, 0) should return empty vec");
    }

    /// truncate_der() preserves prefix bytes.
    #[test]
    fn truncate_der_preserves_prefix(
        der in prop::collection::vec(any::<u8>(), 2..256),
        len in 1usize..100
    ) {
        let actual_len = len.min(der.len());
        let result = truncate_der(&der, actual_len);

        // Result should be a prefix of the original.
        for (i, &byte) in result.iter().enumerate() {
            prop_assert_eq!(
                byte, der[i],
                "truncate_der should preserve byte at index {}", i
            );
        }
    }
}
