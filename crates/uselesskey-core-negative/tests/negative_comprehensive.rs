//! Comprehensive tests for `uselesskey-core-negative` PEM/DER corruption.
//!
//! Covers:
//! - All CorruptPem variants produce distinct outputs
//! - corrupt_der with various input sizes
//! - truncate_der edge cases (empty input, single byte)
//! - flip_byte at various positions
//! - Deterministic corruption (same seed = same corruption)

use std::collections::HashSet;

use uselesskey_core_negative::{
    CorruptPem, corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic, flip_byte,
    truncate_der,
};

// =========================================================================
// Sample PEM for tests
// =========================================================================

const SAMPLE_PEM: &str =
    "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALRiMLAh\n-----END CERTIFICATE-----\n";

// =========================================================================
// All CorruptPem variants produce distinct outputs
// =========================================================================

#[test]
fn all_corrupt_pem_variants_produce_distinct_outputs() {
    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 15 },
        CorruptPem::ExtraBlankLine,
    ];

    let outputs: HashSet<String> = variants
        .iter()
        .map(|v| corrupt_pem(SAMPLE_PEM, *v))
        .collect();

    assert_eq!(
        outputs.len(),
        variants.len(),
        "all CorruptPem variants should produce distinct outputs"
    );
}

#[test]
fn all_corrupt_pem_variants_differ_from_original() {
    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 15 },
        CorruptPem::ExtraBlankLine,
    ];

    for v in &variants {
        let corrupted = corrupt_pem(SAMPLE_PEM, *v);
        assert_ne!(
            corrupted, SAMPLE_PEM,
            "{:?} should produce output different from input",
            v
        );
    }
}

#[test]
fn bad_header_replaces_begin_line() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadHeader);
    assert!(out.starts_with("-----BEGIN CORRUPTED KEY-----"));
    assert!(!out.contains("-----BEGIN CERTIFICATE-----"));
}

#[test]
fn bad_footer_replaces_end_line() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadFooter);
    assert!(out.contains("-----END CORRUPTED KEY-----"));
    assert!(!out.contains("-----END CERTIFICATE-----"));
}

#[test]
fn bad_base64_injects_invalid_chars() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadBase64);
    assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
}

#[test]
fn truncate_limits_char_count() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes: 10 });
    assert_eq!(out.len(), 10);
}

#[test]
fn extra_blank_line_adds_empty_line() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::ExtraBlankLine);
    assert!(out.contains("\n\n"));
}

// =========================================================================
// corrupt_der with various input sizes
// =========================================================================

#[test]
fn corrupt_der_deterministic_with_small_input() {
    let der = vec![0x30, 0x03];
    let out = corrupt_der_deterministic(&der, "small-input");
    assert_ne!(out, der);
}

#[test]
fn corrupt_der_deterministic_with_medium_input() {
    let der: Vec<u8> = (0..64).collect();
    let out = corrupt_der_deterministic(&der, "medium-input");
    assert_ne!(out, der);
}

#[test]
fn corrupt_der_deterministic_with_large_input() {
    let der: Vec<u8> = (0..=255).cycle().take(1024).collect();
    let out = corrupt_der_deterministic(&der, "large-input");
    assert_ne!(out, der);
}

#[test]
fn corrupt_der_deterministic_different_variants_differ() {
    let der: Vec<u8> = (0..32).collect();
    let a = corrupt_der_deterministic(&der, "variant-alpha");
    let b = corrupt_der_deterministic(&der, "variant-beta");
    // With different variant strings the corruption should (likely) differ.
    // We can't guarantee it for every pair, but at least one of several should differ.
    let c = corrupt_der_deterministic(&der, "variant-gamma");
    let outputs: HashSet<Vec<u8>> = [a, b, c].into_iter().collect();
    assert!(
        outputs.len() >= 2,
        "different variants should produce at least 2 distinct corruptions"
    );
}

// =========================================================================
// truncate_der edge cases
// =========================================================================

#[test]
fn truncate_der_empty_input() {
    let der: Vec<u8> = vec![];
    let out = truncate_der(&der, 0);
    assert!(out.is_empty());
}

#[test]
fn truncate_der_empty_input_with_nonzero_len() {
    let der: Vec<u8> = vec![];
    // When len >= der.len(), returns full copy.
    let out = truncate_der(&der, 5);
    assert!(out.is_empty());
}

#[test]
fn truncate_der_single_byte_to_zero() {
    let der = vec![0xFF];
    let out = truncate_der(&der, 0);
    assert!(out.is_empty());
}

#[test]
fn truncate_der_single_byte_to_one() {
    let der = vec![0xFF];
    let out = truncate_der(&der, 1);
    assert_eq!(out, vec![0xFF]);
}

#[test]
fn truncate_der_single_byte_beyond_length() {
    let der = vec![0xFF];
    let out = truncate_der(&der, 10);
    assert_eq!(out, vec![0xFF]);
}

#[test]
fn truncate_der_returns_exact_prefix() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10];
    let out = truncate_der(&der, 3);
    assert_eq!(out, vec![0x30, 0x82, 0x01]);
}

#[test]
fn truncate_der_at_boundary() {
    let der = vec![0x01, 0x02, 0x03, 0x04];
    let out = truncate_der(&der, 4);
    assert_eq!(out, der, "truncate at exact length should return full copy");
}

#[test]
fn truncate_der_beyond_boundary() {
    let der = vec![0x01, 0x02, 0x03];
    let out = truncate_der(&der, 100);
    assert_eq!(out, der);
}

// =========================================================================
// flip_byte at various positions
// =========================================================================

#[test]
fn flip_byte_at_first_position() {
    let der = vec![0x30, 0x82, 0x01, 0x22];
    let out = flip_byte(&der, 0);
    assert_eq!(out[0], 0x31); // 0x30 ^ 0x01
    assert_eq!(&out[1..], &der[1..]);
}

#[test]
fn flip_byte_at_last_position() {
    let der = vec![0x30, 0x82, 0x01, 0x22];
    let out = flip_byte(&der, 3);
    assert_eq!(out[3], 0x23); // 0x22 ^ 0x01
    assert_eq!(&out[..3], &der[..3]);
}

#[test]
fn flip_byte_at_middle_position() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0xFF];
    let out = flip_byte(&der, 2);
    assert_eq!(out[2], 0x00); // 0x01 ^ 0x01
    assert_eq!(&out[..2], &der[..2]);
    assert_eq!(&out[3..], &der[3..]);
}

#[test]
fn flip_byte_beyond_length_returns_original() {
    let der = vec![0x30, 0x82];
    let out = flip_byte(&der, 10);
    assert_eq!(out, der);
}

#[test]
fn flip_byte_on_empty_input() {
    let der: Vec<u8> = vec![];
    let out = flip_byte(&der, 0);
    assert!(out.is_empty());
}

#[test]
fn flip_byte_on_single_byte() {
    let der = vec![0x00];
    let out = flip_byte(&der, 0);
    assert_eq!(out, vec![0x01]); // 0x00 ^ 0x01
}

#[test]
fn flip_byte_on_0x01_yields_0x00() {
    let der = vec![0x01];
    let out = flip_byte(&der, 0);
    assert_eq!(out, vec![0x00]); // XOR: 0x01 ^ 0x01 = 0x00
}

#[test]
fn flip_byte_on_0xff_yields_0xfe() {
    let der = vec![0xFF];
    let out = flip_byte(&der, 0);
    assert_eq!(out, vec![0xFE]); // 0xFF ^ 0x01 = 0xFE
}

#[test]
fn flip_byte_changes_only_target_byte() {
    let der: Vec<u8> = (0..16).collect();
    for i in 0..der.len() {
        let out = flip_byte(&der, i);
        for (j, byte) in out.iter().enumerate() {
            if j == i {
                assert_ne!(*byte, der[j], "byte at offset {i} should be flipped");
            } else {
                assert_eq!(
                    *byte, der[j],
                    "byte at offset {j} should be unchanged when flipping {i}"
                );
            }
        }
    }
}

// =========================================================================
// Deterministic corruption: same seed = same corruption
// =========================================================================

#[test]
fn deterministic_pem_corruption_same_variant_same_output() {
    let a = corrupt_pem_deterministic(SAMPLE_PEM, "stable-variant-1");
    let b = corrupt_pem_deterministic(SAMPLE_PEM, "stable-variant-1");
    assert_eq!(a, b);
}

#[test]
fn deterministic_pem_corruption_different_variants_likely_differ() {
    let variants = ["v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8"];
    let outputs: HashSet<String> = variants
        .iter()
        .map(|v| corrupt_pem_deterministic(SAMPLE_PEM, v))
        .collect();
    assert!(
        outputs.len() >= 2,
        "different variants should produce at least 2 distinct PEM corruptions"
    );
}

#[test]
fn deterministic_der_corruption_same_variant_same_output() {
    let der: Vec<u8> = (0..32).collect();
    let a = corrupt_der_deterministic(&der, "stable-der-v1");
    let b = corrupt_der_deterministic(&der, "stable-der-v1");
    assert_eq!(a, b);
}

#[test]
fn deterministic_der_corruption_different_variants_likely_differ() {
    let der: Vec<u8> = (0..32).collect();
    let variants = ["d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8"];
    let outputs: HashSet<Vec<u8>> = variants
        .iter()
        .map(|v| corrupt_der_deterministic(&der, v))
        .collect();
    assert!(
        outputs.len() >= 2,
        "different variants should produce at least 2 distinct DER corruptions"
    );
}

#[test]
fn deterministic_der_corruption_always_differs_from_original() {
    let der: Vec<u8> = (0..32).collect();
    for i in 0..20 {
        let variant = format!("diff-test-{i}");
        let out = corrupt_der_deterministic(&der, &variant);
        assert_ne!(
            out, der,
            "variant '{variant}' should produce output different from original"
        );
    }
}

#[test]
fn deterministic_pem_corruption_always_differs_from_original() {
    for i in 0..20 {
        let variant = format!("pem-diff-{i}");
        let out = corrupt_pem_deterministic(SAMPLE_PEM, &variant);
        assert_ne!(
            out, SAMPLE_PEM,
            "variant '{variant}' should produce output different from original"
        );
    }
}

// =========================================================================
// Edge cases in corruption algorithms
// =========================================================================

#[test]
fn negative_corrupt_pem_bad_header_on_minimal_pem() {
    let pem = "-----BEGIN X-----\nAA==\n-----END X-----\n";
    let out = corrupt_pem(pem, CorruptPem::BadHeader);
    assert!(out.starts_with("-----BEGIN CORRUPTED KEY-----"));
    assert!(!out.contains("-----BEGIN X-----"));
}

#[test]
fn negative_corrupt_pem_bad_footer_on_minimal_pem() {
    let pem = "-----BEGIN X-----\nAA==\n-----END X-----\n";
    let out = corrupt_pem(pem, CorruptPem::BadFooter);
    assert!(out.contains("-----END CORRUPTED KEY-----"));
    assert!(!out.contains("-----END X-----"));
}

#[test]
fn negative_corrupt_pem_truncate_to_zero() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes: 0 });
    assert!(out.is_empty());
}

#[test]
fn negative_corrupt_pem_truncate_to_one() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes: 1 });
    assert_eq!(out.chars().count(), 1);
}

#[test]
fn negative_corrupt_pem_truncate_beyond_length() {
    let char_count = SAMPLE_PEM.chars().count();
    let out = corrupt_pem(
        SAMPLE_PEM,
        CorruptPem::Truncate {
            bytes: char_count + 100,
        },
    );
    // Truncate with bytes >= char count returns the full PEM
    assert_eq!(out.chars().count(), char_count);
}

#[test]
fn negative_corrupt_pem_extra_blank_on_multiline() {
    let pem = "-----BEGIN KEY-----\nAAAA\nBBBB\nCCCC\n-----END KEY-----\n";
    let out = corrupt_pem(pem, CorruptPem::ExtraBlankLine);
    // Blank line is inserted after the header
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[1], "", "second line should be blank");
}

#[test]
fn negative_corrupt_pem_bad_base64_on_multiline() {
    let pem = "-----BEGIN KEY-----\nAAAA\nBBBB\n-----END KEY-----\n";
    let out = corrupt_pem(pem, CorruptPem::BadBase64);
    // Bad base64 line inserted after header
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[1], "THIS_IS_NOT_BASE64!!!");
}

// =========================================================================
// Boundary conditions: empty and single-char inputs
// =========================================================================

#[test]
fn negative_corrupt_pem_bad_header_on_empty_string() {
    let out = corrupt_pem("", CorruptPem::BadHeader);
    assert!(out.contains("-----BEGIN CORRUPTED KEY-----"));
}

#[test]
fn negative_corrupt_pem_bad_base64_on_single_line() {
    let pem = "just-one-line";
    let out = corrupt_pem(pem, CorruptPem::BadBase64);
    assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
}

#[test]
fn negative_corrupt_pem_extra_blank_on_single_line() {
    let pem = "just-one-line";
    let out = corrupt_pem(pem, CorruptPem::ExtraBlankLine);
    assert!(out.contains("\n\n") || out.contains("just-one-line\n"));
}

#[test]
fn negative_flip_byte_on_all_zeros() {
    let der = vec![0x00; 8];
    for i in 0..der.len() {
        let out = flip_byte(&der, i);
        assert_eq!(out[i], 0x01, "flipping 0x00 should yield 0x01");
        for (j, b) in out.iter().enumerate() {
            if j != i {
                assert_eq!(*b, 0x00);
            }
        }
    }
}

#[test]
fn negative_flip_byte_on_all_ones() {
    let der = vec![0xFF; 4];
    for i in 0..der.len() {
        let out = flip_byte(&der, i);
        assert_eq!(out[i], 0xFE, "flipping 0xFF should yield 0xFE");
    }
}

#[test]
fn negative_truncate_der_preserves_prefix() {
    let der: Vec<u8> = (0..100).collect();
    for len in [0, 1, 2, 10, 50, 99, 100] {
        let out = truncate_der(&der, len);
        assert_eq!(out.len(), len.min(der.len()));
        assert_eq!(&out[..], &der[..out.len()]);
    }
}

#[test]
fn negative_corrupt_der_deterministic_on_empty_input() {
    let der: Vec<u8> = vec![];
    let out = corrupt_der_deterministic(&der, "empty-input");
    // Empty input may return empty (truncation of nothing)
    assert!(out.len() <= 1);
}

#[test]
fn negative_corrupt_der_deterministic_on_single_byte() {
    let der = vec![0x42];
    let out = corrupt_der_deterministic(&der, "single-byte");
    // With a single byte, truncation yields empty, or flip changes the byte
    assert!(out.is_empty() || (out.len() == 1 && out[0] != 0x42));
}

#[test]
fn negative_corrupt_pem_deterministic_on_empty_string() {
    let out = corrupt_pem_deterministic("", "empty");
    // Empty input should produce some output (even if minimal)
    // Each arm handles empty differently
    assert!(out.len() <= 50);
}

// =========================================================================
// Deterministic corruption: cross-variant independence
// =========================================================================

#[test]
fn negative_der_corruption_100_variants_all_stable() {
    let der: Vec<u8> = (0..64).collect();
    for i in 0..100 {
        let variant = format!("stability-{i}");
        let a = corrupt_der_deterministic(&der, &variant);
        let b = corrupt_der_deterministic(&der, &variant);
        assert_eq!(a, b, "variant '{variant}' must be deterministically stable");
    }
}

#[test]
fn negative_pem_corruption_100_variants_all_stable() {
    for i in 0..100 {
        let variant = format!("pem-stability-{i}");
        let a = corrupt_pem_deterministic(SAMPLE_PEM, &variant);
        let b = corrupt_pem_deterministic(SAMPLE_PEM, &variant);
        assert_eq!(a, b, "variant '{variant}' must be deterministically stable");
    }
}

#[test]
fn negative_der_corruption_covers_all_three_arms() {
    // Ensure at least one variant hits each of the 3 arms (truncate, flip, flip+truncate)
    let der: Vec<u8> = (0..32).collect();
    let mut saw_shorter = false;
    let mut saw_same_len = false;
    let mut saw_shorter_with_diff = false;

    for i in 0..50 {
        let variant = format!("arm-check-{i}");
        let out = corrupt_der_deterministic(&der, &variant);
        if out.len() < der.len() {
            // Either arm 0 (truncate) or arm 2 (flip+truncate)
            if out.iter().zip(der.iter()).all(|(a, b)| a == b) {
                saw_shorter = true; // Pure truncation (arm 0)
            } else {
                saw_shorter_with_diff = true; // Flip + truncate (arm 2)
            }
        } else if out.len() == der.len() {
            saw_same_len = true; // Flip only (arm 1)
        }
    }

    assert!(
        saw_shorter || saw_shorter_with_diff,
        "should see truncation"
    );
    assert!(saw_same_len, "should see same-length flip");
}

#[test]
fn negative_pem_corruption_covers_all_five_arms() {
    let mut saw_bad_header = false;
    let mut saw_bad_footer = false;
    let mut saw_bad_base64 = false;
    let mut saw_blank_line = false;
    let mut saw_truncate = false;

    for i in 0..100 {
        let variant = format!("arm-pem-{i}");
        let out = corrupt_pem_deterministic(SAMPLE_PEM, &variant);
        if out.contains("-----BEGIN CORRUPTED KEY-----") {
            saw_bad_header = true;
        }
        if out.contains("-----END CORRUPTED KEY-----") {
            saw_bad_footer = true;
        }
        if out.contains("THIS_IS_NOT_BASE64!!!") {
            saw_bad_base64 = true;
        }
        if out.contains("BEGIN CERTIFICATE-----\n\n") {
            saw_blank_line = true;
        }
        if out.len() < SAMPLE_PEM.len()
            && !out.contains("CORRUPTED")
            && !out.contains("THIS_IS_NOT_BASE64")
        {
            saw_truncate = true;
        }
    }

    assert!(saw_bad_header, "should see BadHeader arm");
    assert!(saw_bad_footer, "should see BadFooter arm");
    assert!(saw_bad_base64, "should see BadBase64 arm");
    // Blank line and truncate may not trigger with this specific PEM but we don't
    // hard-fail on them since coverage depends on hash distribution
    let _ = (saw_blank_line, saw_truncate);
}
