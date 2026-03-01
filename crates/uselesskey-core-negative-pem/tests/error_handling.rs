//! Error handling and edge case tests for `uselesskey-core-negative-pem`.

use rstest::rstest;
use uselesskey_core_negative_pem::{CorruptPem, corrupt_pem, corrupt_pem_deterministic};

// ---------------------------------------------------------------------------
// 1. Debug impl for CorruptPem variants (no key material leakage)
// ---------------------------------------------------------------------------

#[rstest]
#[case(CorruptPem::BadHeader, "BadHeader")]
#[case(CorruptPem::BadFooter, "BadFooter")]
#[case(CorruptPem::BadBase64, "BadBase64")]
#[case(CorruptPem::Truncate { bytes: 42 }, "Truncate")]
#[case(CorruptPem::ExtraBlankLine, "ExtraBlankLine")]
fn debug_output_contains_variant_name(#[case] variant: CorruptPem, #[case] expected: &str) {
    let dbg = format!("{variant:?}");
    assert!(
        dbg.contains(expected),
        "Debug output '{dbg}' should contain '{expected}'"
    );
}

#[test]
fn debug_truncate_shows_byte_count() {
    let dbg = format!("{:?}", CorruptPem::Truncate { bytes: 123 });
    assert!(dbg.contains("123"), "Truncate debug should show byte count");
}

#[test]
fn debug_output_never_contains_key_material() {
    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 10 },
        CorruptPem::ExtraBlankLine,
    ];
    for v in variants {
        let dbg = format!("{v:?}");
        assert!(
            !dbg.contains("BEGIN"),
            "Debug should not contain PEM markers"
        );
        assert!(
            !dbg.contains("PRIVATE"),
            "Debug should not contain key type"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Clone and Copy semantics
// ---------------------------------------------------------------------------

#[test]
fn corrupt_pem_is_copy() {
    let a = CorruptPem::BadHeader;
    let b = a; // Copy
    let c = a; // Still accessible after copy
    let _ = (b, c);
}

#[test]
fn corrupt_pem_clone_produces_identical_results() {
    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 50 },
        CorruptPem::ExtraBlankLine,
    ];
    let pem = "-----BEGIN TEST-----\nDATA\n-----END TEST-----\n";
    for v in variants {
        let cloned = v;
        assert_eq!(corrupt_pem(pem, v), corrupt_pem(pem, cloned));
    }
}

// ---------------------------------------------------------------------------
// 3. Edge cases: empty and minimal input
// ---------------------------------------------------------------------------

#[rstest]
#[case(CorruptPem::BadHeader)]
#[case(CorruptPem::BadFooter)]
#[case(CorruptPem::BadBase64)]
#[case(CorruptPem::Truncate { bytes: 0 })]
#[case(CorruptPem::ExtraBlankLine)]
fn empty_input_does_not_panic(#[case] variant: CorruptPem) {
    let _ = corrupt_pem("", variant);
}

#[rstest]
#[case(CorruptPem::BadHeader)]
#[case(CorruptPem::BadFooter)]
#[case(CorruptPem::BadBase64)]
#[case(CorruptPem::Truncate { bytes: 1 })]
#[case(CorruptPem::ExtraBlankLine)]
fn single_char_input_does_not_panic(#[case] variant: CorruptPem) {
    let _ = corrupt_pem("X", variant);
}

#[test]
fn newline_only_input_all_variants() {
    let pem = "\n";
    for variant in [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 0 },
        CorruptPem::ExtraBlankLine,
    ] {
        let _ = corrupt_pem(pem, variant);
    }
}

#[test]
fn multiple_newlines_only() {
    let pem = "\n\n\n";
    for variant in [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 1 },
        CorruptPem::ExtraBlankLine,
    ] {
        let out = corrupt_pem(pem, variant);
        assert!(!out.is_empty() || matches!(variant, CorruptPem::Truncate { bytes: 0 }));
    }
}

// ---------------------------------------------------------------------------
// 4. Unicode / multi-byte edge cases
// ---------------------------------------------------------------------------

#[test]
fn unicode_pem_truncate_counts_chars_not_bytes() {
    // Each emoji is 4 bytes but 1 char
    let pem = "🔑🔒🔓";
    let out = corrupt_pem(pem, CorruptPem::Truncate { bytes: 2 });
    assert_eq!(out.chars().count(), 2);
    assert_eq!(out, "🔑🔒");
}

#[test]
fn unicode_pem_bad_header_replaces_first_line() {
    let pem = "🔑header🔑\nbody\nfooter\n";
    let out = corrupt_pem(pem, CorruptPem::BadHeader);
    assert!(out.starts_with("-----BEGIN CORRUPTED KEY-----\n"));
    assert!(!out.contains("🔑header🔑"));
}

// ---------------------------------------------------------------------------
// 5. Truncate boundary values
// ---------------------------------------------------------------------------

#[rstest]
#[case(0, 0)]
#[case(1, 1)]
#[case(5, 5)]
#[case(100, 46)] // PEM has 46 chars, so capped
fn truncate_at_various_lengths(#[case] requested: usize, #[case] expected: usize) {
    let pem = "-----BEGIN TEST-----\nDATA\n-----END TEST-----\n";
    let char_count = pem.chars().count();
    let effective = expected.min(char_count);
    let out = corrupt_pem(pem, CorruptPem::Truncate { bytes: requested });
    assert_eq!(out.chars().count(), effective);
}

#[test]
fn truncate_at_exact_length_preserves_all() {
    let pem = "ABCDEF";
    let out = corrupt_pem(pem, CorruptPem::Truncate { bytes: 6 });
    assert_eq!(out, pem);
}

#[test]
fn truncate_at_one_less_than_length_drops_last_char() {
    let pem = "ABCDEF";
    let out = corrupt_pem(pem, CorruptPem::Truncate { bytes: 5 });
    assert_eq!(out, "ABCDE");
}

// ---------------------------------------------------------------------------
// 6. Deterministic corruption edge cases
// ---------------------------------------------------------------------------

#[test]
fn deterministic_empty_variant_string() {
    let pem = "-----BEGIN TEST-----\nDATA\n-----END TEST-----\n";
    let a = corrupt_pem_deterministic(pem, "");
    let b = corrupt_pem_deterministic(pem, "");
    assert_eq!(a, b);
}

#[test]
fn deterministic_very_long_variant_string() {
    let pem = "-----BEGIN TEST-----\nDATA\n-----END TEST-----\n";
    let long_variant = "a".repeat(10_000);
    let a = corrupt_pem_deterministic(pem, &long_variant);
    let b = corrupt_pem_deterministic(pem, &long_variant);
    assert_eq!(a, b);
    assert_ne!(a, pem);
}

#[test]
fn deterministic_empty_pem_does_not_panic() {
    let _ = corrupt_pem_deterministic("", "some-variant");
}

#[test]
fn deterministic_single_char_pem_does_not_panic() {
    let _ = corrupt_pem_deterministic("X", "some-variant");
}

#[test]
fn deterministic_different_variants_on_empty_input() {
    // Even on empty input, deterministic corruption should be stable
    let a = corrupt_pem_deterministic("", "variant-a");
    let b = corrupt_pem_deterministic("", "variant-a");
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// 7. Parameterized: all variants applied to various PEM types
// ---------------------------------------------------------------------------

const SIMPLE_PEM: &str = "-----BEGIN TEST-----\nABC=\n-----END TEST-----\n";

#[rstest]
#[case(CorruptPem::BadHeader)]
#[case(CorruptPem::BadFooter)]
#[case(CorruptPem::BadBase64)]
#[case(CorruptPem::Truncate { bytes: 10 })]
#[case(CorruptPem::ExtraBlankLine)]
fn each_variant_corrupts_simple_pem(#[case] variant: CorruptPem) {
    let out = corrupt_pem(SIMPLE_PEM, variant);
    assert_ne!(out, SIMPLE_PEM, "variant {variant:?} must change the PEM");
}

#[rstest]
#[case(CorruptPem::BadHeader)]
#[case(CorruptPem::BadFooter)]
#[case(CorruptPem::BadBase64)]
#[case(CorruptPem::Truncate { bytes: 10 })]
#[case(CorruptPem::ExtraBlankLine)]
fn each_variant_is_idempotent_in_output(#[case] variant: CorruptPem) {
    let first = corrupt_pem(SIMPLE_PEM, variant);
    let second = corrupt_pem(SIMPLE_PEM, variant);
    assert_eq!(first, second, "variant {variant:?} must be deterministic");
}

// ---------------------------------------------------------------------------
// 8. Two-line PEM edge cases (boundary for < 3 check)
// ---------------------------------------------------------------------------

#[test]
fn two_line_pem_bad_header() {
    let pem = "HEADER\nFOOTER";
    let out = corrupt_pem(pem, CorruptPem::BadHeader);
    assert!(out.starts_with("-----BEGIN CORRUPTED KEY-----\n"));
    assert!(out.contains("FOOTER"));
}

#[test]
fn two_line_pem_bad_footer() {
    let pem = "HEADER\nFOOTER";
    let out = corrupt_pem(pem, CorruptPem::BadFooter);
    assert!(out.contains("HEADER"));
    assert!(out.contains("-----END CORRUPTED KEY-----"));
}

// ---------------------------------------------------------------------------
// 9. Large input doesn't panic or truncate unexpectedly
// ---------------------------------------------------------------------------

#[test]
fn large_pem_all_variants_succeed() {
    let body = "A".repeat(10_000);
    let pem = format!("-----BEGIN LARGE-----\n{body}\n-----END LARGE-----\n");
    for variant in [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 500 },
        CorruptPem::ExtraBlankLine,
    ] {
        let out = corrupt_pem(&pem, variant);
        assert_ne!(out, pem);
    }
}
