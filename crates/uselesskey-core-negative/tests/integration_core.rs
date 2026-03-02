//! Integration tests for `uselesskey-core-negative`.
//!
//! Covers: CorruptPem variant construction, Debug output, all-variant coverage,
//! fingerprint stability for deterministic corruption, DER helpers, and
//! edge cases for both PEM and DER corruption paths.

use std::collections::HashSet;

use uselesskey_core_negative::{
    CorruptPem, corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic, flip_byte,
    truncate_der,
};

// ── sample data ──────────────────────────────────────────────────────

const SAMPLE_PEM: &str =
    "-----BEGIN EC PRIVATE KEY-----\nTWF0dGVyIGlzIG1hZGU=\n-----END EC PRIVATE KEY-----\n";

fn sample_der() -> Vec<u8> {
    vec![
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
        0x01,
    ]
}

// ── CorruptPem construction & Debug ──────────────────────────────────

#[test]
fn corrupt_pem_variants_are_constructible() {
    let _a = CorruptPem::BadHeader;
    let _b = CorruptPem::BadFooter;
    let _c = CorruptPem::BadBase64;
    let _d = CorruptPem::Truncate { bytes: 5 };
    let _e = CorruptPem::ExtraBlankLine;
}

#[test]
fn corrupt_pem_debug_output_contains_variant_name() {
    assert!(format!("{:?}", CorruptPem::BadHeader).contains("BadHeader"));
    assert!(format!("{:?}", CorruptPem::BadFooter).contains("BadFooter"));
    assert!(format!("{:?}", CorruptPem::BadBase64).contains("BadBase64"));
    assert!(format!("{:?}", CorruptPem::Truncate { bytes: 7 }).contains("Truncate"));
    assert!(format!("{:?}", CorruptPem::ExtraBlankLine).contains("ExtraBlankLine"));
}

#[test]
fn corrupt_pem_clone_and_copy() {
    let v = CorruptPem::BadHeader;
    let cloned = v;
    let _copied = cloned;
    // CorruptPem is Copy, so all three should be valid
    let _ = format!("{v:?}");
}

// ── all-variant coverage ─────────────────────────────────────────────

#[test]
fn every_variant_corrupts_pem_differently() {
    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::ExtraBlankLine,
        CorruptPem::Truncate { bytes: 12 },
    ];

    let outputs: HashSet<String> = variants
        .iter()
        .map(|v| corrupt_pem(SAMPLE_PEM, *v))
        .collect();
    assert_eq!(
        outputs.len(),
        variants.len(),
        "each variant should produce a distinct output"
    );
}

#[test]
fn no_variant_returns_original() {
    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::ExtraBlankLine,
        CorruptPem::Truncate { bytes: 12 },
    ];

    for v in &variants {
        let out = corrupt_pem(SAMPLE_PEM, *v);
        assert_ne!(out, SAMPLE_PEM, "{v:?} must differ from original");
    }
}

// ── specific variant behavior ────────────────────────────────────────

#[test]
fn bad_header_replaces_begin_line() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadHeader);
    assert!(out.starts_with("-----BEGIN CORRUPTED KEY-----"));
    assert!(!out.contains("-----BEGIN EC PRIVATE KEY-----"));
}

#[test]
fn bad_footer_replaces_end_line() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadFooter);
    assert!(out.contains("-----END CORRUPTED KEY-----"));
    assert!(!out.contains("-----END EC PRIVATE KEY-----"));
}

#[test]
fn bad_base64_injects_invalid_chars() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadBase64);
    assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
    assert!(out.contains("-----BEGIN EC PRIVATE KEY-----"));
}

#[test]
fn truncate_limits_to_exact_byte_count() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes: 8 });
    assert_eq!(out.len(), 8);
}

#[test]
fn extra_blank_line_inserts_empty_line() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::ExtraBlankLine);
    assert!(out.contains("\n\n"));
}

// ── deterministic PEM fingerprint stability ──────────────────────────

#[test]
fn deterministic_pem_is_reproducible() {
    let a = corrupt_pem_deterministic(SAMPLE_PEM, "fingerprint:v1");
    let b = corrupt_pem_deterministic(SAMPLE_PEM, "fingerprint:v1");
    assert_eq!(a, b);
}

#[test]
fn deterministic_pem_differs_for_different_variants() {
    let a = corrupt_pem_deterministic(SAMPLE_PEM, "variant-alpha");
    let b = corrupt_pem_deterministic(SAMPLE_PEM, "variant-beta");
    let c = corrupt_pem_deterministic(SAMPLE_PEM, "variant-gamma");
    let d = corrupt_pem_deterministic(SAMPLE_PEM, "variant-delta");
    let outputs: HashSet<_> = [a, b, c, d].into_iter().collect();
    assert!(
        outputs.len() >= 2,
        "different variant strings should (very likely) produce distinct corruptions"
    );
}

#[test]
fn deterministic_pem_always_differs_from_original() {
    for i in 0..10 {
        let variant = format!("stability-{i}");
        let out = corrupt_pem_deterministic(SAMPLE_PEM, &variant);
        assert_ne!(
            out, SAMPLE_PEM,
            "variant '{variant}' must differ from original"
        );
    }
}

// ── DER helpers ──────────────────────────────────────────────────────

#[test]
fn truncate_der_at_various_lengths() {
    let der = sample_der();
    assert_eq!(truncate_der(&der, 4).len(), 4);
    assert_eq!(truncate_der(&der, 0).len(), 0);
    assert_eq!(truncate_der(&der, 100), der); // beyond length
}

#[test]
fn flip_byte_changes_exactly_one_byte() {
    let der = sample_der();
    for offset in 0..der.len() {
        let flipped = flip_byte(&der, offset);
        assert_eq!(flipped.len(), der.len());
        let diff_count = flipped
            .iter()
            .zip(der.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert_eq!(
            diff_count, 1,
            "exactly one byte should differ at offset {offset}"
        );
    }
}

#[test]
fn flip_byte_out_of_bounds_is_identity() {
    let der = sample_der();
    let result = flip_byte(&der, 1000);
    assert_eq!(result, der);
}

// ── deterministic DER fingerprint stability ──────────────────────────

#[test]
fn deterministic_der_is_reproducible() {
    let der = sample_der();
    let a = corrupt_der_deterministic(&der, "der-fp:v1");
    let b = corrupt_der_deterministic(&der, "der-fp:v1");
    assert_eq!(a, b);
}

#[test]
fn deterministic_der_differs_from_original() {
    let der = sample_der();
    let out = corrupt_der_deterministic(&der, "der-must-differ");
    assert_ne!(out, der);
}

#[test]
fn deterministic_der_different_variants_produce_variety() {
    let der = sample_der();
    let outputs: HashSet<Vec<u8>> = (0..10)
        .map(|i| corrupt_der_deterministic(&der, &format!("var-{i}")))
        .collect();
    assert!(
        outputs.len() >= 2,
        "different variant strings should produce varied corruptions"
    );
}
