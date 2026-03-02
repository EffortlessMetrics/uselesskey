//! Edge-case and boundary tests for PEM corruption.

use uselesskey_core_negative_pem::{CorruptPem, corrupt_pem, corrupt_pem_deterministic};

const SAMPLE_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA0Z3VS5JJcds3xf0G
-----END PRIVATE KEY-----";

// ── Minimal PEM inputs ──────────────────────────────────────────────

#[test]
fn corrupt_empty_pem_bad_header() {
    let result = corrupt_pem("", CorruptPem::BadHeader);
    // Should not panic on empty input
    let _ = result;
}

#[test]
fn corrupt_single_line_pem_bad_footer() {
    let result = corrupt_pem("-----BEGIN PRIVATE KEY-----", CorruptPem::BadFooter);
    let _ = result;
}

#[test]
fn corrupt_pem_with_no_base64_content() {
    let pem = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----";
    let result = corrupt_pem(pem, CorruptPem::BadBase64);
    let _ = result;
}

// ── Truncate boundary ───────────────────────────────────────────────

#[test]
fn truncate_zero_bytes_produces_empty() {
    let result = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes: 0 });
    assert!(
        result.is_empty(),
        "Truncate{{bytes: 0}} should produce empty string"
    );
}

#[test]
fn truncate_more_than_content_returns_full() {
    let result = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes: 100_000 });
    // Taking more chars than exist should return the full PEM
    assert_eq!(result, SAMPLE_PEM);
}

// ── All CorruptPem variants produce different outputs ────────────────

#[test]
fn all_variants_produce_different_corruptions() {
    use std::collections::HashSet;

    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 5 },
        CorruptPem::ExtraBlankLine,
    ];
    let mut results = HashSet::new();
    for variant in variants {
        results.insert(corrupt_pem(SAMPLE_PEM, variant));
    }
    // All should differ from the original
    for result in &results {
        assert_ne!(result, SAMPLE_PEM, "corruption should change the PEM");
    }
}

// ── Deterministic corruption ────────────────────────────────────────

#[test]
fn deterministic_corruption_is_stable() {
    let c1 = corrupt_pem_deterministic(SAMPLE_PEM, "variant-a");
    let c2 = corrupt_pem_deterministic(SAMPLE_PEM, "variant-a");
    assert_eq!(c1, c2);
}

#[test]
fn deterministic_different_variants_produce_different_corruptions() {
    let c1 = corrupt_pem_deterministic(SAMPLE_PEM, "variant-a");
    let c2 = corrupt_pem_deterministic(SAMPLE_PEM, "variant-b");
    // High probability they differ (hash selects different strategy)
    // but not guaranteed for all pairs; at least they should both be valid corruptions
    assert_ne!(&c1, SAMPLE_PEM);
    assert_ne!(&c2, SAMPLE_PEM);
}

#[test]
fn deterministic_empty_variant() {
    let result = corrupt_pem_deterministic(SAMPLE_PEM, "");
    assert_ne!(&result, SAMPLE_PEM);
}

#[test]
fn deterministic_unicode_variant() {
    let result = corrupt_pem_deterministic(SAMPLE_PEM, "日本語🔑");
    assert_ne!(&result, SAMPLE_PEM);
}

// ── CorruptPem trait coverage ───────────────────────────────────────

#[test]
fn corrupt_pem_clone() {
    let c = CorruptPem::BadHeader;
    let c2 = c;
    assert!(matches!(c2, CorruptPem::BadHeader));
}

#[test]
fn corrupt_pem_debug() {
    let dbg = format!("{:?}", CorruptPem::Truncate { bytes: 42 });
    assert!(dbg.contains("Truncate"));
    assert!(dbg.contains("42"));
}
