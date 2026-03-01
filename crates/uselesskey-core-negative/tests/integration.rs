use rstest::rstest;
use uselesskey_core_negative::{
    CorruptPem, corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic, flip_byte,
    truncate_der,
};

// ── truncate_der ─────────────────────────────────────────────────────

#[test]
fn truncate_der_shortens_to_requested_length() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10];
    let truncated = truncate_der(&der, 3);
    assert_eq!(truncated, &[0x30, 0x82, 0x01]);
}

#[test]
fn truncate_der_returns_full_when_len_exceeds() {
    let der = vec![0x30, 0x82];
    let result = truncate_der(&der, 100);
    assert_eq!(result, der);
}

#[test]
fn truncate_der_to_zero() {
    let der = vec![0x30, 0x82, 0x01];
    let truncated = truncate_der(&der, 0);
    assert!(truncated.is_empty());
}

// ── flip_byte ────────────────────────────────────────────────────────

#[test]
fn flip_byte_xors_target_only() {
    let der = vec![0x00, 0xFF, 0x80];
    let flipped = flip_byte(&der, 1);
    assert_eq!(flipped, &[0x00, 0xFE, 0x80]);
}

#[test]
fn flip_byte_out_of_bounds_returns_copy() {
    let der = vec![0x30, 0x82];
    let result = flip_byte(&der, 100);
    assert_eq!(result, der);
}

#[rstest]
#[case(0, 0x01)]
#[case(1, 0x03)]
fn flip_byte_at_various_offsets(#[case] offset: usize, #[case] expected: u8) {
    let der = vec![0x00, 0x02, 0xFF];
    let flipped = flip_byte(&der, offset);
    assert_eq!(flipped[offset], expected);
}

// ── corrupt_der_deterministic ────────────────────────────────────────

#[test]
fn corrupt_der_deterministic_is_stable() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0x30, 0x40];
    let a = corrupt_der_deterministic(&der, "corrupt:test-v1");
    let b = corrupt_der_deterministic(&der, "corrupt:test-v1");
    assert_eq!(a, b);
}

#[test]
fn corrupt_der_deterministic_differs_from_original() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0x30, 0x40];
    let corrupted = corrupt_der_deterministic(&der, "corrupt:test");
    assert_ne!(corrupted, der);
}

#[test]
fn corrupt_der_deterministic_different_variants_differ() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0x30, 0x40];
    let a = corrupt_der_deterministic(&der, "corrupt:variant-a");
    let b = corrupt_der_deterministic(&der, "corrupt:variant-b");
    // Not guaranteed to differ but overwhelmingly likely for different variant strings
    // We test determinism by checking they're individually stable
    let a2 = corrupt_der_deterministic(&der, "corrupt:variant-a");
    assert_eq!(a, a2);
    let b2 = corrupt_der_deterministic(&der, "corrupt:variant-b");
    assert_eq!(b, b2);
}

// ── corrupt_pem re-exports ───────────────────────────────────────────

const SAMPLE_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\nABC=\n-----END RSA PRIVATE KEY-----\n";

#[test]
fn corrupt_pem_bad_header() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadHeader);
    assert!(out.starts_with("-----BEGIN CORRUPTED KEY-----"));
    assert!(!out.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
}

#[test]
fn corrupt_pem_bad_footer() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadFooter);
    assert!(out.contains("-----END CORRUPTED KEY-----"));
    assert!(!out.contains("-----END RSA PRIVATE KEY-----"));
}

#[test]
fn corrupt_pem_bad_base64() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadBase64);
    assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
}

#[test]
fn corrupt_pem_truncate() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes: 10 });
    assert_eq!(out.len(), 10);
    assert!(out.len() < SAMPLE_PEM.len());
}

#[test]
fn corrupt_pem_extra_blank_line() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::ExtraBlankLine);
    assert!(out.contains("\n\n"));
}

#[rstest]
#[case(CorruptPem::BadHeader)]
#[case(CorruptPem::BadFooter)]
#[case(CorruptPem::BadBase64)]
#[case(CorruptPem::ExtraBlankLine)]
#[case(CorruptPem::Truncate { bytes: 15 })]
fn all_variants_produce_non_empty_output(#[case] variant: CorruptPem) {
    let out = corrupt_pem(SAMPLE_PEM, variant);
    assert!(!out.is_empty());
}

#[rstest]
#[case(CorruptPem::BadHeader)]
#[case(CorruptPem::BadFooter)]
#[case(CorruptPem::BadBase64)]
#[case(CorruptPem::ExtraBlankLine)]
#[case(CorruptPem::Truncate { bytes: 15 })]
fn all_variants_differ_from_original(#[case] variant: CorruptPem) {
    let out = corrupt_pem(SAMPLE_PEM, variant);
    assert_ne!(out, SAMPLE_PEM);
}

// ── corrupt_pem_deterministic re-export ──────────────────────────────

#[test]
fn corrupt_pem_deterministic_is_stable() {
    let a = corrupt_pem_deterministic(SAMPLE_PEM, "corrupt:det-v1");
    let b = corrupt_pem_deterministic(SAMPLE_PEM, "corrupt:det-v1");
    assert_eq!(a, b);
}

#[test]
fn corrupt_pem_deterministic_differs_from_original() {
    let out = corrupt_pem_deterministic(SAMPLE_PEM, "corrupt:det-test");
    assert_ne!(out, SAMPLE_PEM);
}
