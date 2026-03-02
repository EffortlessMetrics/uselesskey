//! Mutant-killing tests for PEM corruption logic.
//!
//! These tests assert exact output values to kill mutants that would survive
//! if we only check "starts_with" / "contains" / "len".

use uselesskey_core_negative_pem::{CorruptPem, corrupt_pem, corrupt_pem_deterministic};

const SAMPLE_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\nABC=\n-----END RSA PRIVATE KEY-----\n";

#[test]
fn bad_header_preserves_body_lines_exactly() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadHeader);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "-----BEGIN CORRUPTED KEY-----");
    assert_eq!(lines[1], "ABC=");
    assert_eq!(lines[2], "-----END RSA PRIVATE KEY-----");
    assert_eq!(lines.len(), 3);
}

#[test]
fn bad_footer_preserves_header_and_body_exactly() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadFooter);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "-----BEGIN RSA PRIVATE KEY-----");
    assert_eq!(lines[1], "ABC=");
    assert_eq!(lines[2], "-----END CORRUPTED KEY-----");
    assert_eq!(lines.len(), 3);
}

#[test]
fn bad_base64_inserts_at_position_1() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::BadBase64);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "-----BEGIN RSA PRIVATE KEY-----");
    assert_eq!(lines[1], "THIS_IS_NOT_BASE64!!!");
    assert_eq!(lines[2], "ABC=");
    assert_eq!(lines[3], "-----END RSA PRIVATE KEY-----");
    assert_eq!(lines.len(), 4);
}

#[test]
fn extra_blank_line_inserts_at_position_1() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::ExtraBlankLine);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "-----BEGIN RSA PRIVATE KEY-----");
    assert_eq!(lines[1], "");
    assert_eq!(lines[2], "ABC=");
    assert_eq!(lines[3], "-----END RSA PRIVATE KEY-----");
    assert_eq!(lines.len(), 4);
}

#[test]
fn truncate_returns_exact_prefix() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes: 5 });
    assert_eq!(out, "-----");
    assert_eq!(out.len(), 5);

    let out_10 = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes: 10 });
    assert_eq!(out_10, "-----BEGIN");
    assert_eq!(out_10.len(), 10);
}

#[test]
fn truncate_zero_returns_empty() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes: 0 });
    assert_eq!(out, "");
}

#[test]
fn truncate_beyond_length_returns_full_input() {
    let out = corrupt_pem(SAMPLE_PEM, CorruptPem::Truncate { bytes: 10000 });
    assert_eq!(out, SAMPLE_PEM);
}

#[test]
fn bad_footer_on_empty_is_just_replacement() {
    let out = corrupt_pem("", CorruptPem::BadFooter);
    assert_eq!(out, "-----END CORRUPTED KEY-----");
}

#[test]
fn bad_base64_on_two_line_input_appends() {
    let short = "H\nF\n";
    let out = corrupt_pem(short, CorruptPem::BadBase64);
    assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
    assert!(out.starts_with("H\nF\n"));
}

#[test]
fn extra_blank_line_on_two_line_input_appends() {
    let short = "H\nF\n";
    let out = corrupt_pem(short, CorruptPem::ExtraBlankLine);
    assert_eq!(out, "H\nF\n\n\n");
}

#[test]
fn deterministic_different_variants_produce_different_outputs() {
    let a = corrupt_pem_deterministic(SAMPLE_PEM, "variant-alpha");
    let b = corrupt_pem_deterministic(SAMPLE_PEM, "variant-beta");
    // They should be deterministically stable but differ from each other
    assert_ne!(a, b);
    assert_eq!(a, corrupt_pem_deterministic(SAMPLE_PEM, "variant-alpha"));
    assert_eq!(b, corrupt_pem_deterministic(SAMPLE_PEM, "variant-beta"));
}

#[test]
fn truncate_boundary_one_char_pem() {
    // For a single-char PEM, derived_truncate_len should return 0
    // because chars <= 1
    let pem = "X";
    let out = corrupt_pem(pem, CorruptPem::Truncate { bytes: 0 });
    assert_eq!(out, "");
}
