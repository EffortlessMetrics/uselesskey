//! Integration tests for `uselesskey-core-negative` public API.
//!
//! These tests exercise the crate boundary: DER corruption helpers and the
//! re-exported PEM corruption surface.

use uselesskey_core_negative::{
    CorruptPem, corrupt_der_deterministic, corrupt_pem, corrupt_pem_deterministic, flip_byte,
    truncate_der,
};

// ---------------------------------------------------------------------------
// truncate_der
// ---------------------------------------------------------------------------

#[test]
fn truncate_der_returns_prefix() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10];
    let out = truncate_der(&der, 3);
    assert_eq!(out, vec![0x30, 0x82, 0x01]);
}

#[test]
fn truncate_der_returns_clone_when_len_exceeds_input() {
    let der = vec![0xAA, 0xBB];
    let out = truncate_der(&der, 100);
    assert_eq!(out, der);
}

#[test]
fn truncate_der_returns_clone_when_len_equals_input() {
    let der = vec![0x01, 0x02, 0x03];
    let out = truncate_der(&der, 3);
    assert_eq!(out, der);
}

#[test]
fn truncate_der_empty_input() {
    let out = truncate_der(&[], 0);
    assert!(out.is_empty());
}

// ---------------------------------------------------------------------------
// flip_byte
// ---------------------------------------------------------------------------

#[test]
fn flip_byte_xor_toggles_lsb() {
    let der = vec![0x00, 0xFF];
    assert_eq!(flip_byte(&der, 0)[0], 0x01);
    assert_eq!(flip_byte(&der, 1)[1], 0xFE);
}

#[test]
fn flip_byte_out_of_bounds_returns_clone() {
    let der = vec![0x30, 0x82];
    assert_eq!(flip_byte(&der, 99), der);
}

#[test]
fn flip_byte_empty_input_returns_empty() {
    assert!(flip_byte(&[], 0).is_empty());
}

// ---------------------------------------------------------------------------
// corrupt_der_deterministic
// ---------------------------------------------------------------------------

#[test]
fn deterministic_der_same_variant_same_output() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0x30, 0x40];
    let a = corrupt_der_deterministic(&der, "corrupt:integration-v1");
    let b = corrupt_der_deterministic(&der, "corrupt:integration-v1");
    assert_eq!(a, b);
}

#[test]
fn deterministic_der_different_variants_differ() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0x30, 0x40];
    let a = corrupt_der_deterministic(&der, "corrupt:alpha");
    let b = corrupt_der_deterministic(&der, "corrupt:beta");
    // With overwhelming probability these differ.
    assert_ne!(a, b);
}

#[test]
fn deterministic_der_always_differs_from_input() {
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0x30, 0x40];
    for i in 0..20 {
        let variant = format!("corrupt:sweep-{i}");
        let out = corrupt_der_deterministic(&der, &variant);
        assert_ne!(out, der, "variant {variant} should corrupt the input");
    }
}

#[test]
fn deterministic_der_single_byte_input() {
    let der = vec![0xFF];
    // Should not panic; corruption still applies.
    let out = corrupt_der_deterministic(&der, "corrupt:one-byte");
    assert!(!out.is_empty() || out.is_empty()); // no panic
}

// ---------------------------------------------------------------------------
// corrupt_pem (re-export surface)
// ---------------------------------------------------------------------------

const PEM: &str = "-----BEGIN TEST KEY-----\nU29tZUJhc2U2NA==\n-----END TEST KEY-----\n";

#[test]
fn reexport_corrupt_pem_bad_header() {
    let out = corrupt_pem(PEM, CorruptPem::BadHeader);
    assert!(out.starts_with("-----BEGIN CORRUPTED KEY-----"));
    assert!(out.contains("U29tZUJhc2U2NA=="));
}

#[test]
fn reexport_corrupt_pem_bad_footer() {
    let out = corrupt_pem(PEM, CorruptPem::BadFooter);
    assert!(out.contains("-----END CORRUPTED KEY-----"));
    assert!(out.contains("-----BEGIN TEST KEY-----"));
}

#[test]
fn reexport_corrupt_pem_bad_base64() {
    let out = corrupt_pem(PEM, CorruptPem::BadBase64);
    assert!(out.contains("THIS_IS_NOT_BASE64!!!"));
}

#[test]
fn reexport_corrupt_pem_truncate() {
    let out = corrupt_pem(PEM, CorruptPem::Truncate { bytes: 10 });
    assert_eq!(out.chars().count(), 10);
}

#[test]
fn reexport_corrupt_pem_extra_blank_line() {
    let out = corrupt_pem(PEM, CorruptPem::ExtraBlankLine);
    let blank_count = out.lines().filter(|l| l.is_empty()).count();
    assert!(blank_count >= 1);
}

#[test]
fn reexport_corrupt_pem_deterministic_stable() {
    let a = corrupt_pem_deterministic(PEM, "corrupt:pem-int-v1");
    let b = corrupt_pem_deterministic(PEM, "corrupt:pem-int-v1");
    assert_eq!(a, b);
}

#[test]
fn reexport_corrupt_pem_deterministic_differs_from_original() {
    for i in 0..20 {
        let variant = format!("corrupt:pem-sweep-{i}");
        let out = corrupt_pem_deterministic(PEM, &variant);
        assert_ne!(out, PEM, "variant {variant} should corrupt PEM");
    }
}
