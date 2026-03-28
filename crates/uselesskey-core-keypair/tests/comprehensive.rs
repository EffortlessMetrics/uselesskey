//! Comprehensive tests for `uselesskey-core-keypair`.
//!
//! Covers edge cases and scenarios not covered by existing test files:
//! - All `CorruptPem` variants via the facade
//! - Debug safety for DER hex content
//! - Tempfile content fidelity and path extensions
//! - Empty and edge-case inputs
//! - DER truncation boundary conditions
//! - Different deterministic variants diverge
//! - `Into<Arc<[u8]>>` conversion in constructor
//! - kid format properties

use std::sync::Arc;
use uselesskey_core_keypair::Pkcs8SpkiKeyMaterial;
use uselesskey_core_negative::CorruptPem;
mod fixtures;

// ── helpers ──────────────────────────────────────────────────────────

fn sample() -> Pkcs8SpkiKeyMaterial {
    fixtures::rsa_material("comprehensive-sample")
}

// ── CorruptPem variant coverage ──────────────────────────────────────

#[test]
fn corrupt_pem_bad_footer() {
    let m = sample();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    assert!(corrupted.contains("END CORRUPTED KEY"));
    assert!(!corrupted.contains("END PRIVATE KEY"));
    // Header should remain intact
    assert!(corrupted.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn corrupt_pem_bad_base64() {
    let m = sample();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    assert_ne!(corrupted, m.private_key_pkcs8_pem());
}

#[test]
fn corrupt_pem_truncate() {
    let m = sample();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 10 });
    assert_eq!(corrupted.len(), 10);
    // Should be a prefix of the original
    assert!(m.private_key_pkcs8_pem().starts_with(&corrupted));
}

#[test]
fn corrupt_pem_extra_blank_line() {
    let m = sample();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine);
    assert_ne!(corrupted, m.private_key_pkcs8_pem());
    // Should still contain PEM boundary markers
    assert!(corrupted.contains("BEGIN PRIVATE KEY"));
    assert!(corrupted.contains("END PRIVATE KEY"));
}

#[test]
fn all_corrupt_pem_variants_differ_from_original() {
    let m = sample();
    let original = m.private_key_pkcs8_pem();

    let variants = [
        m.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader),
        m.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter),
        m.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64),
        m.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 10 }),
        m.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine),
    ];

    for (i, v) in variants.iter().enumerate() {
        assert_ne!(v, original, "variant {i} should differ from original");
    }
}

// ── Debug safety: DER hex content ────────────────────────────────────

#[test]
fn debug_does_not_contain_der_hex_bytes() {
    let m = fixtures::rsa_material("comprehensive-debug");
    let dbg = format!("{m:?}");
    // Should not contain raw byte values or PEM body content
    assert!(!dbg.contains("DEADBEEF"), "must not leak private DER hex");
    assert!(!dbg.contains("CAFEBABE"), "must not leak public DER hex");
    assert!(
        !dbg.contains("BEGIN PRIVATE KEY"),
        "must not leak private PEM"
    );
    assert!(
        !dbg.contains("BEGIN PUBLIC KEY"),
        "must not leak public PEM"
    );
}

#[test]
fn debug_uses_non_exhaustive_marker() {
    let m = sample();
    let dbg = format!("{m:?}");
    assert!(dbg.contains(".."), "Debug should use finish_non_exhaustive");
}

// ── kid format properties ────────────────────────────────────────────

#[test]
fn kid_is_base64url_charset() {
    let m = sample();
    let kid = m.kid();
    assert!(
        kid.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "kid should be base64url-shaped, got: {kid}"
    );
}

#[test]
fn kid_has_consistent_length() {
    let m1 = sample();
    let m2 = Pkcs8SpkiKeyMaterial::new(
        vec![0xFF],
        "priv",
        vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        "pub",
    );
    // All kids should have the same length regardless of input size
    assert_eq!(m1.kid().len(), m2.kid().len());
}

// ── Arc conversion in constructor ────────────────────────────────────

#[test]
fn new_accepts_arc_slice_directly() {
    let pkcs8: Arc<[u8]> = Arc::from(vec![0x30, 0x82].as_slice());
    let spki: Arc<[u8]> = Arc::from(vec![0x30, 0x59].as_slice());
    let m = Pkcs8SpkiKeyMaterial::new(
        pkcs8,
        "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n",
        spki,
        "-----BEGIN PUBLIC KEY-----\nY\n-----END PUBLIC KEY-----\n",
    );
    assert_eq!(m.private_key_pkcs8_der(), &[0x30, 0x82]);
    assert_eq!(m.public_key_spki_der(), &[0x30, 0x59]);
}

// ── Empty and edge-case inputs ───────────────────────────────────────

#[test]
fn empty_der_produces_valid_material() {
    let m = Pkcs8SpkiKeyMaterial::new(Vec::<u8>::new(), "", Vec::<u8>::new(), "");
    assert!(m.private_key_pkcs8_der().is_empty());
    assert!(m.private_key_pkcs8_pem().is_empty());
    assert!(m.public_key_spki_der().is_empty());
    assert!(m.public_key_spki_pem().is_empty());
    // kid should still be deterministic and non-empty even for empty SPKI
    assert!(!m.kid().is_empty());
}

#[test]
fn single_byte_der_works() {
    let m = Pkcs8SpkiKeyMaterial::new(vec![0xFF], "p", vec![0x01], "q");
    assert_eq!(m.private_key_pkcs8_der(), &[0xFF]);
    assert_eq!(m.public_key_spki_der(), &[0x01]);
}

// ── DER truncation boundary conditions ───────────────────────────────

#[test]
fn der_truncation_to_zero_yields_empty() {
    let m = sample();
    let truncated = m.private_key_pkcs8_der_truncated(0);
    assert!(truncated.is_empty());
}

#[test]
fn der_truncation_beyond_length_yields_full_der() {
    let m = sample();
    let full_len = m.private_key_pkcs8_der().len();
    let truncated = m.private_key_pkcs8_der_truncated(full_len + 100);
    assert_eq!(truncated.len(), full_len);
    assert_eq!(truncated.as_slice(), m.private_key_pkcs8_der());
}

#[test]
fn der_truncation_at_exact_length_returns_identical() {
    let m = sample();
    let full_len = m.private_key_pkcs8_der().len();
    let truncated = m.private_key_pkcs8_der_truncated(full_len);
    assert_eq!(truncated.as_slice(), m.private_key_pkcs8_der());
}

// ── Deterministic corruption divergence ──────────────────────────────

#[test]
fn different_deterministic_pem_variants_produce_different_output() {
    let m = sample();
    let a = m.private_key_pkcs8_pem_corrupt_deterministic("variant-alpha");
    let b = m.private_key_pkcs8_pem_corrupt_deterministic("variant-beta");
    assert_ne!(
        a, b,
        "different variants must produce different corruptions"
    );
}

#[test]
fn different_deterministic_der_variants_produce_different_output() {
    let m = sample();
    let a = m.private_key_pkcs8_der_corrupt_deterministic("der-alpha");
    let b = m.private_key_pkcs8_der_corrupt_deterministic("der-beta");
    assert_ne!(
        a, b,
        "different DER variants must produce different corruptions"
    );
}

// ── Tempfile content fidelity ────────────────────────────────────────

#[test]
fn tempfile_private_key_matches_pem_exactly() {
    let m = sample();
    let tmp = m.write_private_key_pkcs8_pem().expect("write");
    let content = tmp.read_to_string().expect("read");
    assert_eq!(content, m.private_key_pkcs8_pem());
}

#[test]
fn tempfile_public_key_matches_pem_exactly() {
    let m = sample();
    let tmp = m.write_public_key_spki_pem().expect("write");
    let content = tmp.read_to_string().expect("read");
    assert_eq!(content, m.public_key_spki_pem());
}

#[test]
fn tempfile_private_key_path_has_pem_extension() {
    let m = sample();
    let tmp = m.write_private_key_pkcs8_pem().expect("write");
    let path_str = tmp.path().to_string_lossy();
    assert!(
        path_str.ends_with(".pkcs8.pem"),
        "expected .pkcs8.pem suffix, got: {path_str}"
    );
}

#[test]
fn tempfile_public_key_path_has_pem_extension() {
    let m = sample();
    let tmp = m.write_public_key_spki_pem().expect("write");
    let path_str = tmp.path().to_string_lossy();
    assert!(
        path_str.ends_with(".spki.pem"),
        "expected .spki.pem suffix, got: {path_str}"
    );
}

// ── Clone independence ───────────────────────────────────────────────

#[test]
fn clone_is_independent_from_original() {
    let m = sample();
    let c = m.clone();
    // Both should have identical kids
    assert_eq!(m.kid(), c.kid());
    // Corruption on clone should not affect original's base PEM
    let corrupt_from_clone = c.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert_ne!(corrupt_from_clone, m.private_key_pkcs8_pem());
    // Original's PEM remains unchanged
    assert!(m.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
}
