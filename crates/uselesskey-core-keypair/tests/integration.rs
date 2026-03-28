//! Integration tests for `uselesskey-core-keypair`.
//!
//! Covers: Pkcs8SpkiKeyMaterial construction, all accessors, kid determinism,
//! Debug safety (no key-material leakage), Clone semantics, negative-fixture
//! helpers (corrupt PEM/DER), and tempfile writers.

use uselesskey_core_keypair::Pkcs8SpkiKeyMaterial;
mod fixtures;

// ── helpers ──────────────────────────────────────────────────────────

fn material_a() -> Pkcs8SpkiKeyMaterial {
    fixtures::rsa_material("material-a")
}

fn material_b() -> Pkcs8SpkiKeyMaterial {
    fixtures::rsa_material("material-b")
}

// ── construction & accessors ─────────────────────────────────────────

#[test]
fn private_key_pkcs8_der_returns_expected_bytes() {
    let m = material_a();
    assert!(!m.private_key_pkcs8_der().is_empty());
}

#[test]
fn private_key_pkcs8_pem_contains_private_key_header() {
    let m = material_a();
    assert!(m.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(m.private_key_pkcs8_pem().contains("END PRIVATE KEY"));
}

#[test]
fn public_key_spki_der_returns_expected_bytes() {
    let m = material_a();
    assert!(!m.public_key_spki_der().is_empty());
}

#[test]
fn public_key_spki_pem_contains_public_key_header() {
    let m = material_a();
    assert!(m.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
    assert!(m.public_key_spki_pem().contains("END PUBLIC KEY"));
}

// ── kid ──────────────────────────────────────────────────────────────

#[test]
fn kid_is_deterministic() {
    let m = material_a();
    assert_eq!(m.kid(), m.kid());
}

#[test]
fn kid_is_non_empty() {
    assert!(!material_a().kid().is_empty());
}

#[test]
fn kid_differs_for_different_spki_bytes() {
    let a = material_a();
    let b = material_b();
    assert_ne!(a.kid(), b.kid());
}

#[test]
fn kid_depends_only_on_spki_not_pkcs8() {
    let m1 = material_a();
    let m2 = Pkcs8SpkiKeyMaterial::new(
        vec![0x02],
        "another-private-pem",
        m1.public_key_spki_der().to_vec(),
        m1.public_key_spki_pem().to_owned(),
    );
    assert_eq!(m1.kid(), m2.kid());
}

// ── Debug safety ─────────────────────────────────────────────────────

#[test]
fn debug_does_not_leak_private_pem() {
    let m = material_a();
    let dbg = format!("{m:?}");
    assert!(dbg.contains("Pkcs8SpkiKeyMaterial"));
    assert!(!dbg.contains("BEGIN PRIVATE KEY"));
    assert!(!dbg.contains("material-a"));
}

#[test]
fn debug_does_not_leak_public_pem() {
    let m = material_a();
    let dbg = format!("{m:?}");
    assert!(!dbg.contains("BEGIN PUBLIC KEY"));
    assert!(!dbg.contains("material-a"));
}

#[test]
fn debug_shows_lengths_not_content() {
    let m = material_a();
    let dbg = format!("{m:?}");
    assert!(dbg.contains("pkcs8_der_len"));
    assert!(dbg.contains("spki_der_len"));
}

// ── Clone ────────────────────────────────────────────────────────────

#[test]
fn clone_preserves_all_accessors() {
    let m = material_a();
    let c = m.clone();
    assert_eq!(m.private_key_pkcs8_der(), c.private_key_pkcs8_der());
    assert_eq!(m.private_key_pkcs8_pem(), c.private_key_pkcs8_pem());
    assert_eq!(m.public_key_spki_der(), c.public_key_spki_der());
    assert_eq!(m.public_key_spki_pem(), c.public_key_spki_pem());
    assert_eq!(m.kid(), c.kid());
}

// ── negative fixture helpers ─────────────────────────────────────────

#[test]
fn corrupt_pem_bad_header_via_keypair() {
    use uselesskey_core_negative::CorruptPem;
    let m = material_a();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(corrupted.contains("CORRUPTED KEY"));
    assert!(!corrupted.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn deterministic_pem_corruption_is_stable() {
    let m = material_a();
    let a = m.private_key_pkcs8_pem_corrupt_deterministic("test:v1");
    let b = m.private_key_pkcs8_pem_corrupt_deterministic("test:v1");
    assert_eq!(a, b);
    assert_ne!(a, m.private_key_pkcs8_pem());
}

#[test]
fn der_truncation_respects_length() {
    let m = material_a();
    let truncated = m.private_key_pkcs8_der_truncated(2);
    assert_eq!(truncated.len(), 2);
    assert_eq!(truncated, &m.private_key_pkcs8_der()[..2]);
}

#[test]
fn der_corrupt_deterministic_is_stable() {
    let m = material_a();
    let a = m.private_key_pkcs8_der_corrupt_deterministic("der:v1");
    let b = m.private_key_pkcs8_der_corrupt_deterministic("der:v1");
    assert_eq!(a, b);
    assert_ne!(a.as_slice(), m.private_key_pkcs8_der());
}

// ── tempfile writers ─────────────────────────────────────────────────

#[test]
fn write_private_key_creates_readable_tempfile() {
    let m = material_a();
    let tmp = m.write_private_key_pkcs8_pem().expect("write private pem");
    let content = tmp.read_to_string().expect("read tempfile");
    assert!(content.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn write_public_key_creates_readable_tempfile() {
    let m = material_a();
    let tmp = m.write_public_key_spki_pem().expect("write public pem");
    let content = tmp.read_to_string().expect("read tempfile");
    assert!(content.contains("BEGIN PUBLIC KEY"));
}
