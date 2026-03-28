//! Integration tests for the uselesskey-core-keypair facade crate.
//!
//! This crate re-exports `Pkcs8SpkiKeyMaterial` from
//! `uselesskey-core-keypair-material`. These tests verify the
//! re-export is accessible and functional.

mod fixtures;

#[test]
fn pkcs8_spki_key_material_is_importable() {
    let material = fixtures::rsa_material("facade-importable");
    assert!(material.private_key_pkcs8_pem().contains("PRIVATE KEY"));
}

#[test]
fn pkcs8_spki_key_material_accessors_work() {
    let material = fixtures::rsa_material("facade-accessors");
    assert!(material.private_key_pkcs8_pem().contains("PRIVATE KEY"));
    assert!(material.public_key_spki_pem().contains("PUBLIC KEY"));
    assert!(!material.private_key_pkcs8_der().is_empty());
    assert!(!material.public_key_spki_der().is_empty());
}

#[test]
fn kid_is_deterministic_from_facade() {
    let material = fixtures::rsa_material("facade-kid");
    let kid1 = material.kid();
    let kid2 = material.kid();
    assert_eq!(kid1, kid2);
    assert!(!kid1.is_empty());
}

#[test]
fn debug_format_does_not_leak_key_material() {
    let material = fixtures::rsa_material("facade-debug");
    let dbg = format!("{material:?}");
    assert!(dbg.contains("Pkcs8SpkiKeyMaterial"));
    assert!(!dbg.contains("BEGIN PRIVATE KEY"));
}
