//! Integration tests for the uselesskey-core-keypair facade crate.
//!
//! This crate re-exports `Pkcs8SpkiKeyMaterial` from
//! `uselesskey-core-keypair-material`. These tests verify the
//! re-export is accessible and functional.

use uselesskey_core_keypair::Pkcs8SpkiKeyMaterial;

#[test]
fn pkcs8_spki_key_material_is_importable() {
    let material = Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82, 0x01, 0x22],
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59, 0x30, 0x13],
        "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n",
    );
    assert!(material.private_key_pkcs8_pem().contains("PRIVATE KEY"));
}

#[test]
fn pkcs8_spki_key_material_accessors_work() {
    let material = Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82],
        "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59],
        "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n",
    );
    assert!(material.private_key_pkcs8_pem().contains("PRIVATE KEY"));
    assert!(material.public_key_spki_pem().contains("PUBLIC KEY"));
    assert!(!material.private_key_pkcs8_der().is_empty());
    assert!(!material.public_key_spki_der().is_empty());
}

#[test]
fn kid_is_deterministic_from_facade() {
    let material = Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82, 0x01, 0x22],
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59, 0x30, 0x13],
        "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n",
    );
    let kid1 = material.kid();
    let kid2 = material.kid();
    assert_eq!(kid1, kid2);
    assert!(!kid1.is_empty());
}

#[test]
fn debug_format_does_not_leak_key_material() {
    let material = Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82],
        "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59],
        "-----BEGIN PUBLIC KEY-----\nPUBLIC\n-----END PUBLIC KEY-----\n",
    );
    let dbg = format!("{material:?}");
    assert!(dbg.contains("Pkcs8SpkiKeyMaterial"));
    assert!(!dbg.contains("SECRET"));
    assert!(!dbg.contains("BEGIN PRIVATE KEY"));
}
