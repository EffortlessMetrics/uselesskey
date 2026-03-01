//! Integration tests for the `uselesskey-core-keypair` facade crate.
//!
//! Verifies the re-export of `Pkcs8SpkiKeyMaterial` from `uselesskey-core-keypair-material`.

use uselesskey_core_keypair::Pkcs8SpkiKeyMaterial;

#[test]
fn facade_re_exports_pkcs8_spki_key_material() {
    let material = Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82],
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59],
        "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n",
    );

    assert_eq!(material.private_key_pkcs8_der(), &[0x30, 0x82]);
    assert!(material.private_key_pkcs8_pem().contains("PRIVATE KEY"));
    assert_eq!(material.public_key_spki_der(), &[0x30, 0x59]);
    assert!(material.public_key_spki_pem().contains("PUBLIC KEY"));
}

#[test]
fn facade_type_supports_kid_generation() {
    let material = Pkcs8SpkiKeyMaterial::new(
        vec![0x30],
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59, 0x30, 0x13],
        "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n",
    );

    let kid = material.kid();
    assert!(!kid.is_empty());
    // Deterministic: same input → same kid
    assert_eq!(kid, material.kid());
}

#[test]
fn facade_debug_hides_key_material() {
    let material = Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82, 0x01, 0x22],
        "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59],
        "-----BEGIN PUBLIC KEY-----\nPUBLIC\n-----END PUBLIC KEY-----\n",
    );

    let dbg = format!("{material:?}");
    assert!(dbg.contains("Pkcs8SpkiKeyMaterial"));
    assert!(!dbg.contains("SECRET"));
    assert!(!dbg.contains("BEGIN PRIVATE KEY"));
}
