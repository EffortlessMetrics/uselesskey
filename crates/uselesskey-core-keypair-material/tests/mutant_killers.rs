//! Mutant-killing tests for keypair material accessors and negative fixtures.

use uselesskey_core::negative::CorruptPem;
use uselesskey_core_keypair_material::Pkcs8SpkiKeyMaterial;

fn sample() -> Pkcs8SpkiKeyMaterial {
    Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82, 0x01, 0x22, 0xAA],
        "-----BEGIN PRIVATE KEY-----\nPRIVATE\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59, 0x30, 0x13, 0xBB],
        "-----BEGIN PUBLIC KEY-----\nPUBLIC\n-----END PUBLIC KEY-----\n",
    )
}

#[test]
fn private_key_pkcs8_der_returns_exact_bytes() {
    let m = sample();
    assert_eq!(m.private_key_pkcs8_der(), &[0x30, 0x82, 0x01, 0x22, 0xAA]);
}

#[test]
fn private_key_pkcs8_pem_returns_exact_string() {
    let m = sample();
    assert_eq!(
        m.private_key_pkcs8_pem(),
        "-----BEGIN PRIVATE KEY-----\nPRIVATE\n-----END PRIVATE KEY-----\n"
    );
}

#[test]
fn public_key_spki_der_returns_exact_bytes() {
    let m = sample();
    assert_eq!(m.public_key_spki_der(), &[0x30, 0x59, 0x30, 0x13, 0xBB]);
}

#[test]
fn public_key_spki_pem_returns_exact_string() {
    let m = sample();
    assert_eq!(
        m.public_key_spki_pem(),
        "-----BEGIN PUBLIC KEY-----\nPUBLIC\n-----END PUBLIC KEY-----\n"
    );
}

#[test]
fn corrupt_bad_header_changes_first_line() {
    let m = sample();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(corrupted.starts_with("-----BEGIN CORRUPTED KEY-----"));
    assert!(corrupted.contains("PRIVATE"));
}

#[test]
fn corrupt_bad_footer_changes_last_line() {
    let m = sample();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    assert!(corrupted.contains("-----END CORRUPTED KEY-----"));
    assert!(corrupted.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn corrupt_bad_base64_injects_line() {
    let m = sample();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    assert!(corrupted.contains("THIS_IS_NOT_BASE64!!!"));
}

#[test]
fn truncated_der_exact_length() {
    let m = sample();
    let truncated = m.private_key_pkcs8_der_truncated(3);
    assert_eq!(truncated, vec![0x30, 0x82, 0x01]);
    assert_eq!(truncated.len(), 3);
}

#[test]
fn truncated_der_beyond_length() {
    let m = sample();
    let truncated = m.private_key_pkcs8_der_truncated(100);
    assert_eq!(truncated, m.private_key_pkcs8_der());
}

#[test]
fn kid_is_derived_from_spki_not_pkcs8() {
    let m1 = sample();
    let m2 = Pkcs8SpkiKeyMaterial::new(
        vec![0xFF, 0xFE, 0xFD], // different private key
        "different private pem",
        vec![0x30, 0x59, 0x30, 0x13, 0xBB], // same public key
        "-----BEGIN PUBLIC KEY-----\nPUBLIC\n-----END PUBLIC KEY-----\n",
    );
    // Kid should be the same because it's derived from SPKI, not PKCS8
    assert_eq!(m1.kid(), m2.kid());
}

#[test]
fn kid_changes_with_different_spki() {
    let m1 = sample();
    let m2 = Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82, 0x01, 0x22, 0xAA],
        "-----BEGIN PRIVATE KEY-----\nPRIVATE\n-----END PRIVATE KEY-----\n",
        vec![0xFF, 0xFE, 0xFD], // different public key
        "-----BEGIN PUBLIC KEY-----\nDIFFERENT\n-----END PUBLIC KEY-----\n",
    );
    assert_ne!(m1.kid(), m2.kid());
}

#[test]
fn debug_does_not_leak_key_material() {
    let m = sample();
    let dbg = format!("{m:?}");
    assert!(dbg.contains("Pkcs8SpkiKeyMaterial"));
    assert!(!dbg.contains("PRIVATE"));
    assert!(!dbg.contains("PUBLIC"));
    assert!(!dbg.contains("BEGIN"));
    // Should show lengths
    assert!(dbg.contains("pkcs8_der_len"));
    assert!(dbg.contains("spki_der_len"));
}

#[test]
fn deterministic_pem_corruption_stable_and_non_trivial() {
    let m = sample();
    let a = m.private_key_pkcs8_pem_corrupt_deterministic("test-variant-1");
    let b = m.private_key_pkcs8_pem_corrupt_deterministic("test-variant-1");
    assert_eq!(a, b);
    assert_ne!(a, m.private_key_pkcs8_pem());
}

#[test]
fn deterministic_der_corruption_stable_and_non_trivial() {
    let m = sample();
    let a = m.private_key_pkcs8_der_corrupt_deterministic("test-variant-1");
    let b = m.private_key_pkcs8_der_corrupt_deterministic("test-variant-1");
    assert_eq!(a, b);
    assert_ne!(a.as_slice(), m.private_key_pkcs8_der());
}

#[test]
fn write_tempfiles_round_trip() {
    let m = sample();
    let priv_temp = m.write_private_key_pkcs8_pem().unwrap();
    let pub_temp = m.write_public_key_spki_pem().unwrap();

    let priv_content = priv_temp.read_to_string().unwrap();
    let pub_content = pub_temp.read_to_string().unwrap();

    assert_eq!(priv_content, m.private_key_pkcs8_pem());
    assert_eq!(pub_content, m.public_key_spki_pem());
}
