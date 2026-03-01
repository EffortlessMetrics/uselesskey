//! Integration tests for negative fixture support in Pkcs8SpkiKeyMaterial.

use uselesskey_core_keypair_material::Pkcs8SpkiKeyMaterial;

fn sample() -> Pkcs8SpkiKeyMaterial {
    Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82, 0x01, 0x22, 0x10, 0x20, 0x30, 0x40],
        "-----BEGIN PRIVATE KEY-----\nMIIBVQ==\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59, 0x30, 0x13, 0xAA, 0xBB, 0xCC, 0xDD],
        "-----BEGIN PUBLIC KEY-----\nMFkwEw==\n-----END PUBLIC KEY-----\n",
    )
}

// ── corrupt PEM ──────────────────────────────────────────────────────

#[test]
fn corrupt_pem_bad_header_replaces_header() {
    use uselesskey_core::negative::CorruptPem;

    let m = sample();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(corrupted.contains("CORRUPTED KEY"));
    assert!(!corrupted.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn corrupt_pem_bad_base64_is_not_valid_base64() {
    use uselesskey_core::negative::CorruptPem;

    let m = sample();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    assert!(corrupted.contains("THIS_IS_NOT_BASE64!!!"));
}

#[test]
fn corrupt_pem_truncate_shortens_output() {
    use uselesskey_core::negative::CorruptPem;

    let m = sample();
    let corrupted = m.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 10 });
    assert_eq!(corrupted.len(), 10);
}

// ── deterministic PEM corruption ─────────────────────────────────────

#[test]
fn deterministic_pem_corruption_is_reproducible() {
    let m = sample();
    let a = m.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
    let b = m.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
    assert_eq!(a, b);
}

#[test]
fn deterministic_pem_corruption_differs_across_variants() {
    let m = sample();
    let a = m.private_key_pkcs8_pem_corrupt_deterministic("corrupt:alpha");
    let b = m.private_key_pkcs8_pem_corrupt_deterministic("corrupt:beta");
    assert_ne!(a, b);
}

// ── truncated DER ────────────────────────────────────────────────────

#[test]
fn truncated_der_respects_length() {
    let m = sample();
    let truncated = m.private_key_pkcs8_der_truncated(3);
    assert_eq!(truncated.len(), 3);
    assert_eq!(truncated, &m.private_key_pkcs8_der()[..3]);
}

#[test]
fn truncated_der_beyond_len_returns_full() {
    let m = sample();
    let truncated = m.private_key_pkcs8_der_truncated(1000);
    assert_eq!(truncated, m.private_key_pkcs8_der());
}

#[test]
fn truncated_der_to_zero_returns_empty() {
    let m = sample();
    let truncated = m.private_key_pkcs8_der_truncated(0);
    assert!(truncated.is_empty());
}

// ── deterministic DER corruption ─────────────────────────────────────

#[test]
fn deterministic_der_corruption_is_reproducible() {
    let m = sample();
    let a = m.private_key_pkcs8_der_corrupt_deterministic("corrupt:d1");
    let b = m.private_key_pkcs8_der_corrupt_deterministic("corrupt:d1");
    assert_eq!(a, b);
}

#[test]
fn deterministic_der_corruption_differs_from_original() {
    let m = sample();
    let corrupted = m.private_key_pkcs8_der_corrupt_deterministic("corrupt:d1");
    assert_ne!(corrupted, m.private_key_pkcs8_der());
}

#[test]
fn deterministic_der_corruption_differs_across_variants() {
    let m = sample();
    let a = m.private_key_pkcs8_der_corrupt_deterministic("corrupt:x");
    let b = m.private_key_pkcs8_der_corrupt_deterministic("corrupt:y");
    assert_ne!(a, b);
}

// ── clone preserves data ─────────────────────────────────────────────

#[test]
fn clone_preserves_all_accessors() {
    let m = sample();
    let c = m.clone();
    assert_eq!(c.private_key_pkcs8_der(), m.private_key_pkcs8_der());
    assert_eq!(c.private_key_pkcs8_pem(), m.private_key_pkcs8_pem());
    assert_eq!(c.public_key_spki_der(), m.public_key_spki_der());
    assert_eq!(c.public_key_spki_pem(), m.public_key_spki_pem());
    assert_eq!(c.kid(), m.kid());
}

// ── tempfile round trips ─────────────────────────────────────────────

#[test]
fn write_private_key_tempfile_has_pem_extension() {
    let m = sample();
    let temp = m.write_private_key_pkcs8_pem().unwrap();
    let ext = temp.path().extension().unwrap().to_str().unwrap();
    assert_eq!(ext, "pem");
}

#[test]
fn write_public_key_tempfile_has_pem_extension() {
    let m = sample();
    let temp = m.write_public_key_spki_pem().unwrap();
    let ext = temp.path().extension().unwrap().to_str().unwrap();
    assert_eq!(ext, "pem");
}

#[test]
fn tempfile_round_trip_preserves_content() {
    let m = sample();
    let private_temp = m.write_private_key_pkcs8_pem().unwrap();
    let public_temp = m.write_public_key_spki_pem().unwrap();
    assert_eq!(
        private_temp.read_to_string().unwrap(),
        m.private_key_pkcs8_pem()
    );
    assert_eq!(
        public_temp.read_to_string().unwrap(),
        m.public_key_spki_pem()
    );
}
