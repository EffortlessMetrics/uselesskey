use uselesskey_core_keypair::Pkcs8SpkiKeyMaterial;
use uselesskey_core_negative_pem::CorruptPem;

fn sample() -> Pkcs8SpkiKeyMaterial {
    Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09],
        "-----BEGIN PRIVATE KEY-----\nMIIBIjANCAgJ\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86],
        "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoYI\n-----END PUBLIC KEY-----\n",
    )
}

// ── 1. Construction from raw bytes ──────────────────────────────────────────

#[test]
fn construct_from_raw_bytes() {
    let pkcs8_der = vec![0x30, 0x82];
    let spki_der = vec![0x30, 0x59];
    let kp = Pkcs8SpkiKeyMaterial::new(
        pkcs8_der.clone(),
        "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
        spki_der.clone(),
        "-----BEGIN PUBLIC KEY-----\nBB==\n-----END PUBLIC KEY-----\n",
    );
    assert_eq!(kp.private_key_pkcs8_der(), pkcs8_der.as_slice());
    assert_eq!(kp.public_key_spki_der(), spki_der.as_slice());
}

#[test]
fn construct_with_empty_material() {
    let kp = Pkcs8SpkiKeyMaterial::new(Vec::<u8>::new(), "", Vec::<u8>::new(), "");
    assert!(kp.private_key_pkcs8_der().is_empty());
    assert!(kp.private_key_pkcs8_pem().is_empty());
    assert!(kp.public_key_spki_der().is_empty());
    assert!(kp.public_key_spki_pem().is_empty());
}

// ── 2. PEM encoding / accessors ─────────────────────────────────────────────

#[test]
fn private_key_pem_contains_expected_markers() {
    let kp = sample();
    let pem = kp.private_key_pkcs8_pem();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(pem.contains("-----END PRIVATE KEY-----"));
}

#[test]
fn public_key_pem_contains_expected_markers() {
    let kp = sample();
    let pem = kp.public_key_spki_pem();
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    assert!(pem.contains("-----END PUBLIC KEY-----"));
}

#[test]
fn pem_round_trip_preserves_content() {
    let kp = sample();
    let private_pem = kp.private_key_pkcs8_pem();
    let public_pem = kp.public_key_spki_pem();

    let kp2 = Pkcs8SpkiKeyMaterial::new(
        kp.private_key_pkcs8_der(),
        private_pem,
        kp.public_key_spki_der(),
        public_pem,
    );

    assert_eq!(kp2.private_key_pkcs8_pem(), kp.private_key_pkcs8_pem());
    assert_eq!(kp2.public_key_spki_pem(), kp.public_key_spki_pem());
}

// ── 3. DER encoding / accessors ─────────────────────────────────────────────

#[test]
fn der_bytes_match_construction_input() {
    let kp = sample();
    assert_eq!(
        kp.private_key_pkcs8_der(),
        &[0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09]
    );
    assert_eq!(
        kp.public_key_spki_der(),
        &[0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86]
    );
}

#[test]
fn der_length_matches_input() {
    let pkcs8 = vec![1, 2, 3, 4, 5];
    let spki = vec![10, 20, 30];
    let kp = Pkcs8SpkiKeyMaterial::new(pkcs8, "pem", spki, "pem");
    assert_eq!(kp.private_key_pkcs8_der().len(), 5);
    assert_eq!(kp.public_key_spki_der().len(), 3);
}

// ── 4. Corruption variants ──────────────────────────────────────────────────

#[test]
fn corrupt_pem_bad_header() {
    let kp = sample();
    let corrupted = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(corrupted.contains("CORRUPTED KEY"));
    assert!(!corrupted.starts_with("-----BEGIN PRIVATE KEY-----"));
}

#[test]
fn corrupt_pem_bad_footer() {
    let kp = sample();
    let corrupted = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    assert!(corrupted.contains("CORRUPTED KEY"));
    assert!(!corrupted.contains("-----END PRIVATE KEY-----"));
}

#[test]
fn corrupt_pem_bad_base64() {
    let kp = sample();
    let corrupted = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    assert_ne!(corrupted, kp.private_key_pkcs8_pem());
}

#[test]
fn corrupt_pem_truncate() {
    let kp = sample();
    let corrupted = kp.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 10 });
    assert_eq!(corrupted.len(), 10);
}

#[test]
fn corrupt_pem_extra_blank_line() {
    let kp = sample();
    let corrupted = kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine);
    assert_ne!(corrupted, kp.private_key_pkcs8_pem());
    assert!(corrupted.contains("\n\n"));
}

#[test]
fn deterministic_pem_corruption_is_reproducible() {
    let kp = sample();
    let a = kp.private_key_pkcs8_pem_corrupt_deterministic("test:v1");
    let b = kp.private_key_pkcs8_pem_corrupt_deterministic("test:v1");
    assert_eq!(a, b);
    assert_ne!(a, kp.private_key_pkcs8_pem());
}

#[test]
fn deterministic_pem_corruption_differs_by_variant() {
    let kp = sample();
    let a = kp.private_key_pkcs8_pem_corrupt_deterministic("variant-alpha");
    let b = kp.private_key_pkcs8_pem_corrupt_deterministic("variant-beta");
    assert_ne!(a, b);
}

#[test]
fn truncated_der_respects_length() {
    let kp = sample();
    let truncated = kp.private_key_pkcs8_der_truncated(3);
    assert_eq!(truncated.len(), 3);
    assert_eq!(truncated, &kp.private_key_pkcs8_der()[..3]);
}

#[test]
fn truncated_der_caps_at_original_length() {
    let kp = sample();
    let original_len = kp.private_key_pkcs8_der().len();
    let truncated = kp.private_key_pkcs8_der_truncated(original_len + 100);
    assert_eq!(truncated.len(), original_len);
}

#[test]
fn deterministic_der_corruption_is_reproducible() {
    let kp = sample();
    let a = kp.private_key_pkcs8_der_corrupt_deterministic("der:v1");
    let b = kp.private_key_pkcs8_der_corrupt_deterministic("der:v1");
    assert_eq!(a, b);
    assert_ne!(a.as_slice(), kp.private_key_pkcs8_der());
}

#[test]
fn deterministic_der_corruption_differs_by_variant() {
    let kp = sample();
    let a = kp.private_key_pkcs8_der_corrupt_deterministic("der:variant-1");
    let b = kp.private_key_pkcs8_der_corrupt_deterministic("der:variant-2");
    assert_ne!(a, b);
}

// ── 5. Mismatch detection ───────────────────────────────────────────────────

#[test]
fn mismatched_keypair_has_differing_kids() {
    let kp1 = sample();
    let kp2 = Pkcs8SpkiKeyMaterial::new(
        kp1.private_key_pkcs8_der(),
        kp1.private_key_pkcs8_pem(),
        vec![0xFF, 0xFE, 0xFD, 0xFC], // different public key
        "-----BEGIN PUBLIC KEY-----\nDIFF\n-----END PUBLIC KEY-----\n",
    );
    // Same private key but different public key → different kid
    assert_ne!(kp1.kid(), kp2.kid());
}

#[test]
fn two_identical_keypairs_same_kid() {
    let kp1 = sample();
    let kp2 = Pkcs8SpkiKeyMaterial::new(
        kp1.private_key_pkcs8_der(),
        kp1.private_key_pkcs8_pem(),
        kp1.public_key_spki_der(),
        kp1.public_key_spki_pem(),
    );
    assert_eq!(kp1.kid(), kp2.kid());
}

// ── 6. Tempfile writing via sinks ───────────────────────────────────────────

#[test]
fn write_private_key_to_tempfile_round_trips() {
    let kp = sample();
    let artifact = kp
        .write_private_key_pkcs8_pem()
        .expect("should write private key");
    let content = artifact.read_to_string().expect("should read tempfile");
    assert_eq!(content, kp.private_key_pkcs8_pem());
}

#[test]
fn write_public_key_to_tempfile_round_trips() {
    let kp = sample();
    let artifact = kp
        .write_public_key_spki_pem()
        .expect("should write public key");
    let content = artifact.read_to_string().expect("should read tempfile");
    assert_eq!(content, kp.public_key_spki_pem());
}

#[test]
fn tempfiles_contain_pem_markers() {
    let kp = sample();
    let priv_art = kp.write_private_key_pkcs8_pem().unwrap();
    let pub_art = kp.write_public_key_spki_pem().unwrap();

    let priv_text = priv_art.read_to_string().unwrap();
    let pub_text = pub_art.read_to_string().unwrap();

    assert!(priv_text.contains("BEGIN PRIVATE KEY"));
    assert!(pub_text.contains("BEGIN PUBLIC KEY"));
}

// ── 7. Key ID (kid) derivation ──────────────────────────────────────────────

#[test]
fn kid_is_non_empty() {
    assert!(!sample().kid().is_empty());
}

#[test]
fn kid_is_deterministic() {
    let kp = sample();
    assert_eq!(kp.kid(), kp.kid());
}

#[test]
fn kid_depends_on_spki_bytes() {
    let kp_a = Pkcs8SpkiKeyMaterial::new(vec![0x01], "pem-a", vec![0xAA, 0xBB], "pub-a");
    let kp_b = Pkcs8SpkiKeyMaterial::new(vec![0x01], "pem-a", vec![0xCC, 0xDD], "pub-b");
    assert_ne!(kp_a.kid(), kp_b.kid());
}

#[test]
fn kid_ignores_private_key_content() {
    let kp_a = Pkcs8SpkiKeyMaterial::new(vec![0x01], "pem-a", vec![0xAA, 0xBB], "pub");
    let kp_b = Pkcs8SpkiKeyMaterial::new(vec![0xFF], "pem-b", vec![0xAA, 0xBB], "pub");
    // Same SPKI → same kid, regardless of private key
    assert_eq!(kp_a.kid(), kp_b.kid());
}

// ── Debug safety ────────────────────────────────────────────────────────────

#[test]
fn debug_output_does_not_leak_key_material() {
    let kp = sample();
    let dbg = format!("{kp:?}");
    assert!(dbg.contains("Pkcs8SpkiKeyMaterial"));
    assert!(!dbg.contains("BEGIN PRIVATE KEY"));
    assert!(!dbg.contains("BEGIN PUBLIC KEY"));
    assert!(!dbg.contains("MIIBIjANCAgJ"));
}

// ── Clone ───────────────────────────────────────────────────────────────────

#[test]
fn clone_produces_equal_material() {
    let kp = sample();
    let kp2 = kp.clone();
    assert_eq!(kp.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());
    assert_eq!(kp.private_key_pkcs8_pem(), kp2.private_key_pkcs8_pem());
    assert_eq!(kp.public_key_spki_der(), kp2.public_key_spki_der());
    assert_eq!(kp.public_key_spki_pem(), kp2.public_key_spki_pem());
    assert_eq!(kp.kid(), kp2.kid());
}
