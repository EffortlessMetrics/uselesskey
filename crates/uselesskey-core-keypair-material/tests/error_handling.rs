//! Error handling and edge case tests for `uselesskey-core-keypair-material`.

use rstest::rstest;
use uselesskey_core::negative::CorruptPem;
use uselesskey_core_keypair_material::Pkcs8SpkiKeyMaterial;

// ── helpers ──────────────────────────────────────────────────────────────

fn sample_material() -> Pkcs8SpkiKeyMaterial {
    Pkcs8SpkiKeyMaterial::new(
        vec![0x30, 0x82, 0x01, 0x22],
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59, 0x30, 0x13],
        "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n",
    )
}

fn empty_der_material() -> Pkcs8SpkiKeyMaterial {
    Pkcs8SpkiKeyMaterial::new(
        Vec::<u8>::new(),
        "-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----\n",
        Vec::<u8>::new(),
        "-----BEGIN PUBLIC KEY-----\n\n-----END PUBLIC KEY-----\n",
    )
}

fn single_byte_material() -> Pkcs8SpkiKeyMaterial {
    Pkcs8SpkiKeyMaterial::new(
        vec![0x30],
        "-----BEGIN PRIVATE KEY-----\nMA==\n-----END PRIVATE KEY-----\n",
        vec![0x30],
        "-----BEGIN PUBLIC KEY-----\nMA==\n-----END PUBLIC KEY-----\n",
    )
}

// ---------------------------------------------------------------------------
// 1. Debug impl: no key material leakage
// ---------------------------------------------------------------------------

#[test]
fn debug_does_not_leak_private_key_pem() {
    let m = sample_material();
    let dbg = format!("{m:?}");
    assert!(
        !dbg.contains("BEGIN PRIVATE KEY"),
        "leaked private PEM header"
    );
    assert!(
        !dbg.contains("END PRIVATE KEY"),
        "leaked private PEM footer"
    );
    assert!(!dbg.contains("AAAA"), "leaked private key base64 body");
}

#[test]
fn debug_does_not_leak_public_key_pem() {
    let m = sample_material();
    let dbg = format!("{m:?}");
    assert!(
        !dbg.contains("BEGIN PUBLIC KEY"),
        "leaked public PEM header"
    );
    assert!(!dbg.contains("END PUBLIC KEY"), "leaked public PEM footer");
    assert!(!dbg.contains("BBBB"), "leaked public key base64 body");
}

#[test]
fn debug_shows_type_name_and_lengths() {
    let m = sample_material();
    let dbg = format!("{m:?}");
    assert!(dbg.contains("Pkcs8SpkiKeyMaterial"));
    assert!(dbg.contains("pkcs8_der_len"));
    assert!(dbg.contains("pkcs8_pem_len"));
    assert!(dbg.contains("spki_der_len"));
    assert!(dbg.contains("spki_pem_len"));
}

#[test]
fn debug_lengths_are_accurate() {
    let m = sample_material();
    let dbg = format!("{m:?}");
    // pkcs8_der has 4 bytes
    assert!(
        dbg.contains("pkcs8_der_len: 4"),
        "expected pkcs8_der_len: 4 in {dbg}"
    );
    // spki_der has 4 bytes
    assert!(
        dbg.contains("spki_der_len: 4"),
        "expected spki_der_len: 4 in {dbg}"
    );
}

// ---------------------------------------------------------------------------
// 2. All CorruptPem variants on private key PEM
// ---------------------------------------------------------------------------

#[rstest]
#[case(CorruptPem::BadHeader)]
#[case(CorruptPem::BadFooter)]
#[case(CorruptPem::BadBase64)]
#[case(CorruptPem::Truncate { bytes: 10 })]
#[case(CorruptPem::ExtraBlankLine)]
fn all_corrupt_pem_variants_produce_different_output(#[case] variant: CorruptPem) {
    let m = sample_material();
    let corrupted = m.private_key_pkcs8_pem_corrupt(variant);
    assert_ne!(
        corrupted,
        m.private_key_pkcs8_pem(),
        "variant {variant:?} should change the PEM"
    );
}

#[rstest]
#[case(CorruptPem::BadHeader)]
#[case(CorruptPem::BadFooter)]
#[case(CorruptPem::BadBase64)]
#[case(CorruptPem::Truncate { bytes: 10 })]
#[case(CorruptPem::ExtraBlankLine)]
fn corrupt_pem_is_deterministic(#[case] variant: CorruptPem) {
    let m = sample_material();
    let a = m.private_key_pkcs8_pem_corrupt(variant);
    let b = m.private_key_pkcs8_pem_corrupt(variant);
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// 3. DER truncation edge cases
// ---------------------------------------------------------------------------

#[test]
fn truncate_zero_gives_empty() {
    let m = sample_material();
    assert!(m.private_key_pkcs8_der_truncated(0).is_empty());
}

#[test]
fn truncate_beyond_length_returns_full_der() {
    let m = sample_material();
    let full_len = m.private_key_pkcs8_der().len();
    let truncated = m.private_key_pkcs8_der_truncated(full_len + 100);
    assert_eq!(truncated.len(), full_len);
    assert_eq!(truncated, m.private_key_pkcs8_der());
}

#[test]
fn truncate_exact_length_returns_full_der() {
    let m = sample_material();
    let full_len = m.private_key_pkcs8_der().len();
    let truncated = m.private_key_pkcs8_der_truncated(full_len);
    assert_eq!(truncated, m.private_key_pkcs8_der());
}

#[test]
fn truncate_preserves_prefix_bytes() {
    let m = sample_material();
    for len in 1..=m.private_key_pkcs8_der().len() {
        let truncated = m.private_key_pkcs8_der_truncated(len);
        assert_eq!(&truncated[..], &m.private_key_pkcs8_der()[..len]);
    }
}

// ---------------------------------------------------------------------------
// 4. Empty DER edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_der_truncate_zero() {
    let m = empty_der_material();
    assert!(m.private_key_pkcs8_der_truncated(0).is_empty());
}

#[test]
fn empty_der_truncate_nonzero_returns_empty() {
    let m = empty_der_material();
    assert!(m.private_key_pkcs8_der_truncated(10).is_empty());
}

#[test]
fn empty_der_kid_is_still_deterministic() {
    let m = empty_der_material();
    let a = m.kid();
    let b = m.kid();
    assert_eq!(a, b);
    assert!(!a.is_empty());
}

// ---------------------------------------------------------------------------
// 5. Single byte DER edge cases
// ---------------------------------------------------------------------------

#[test]
fn single_byte_der_truncate_one() {
    let m = single_byte_material();
    let t = m.private_key_pkcs8_der_truncated(1);
    assert_eq!(t.len(), 1);
    assert_eq!(t[0], 0x30);
}

#[test]
fn single_byte_der_corrupt_deterministic() {
    let m = single_byte_material();
    let a = m.private_key_pkcs8_der_corrupt_deterministic("variant-a");
    let b = m.private_key_pkcs8_der_corrupt_deterministic("variant-a");
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// 6. Deterministic PEM corruption: variant sensitivity
// ---------------------------------------------------------------------------

#[test]
fn deterministic_pem_different_variants_differ() {
    let m = sample_material();
    let a = m.private_key_pkcs8_pem_corrupt_deterministic("v1");
    let b = m.private_key_pkcs8_pem_corrupt_deterministic("v2");
    // While not guaranteed for all pairs, these specific variants should differ
    assert_ne!(a, b);
}

#[test]
fn deterministic_pem_empty_variant() {
    let m = sample_material();
    let a = m.private_key_pkcs8_pem_corrupt_deterministic("");
    let b = m.private_key_pkcs8_pem_corrupt_deterministic("");
    assert_eq!(a, b);
    assert_ne!(a, m.private_key_pkcs8_pem());
}

// ---------------------------------------------------------------------------
// 7. Deterministic DER corruption: stability and variant sensitivity
// ---------------------------------------------------------------------------

#[test]
fn deterministic_der_is_stable() {
    let m = sample_material();
    let a = m.private_key_pkcs8_der_corrupt_deterministic("stable-test");
    let b = m.private_key_pkcs8_der_corrupt_deterministic("stable-test");
    assert_eq!(a, b);
}

#[test]
fn deterministic_der_different_variants_differ() {
    let m = sample_material();
    let a = m.private_key_pkcs8_der_corrupt_deterministic("alpha");
    let b = m.private_key_pkcs8_der_corrupt_deterministic("beta");
    assert_ne!(a, b);
}

#[test]
fn deterministic_der_corrupt_differs_from_original() {
    let m = sample_material();
    let corrupted = m.private_key_pkcs8_der_corrupt_deterministic("test");
    assert_ne!(corrupted, m.private_key_pkcs8_der());
}

// ---------------------------------------------------------------------------
// 8. kid: depends only on SPKI, not on PKCS#8
// ---------------------------------------------------------------------------

#[test]
fn kid_same_spki_different_pkcs8() {
    let m1 = Pkcs8SpkiKeyMaterial::new(
        vec![0x01, 0x02],
        "-----BEGIN PRIVATE KEY-----\nAQI=\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59],
        "-----BEGIN PUBLIC KEY-----\nMFk=\n-----END PUBLIC KEY-----\n",
    );
    let m2 = Pkcs8SpkiKeyMaterial::new(
        vec![0xFF, 0xFE],
        "-----BEGIN PRIVATE KEY-----\n//4=\n-----END PRIVATE KEY-----\n",
        vec![0x30, 0x59],
        "-----BEGIN PUBLIC KEY-----\nMFk=\n-----END PUBLIC KEY-----\n",
    );
    assert_eq!(m1.kid(), m2.kid());
}

#[test]
fn kid_different_spki_different_kid() {
    let m1 = Pkcs8SpkiKeyMaterial::new(
        vec![0x30],
        "-----BEGIN PRIVATE KEY-----\nMA==\n-----END PRIVATE KEY-----\n",
        vec![0x01],
        "-----BEGIN PUBLIC KEY-----\nAQ==\n-----END PUBLIC KEY-----\n",
    );
    let m2 = Pkcs8SpkiKeyMaterial::new(
        vec![0x30],
        "-----BEGIN PRIVATE KEY-----\nMA==\n-----END PRIVATE KEY-----\n",
        vec![0x02],
        "-----BEGIN PUBLIC KEY-----\nAg==\n-----END PUBLIC KEY-----\n",
    );
    assert_ne!(m1.kid(), m2.kid());
}

// ---------------------------------------------------------------------------
// 9. Clone independence
// ---------------------------------------------------------------------------

#[test]
fn clone_has_same_kid() {
    let m = sample_material();
    let c = m.clone();
    assert_eq!(m.kid(), c.kid());
}

#[test]
fn clone_corruption_does_not_affect_original() {
    let m = sample_material();
    let c = m.clone();
    // Corrupt on clone
    let _ = c.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    // Original is unchanged
    assert!(m.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
}

// ---------------------------------------------------------------------------
// 10. Tempfile write round-trip
// ---------------------------------------------------------------------------

#[test]
fn tempfile_private_key_content_matches() {
    let m = sample_material();
    let tmp = m.write_private_key_pkcs8_pem().expect("write private");
    let content = tmp.read_to_string().expect("read");
    assert_eq!(content, m.private_key_pkcs8_pem());
}

#[test]
fn tempfile_public_key_content_matches() {
    let m = sample_material();
    let tmp = m.write_public_key_spki_pem().expect("write public");
    let content = tmp.read_to_string().expect("read");
    assert_eq!(content, m.public_key_spki_pem());
}
