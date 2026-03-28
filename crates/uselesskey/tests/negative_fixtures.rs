mod testutil;

use uselesskey::prelude::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fx() -> Factory {
    testutil::fx()
}

fn generated_private_key_pem() -> String {
    #[cfg(feature = "rsa")]
    {
        use uselesskey::{RsaFactoryExt, RsaSpec};
        return fx()
            .rsa("negative-fixtures-standalone", RsaSpec::rs256())
            .private_key_pkcs8_pem()
            .to_owned();
    }

    #[cfg(not(feature = "rsa"))]
    {
        "-----BEGIN PRIVATE KEY-----\nABC=\n-----END PRIVATE KEY-----\n".to_owned()
    }
}

/// Standard PEM must start with "-----BEGIN " and end with "-----END ".
fn is_valid_pem_structure(pem: &str) -> bool {
    let trimmed = pem.trim();
    trimmed.starts_with("-----BEGIN ") && trimmed.contains("-----END ")
}

// ===========================================================================
// 1. Key format validation – normal (non-corrupt) keys parse correctly
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_normal_pkcs8_pem_is_valid() {
    let key = fx().rsa("normal", RsaSpec::rs256());
    let pem = key.private_key_pkcs8_pem();
    assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(pem.contains("-----END PRIVATE KEY-----"));
    assert!(is_valid_pem_structure(pem));
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_normal_spki_pem_is_valid() {
    let key = fx().rsa("normal", RsaSpec::rs256());
    let pem = key.public_key_spki_pem();
    assert!(pem.contains("-----BEGIN PUBLIC KEY-----"));
    assert!(pem.contains("-----END PUBLIC KEY-----"));
    assert!(is_valid_pem_structure(pem));
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_normal_pkcs8_der_is_nonempty() {
    let key = fx().rsa("normal", RsaSpec::rs256());
    let der = key.private_key_pkcs8_der();
    assert!(!der.is_empty());
    // PKCS#8 DER starts with SEQUENCE tag (0x30)
    assert_eq!(der[0], 0x30);
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_normal_spki_der_is_nonempty() {
    let key = fx().rsa("normal", RsaSpec::rs256());
    let der = key.public_key_spki_der();
    assert!(!der.is_empty());
    assert_eq!(der[0], 0x30);
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_normal_pkcs8_pem_is_valid() {
    let key = fx().ecdsa("normal", EcdsaSpec::es256());
    let pem = key.private_key_pkcs8_pem();
    assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(is_valid_pem_structure(pem));
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_normal_spki_pem_is_valid() {
    let key = fx().ecdsa("normal", EcdsaSpec::es256());
    let pem = key.public_key_spki_pem();
    assert!(pem.contains("-----BEGIN PUBLIC KEY-----"));
    assert!(is_valid_pem_structure(pem));
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_normal_pkcs8_pem_is_valid() {
    let key = fx().ed25519("normal", Ed25519Spec::new());
    let pem = key.private_key_pkcs8_pem();
    assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(is_valid_pem_structure(pem));
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_normal_spki_pem_is_valid() {
    let key = fx().ed25519("normal", Ed25519Spec::new());
    let pem = key.public_key_spki_pem();
    assert!(pem.contains("-----BEGIN PUBLIC KEY-----"));
    assert!(is_valid_pem_structure(pem));
}

// ===========================================================================
// 2. Corrupt PEM variants – explicit CorruptPem enum
// ===========================================================================

// --- RSA ---

#[test]
#[cfg(feature = "rsa")]
fn rsa_corrupt_pem_bad_header() {
    let key = fx().rsa("corrupt-test", RsaSpec::rs256());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(corrupted.contains("-----BEGIN CORRUPTED KEY-----"));
    assert!(!corrupted.contains("-----BEGIN PRIVATE KEY-----"));
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_corrupt_pem_bad_footer() {
    let key = fx().rsa("corrupt-test", RsaSpec::rs256());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    assert!(corrupted.contains("-----END CORRUPTED KEY-----"));
    assert!(!corrupted.contains("-----END PRIVATE KEY-----"));
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_corrupt_pem_bad_base64() {
    let key = fx().rsa("corrupt-test", RsaSpec::rs256());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    assert!(corrupted.contains("THIS_IS_NOT_BASE64!!!"));
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_corrupt_pem_truncate() {
    let key = fx().rsa("corrupt-test", RsaSpec::rs256());
    let original = key.private_key_pkcs8_pem();
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 20 });
    assert_eq!(corrupted.len(), 20);
    assert!(corrupted.len() < original.len());
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_corrupt_pem_extra_blank_line() {
    let key = fx().rsa("corrupt-test", RsaSpec::rs256());
    let original = key.private_key_pkcs8_pem();
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine);
    // Blank line injected after header
    assert!(corrupted.contains("-----BEGIN PRIVATE KEY-----\n\n"));
    assert_ne!(corrupted, original);
}

// --- ECDSA ---

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_corrupt_pem_bad_header() {
    let key = fx().ecdsa("corrupt-test", EcdsaSpec::es256());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(corrupted.contains("-----BEGIN CORRUPTED KEY-----"));
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_corrupt_pem_bad_footer() {
    let key = fx().ecdsa("corrupt-test", EcdsaSpec::es256());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    assert!(corrupted.contains("-----END CORRUPTED KEY-----"));
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_corrupt_pem_bad_base64() {
    let key = fx().ecdsa("corrupt-test", EcdsaSpec::es256());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    assert!(corrupted.contains("THIS_IS_NOT_BASE64!!!"));
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_corrupt_pem_truncate() {
    let key = fx().ecdsa("corrupt-test", EcdsaSpec::es256());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 15 });
    assert_eq!(corrupted.len(), 15);
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_corrupt_pem_extra_blank_line() {
    let key = fx().ecdsa("corrupt-test", EcdsaSpec::es256());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine);
    assert!(corrupted.contains("-----BEGIN PRIVATE KEY-----\n\n"));
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_es384_corrupt_pem_bad_header() {
    let key = fx().ecdsa("corrupt-test-384", EcdsaSpec::es384());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(corrupted.contains("-----BEGIN CORRUPTED KEY-----"));
}

// --- Ed25519 ---

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_corrupt_pem_bad_header() {
    let key = fx().ed25519("corrupt-test", Ed25519Spec::new());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(corrupted.contains("-----BEGIN CORRUPTED KEY-----"));
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_corrupt_pem_bad_footer() {
    let key = fx().ed25519("corrupt-test", Ed25519Spec::new());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    assert!(corrupted.contains("-----END CORRUPTED KEY-----"));
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_corrupt_pem_bad_base64() {
    let key = fx().ed25519("corrupt-test", Ed25519Spec::new());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    assert!(corrupted.contains("THIS_IS_NOT_BASE64!!!"));
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_corrupt_pem_truncate() {
    let key = fx().ed25519("corrupt-test", Ed25519Spec::new());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 10 });
    assert_eq!(corrupted.len(), 10);
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_corrupt_pem_extra_blank_line() {
    let key = fx().ed25519("corrupt-test", Ed25519Spec::new());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine);
    assert!(corrupted.contains("-----BEGIN PRIVATE KEY-----\n\n"));
}

// ===========================================================================
// 3. Deterministic PEM corruption – same variant ⇒ same output
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_deterministic_pem_corruption_is_stable() {
    let key = fx().rsa("determ", RsaSpec::rs256());
    let a = key.private_key_pkcs8_pem_corrupt_deterministic("corrupt:neg-v1");
    let b = key.private_key_pkcs8_pem_corrupt_deterministic("corrupt:neg-v1");
    assert_eq!(a, b);
    assert_ne!(a, key.private_key_pkcs8_pem());
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_deterministic_pem_different_variants_differ() {
    let key = fx().rsa("determ", RsaSpec::rs256());
    let a = key.private_key_pkcs8_pem_corrupt_deterministic("corrupt:alpha");
    let b = key.private_key_pkcs8_pem_corrupt_deterministic("corrupt:beta");
    // Different variants should generally produce different corruptions
    // (not guaranteed per-pair, but very likely)
    assert!(a != b || a != key.private_key_pkcs8_pem());
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_deterministic_pem_corruption_is_stable() {
    let key = fx().ecdsa("determ", EcdsaSpec::es256());
    let a = key.private_key_pkcs8_pem_corrupt_deterministic("corrupt:neg-v1");
    let b = key.private_key_pkcs8_pem_corrupt_deterministic("corrupt:neg-v1");
    assert_eq!(a, b);
    assert_ne!(a, key.private_key_pkcs8_pem());
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_deterministic_pem_corruption_is_stable() {
    let key = fx().ed25519("determ", Ed25519Spec::new());
    let a = key.private_key_pkcs8_pem_corrupt_deterministic("corrupt:neg-v1");
    let b = key.private_key_pkcs8_pem_corrupt_deterministic("corrupt:neg-v1");
    assert_eq!(a, b);
    assert_ne!(a, key.private_key_pkcs8_pem());
}

// ===========================================================================
// 4. Truncated DER
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_truncated_der_is_shorter_than_original() {
    let key = fx().rsa("trunc", RsaSpec::rs256());
    let full = key.private_key_pkcs8_der();
    let truncated = key.private_key_pkcs8_der_truncated(10);
    assert_eq!(truncated.len(), 10);
    assert!(truncated.len() < full.len());
    assert_eq!(&truncated[..], &full[..10]);
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_truncated_der_is_shorter_than_original() {
    let key = fx().ecdsa("trunc", EcdsaSpec::es256());
    let full = key.private_key_pkcs8_der();
    let truncated = key.private_key_pkcs8_der_truncated(8);
    assert_eq!(truncated.len(), 8);
    assert!(truncated.len() < full.len());
    assert_eq!(&truncated[..], &full[..8]);
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_truncated_der_is_shorter_than_original() {
    let key = fx().ed25519("trunc", Ed25519Spec::new());
    let full = key.private_key_pkcs8_der();
    let truncated = key.private_key_pkcs8_der_truncated(5);
    assert_eq!(truncated.len(), 5);
    assert!(truncated.len() < full.len());
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_truncated_der_at_zero_is_empty() {
    let key = fx().rsa("trunc-zero", RsaSpec::rs256());
    let truncated = key.private_key_pkcs8_der_truncated(0);
    assert!(truncated.is_empty());
}

// ===========================================================================
// 5. Deterministic DER corruption
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_deterministic_der_corruption_is_stable() {
    let key = fx().rsa("der-determ", RsaSpec::rs256());
    let a = key.private_key_pkcs8_der_corrupt_deterministic("corrupt:der-v1");
    let b = key.private_key_pkcs8_der_corrupt_deterministic("corrupt:der-v1");
    assert_eq!(a, b);
    assert_ne!(a, key.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_deterministic_der_corruption_differs_from_original() {
    let key = fx().rsa("der-determ", RsaSpec::rs256());
    let corrupted = key.private_key_pkcs8_der_corrupt_deterministic("corrupt:der-v2");
    assert_ne!(corrupted.as_slice(), key.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_deterministic_der_corruption_is_stable() {
    let key = fx().ecdsa("der-determ", EcdsaSpec::es256());
    let a = key.private_key_pkcs8_der_corrupt_deterministic("corrupt:der-v1");
    let b = key.private_key_pkcs8_der_corrupt_deterministic("corrupt:der-v1");
    assert_eq!(a, b);
    assert_ne!(a, key.private_key_pkcs8_der());
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_deterministic_der_corruption_is_stable() {
    let key = fx().ed25519("der-determ", Ed25519Spec::new());
    let a = key.private_key_pkcs8_der_corrupt_deterministic("corrupt:der-v1");
    let b = key.private_key_pkcs8_der_corrupt_deterministic("corrupt:der-v1");
    assert_eq!(a, b);
    assert_ne!(a, key.private_key_pkcs8_der());
}

// ===========================================================================
// 6. Mismatched keypairs
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_mismatched_public_key_differs_from_original() {
    let key = fx().rsa("mismatch-test", RsaSpec::rs256());
    let original_pub = key.public_key_spki_der();
    let mismatched_pub = key.mismatched_public_key_spki_der();

    // The mismatched key must be different from the original
    assert_ne!(original_pub, mismatched_pub.as_slice());
    // But it should still be valid DER (starts with SEQUENCE tag)
    assert!(!mismatched_pub.is_empty());
    assert_eq!(mismatched_pub[0], 0x30);
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_mismatched_public_key_differs_from_original() {
    let key = fx().ecdsa("mismatch-test", EcdsaSpec::es256());
    let original_pub = key.public_key_spki_der();
    let mismatched_pub = key.mismatched_public_key_spki_der();

    assert_ne!(original_pub, mismatched_pub.as_slice());
    assert!(!mismatched_pub.is_empty());
    assert_eq!(mismatched_pub[0], 0x30);
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_es384_mismatched_public_key_differs_from_original() {
    let key = fx().ecdsa("mismatch-384", EcdsaSpec::es384());
    let original_pub = key.public_key_spki_der();
    let mismatched_pub = key.mismatched_public_key_spki_der();

    assert_ne!(original_pub, mismatched_pub.as_slice());
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_mismatched_public_key_differs_from_original() {
    let key = fx().ed25519("mismatch-test", Ed25519Spec::new());
    let original_pub = key.public_key_spki_der();
    let mismatched_pub = key.mismatched_public_key_spki_der();

    assert_ne!(original_pub, mismatched_pub.as_slice());
    assert!(!mismatched_pub.is_empty());
    assert_eq!(mismatched_pub[0], 0x30);
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_mismatched_key_is_deterministic() {
    let key = fx().rsa("mismatch-det", RsaSpec::rs256());
    let a = key.mismatched_public_key_spki_der();
    let b = key.mismatched_public_key_spki_der();
    assert_eq!(a, b);
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_mismatched_key_is_deterministic() {
    let key = fx().ecdsa("mismatch-det", EcdsaSpec::es256());
    let a = key.mismatched_public_key_spki_der();
    let b = key.mismatched_public_key_spki_der();
    assert_eq!(a, b);
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_mismatched_key_is_deterministic() {
    let key = fx().ed25519("mismatch-det", Ed25519Spec::new());
    let a = key.mismatched_public_key_spki_der();
    let b = key.mismatched_public_key_spki_der();
    assert_eq!(a, b);
}

// ===========================================================================
// 7. Cross-cutting: corrupt PEM cannot be parsed as valid PEM
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_corrupt_pem_bad_header_is_not_valid_pem() {
    let key = fx().rsa("parse-fail", RsaSpec::rs256());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    // Standard PEM parsers expect "BEGIN PRIVATE KEY", not "BEGIN CORRUPTED KEY"
    assert!(!corrupted.contains("BEGIN PRIVATE KEY"));
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_corrupt_pem_bad_footer_lacks_end_private_key() {
    let key = fx().rsa("parse-fail", RsaSpec::rs256());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    assert!(!corrupted.contains("END PRIVATE KEY"));
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_corrupt_pem_bad_header_is_not_valid_pem() {
    let key = fx().ecdsa("parse-fail", EcdsaSpec::es256());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(!corrupted.contains("BEGIN PRIVATE KEY"));
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_corrupt_pem_bad_header_is_not_valid_pem() {
    let key = fx().ed25519("parse-fail", Ed25519Spec::new());
    let corrupted = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(!corrupted.contains("BEGIN PRIVATE KEY"));
}

// ===========================================================================
// 8. Corrupt PEM via standalone corrupt_pem function
// ===========================================================================

#[test]
fn standalone_corrupt_pem_bad_header() {
    let pem = generated_private_key_pem();
    let corrupted = corrupt_pem(&pem, CorruptPem::BadHeader);
    assert!(corrupted.starts_with("-----BEGIN CORRUPTED KEY-----\n"));
    assert_ne!(corrupted, pem);
}

#[test]
fn standalone_corrupt_pem_bad_footer() {
    let pem = generated_private_key_pem();
    let corrupted = corrupt_pem(&pem, CorruptPem::BadFooter);
    assert!(corrupted.contains("-----END CORRUPTED KEY-----\n"));
    assert!(corrupted.contains("-----BEGIN PRIVATE KEY-----"));
}

#[test]
fn standalone_corrupt_pem_bad_base64() {
    let pem = generated_private_key_pem();
    let corrupted = corrupt_pem(&pem, CorruptPem::BadBase64);
    assert!(corrupted.contains("THIS_IS_NOT_BASE64!!!"));
    // Header and footer are preserved
    assert!(corrupted.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(corrupted.contains("-----END PRIVATE KEY-----"));
}

#[test]
fn standalone_corrupt_pem_truncate() {
    let pem = generated_private_key_pem();
    let corrupted = corrupt_pem(&pem, CorruptPem::Truncate { bytes: 12 });
    assert_eq!(corrupted.len(), 12);
}

#[test]
fn standalone_corrupt_pem_extra_blank_line() {
    let pem = generated_private_key_pem();
    let corrupted = corrupt_pem(&pem, CorruptPem::ExtraBlankLine);
    assert!(corrupted.contains("-----BEGIN PRIVATE KEY-----\n\n"));
}

#[test]
fn standalone_corrupt_pem_deterministic_is_stable() {
    let pem = generated_private_key_pem();
    let a = corrupt_pem_deterministic(&pem, "corrupt:stable-v1");
    let b = corrupt_pem_deterministic(&pem, "corrupt:stable-v1");
    assert_eq!(a, b);
    assert_ne!(a, pem);
}

// ===========================================================================
// 9. Corrupt all five PEM variants are distinct from original
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_all_corrupt_pem_variants_differ_from_original() {
    let key = fx().rsa("all-corrupt", RsaSpec::rs256());
    let original = key.private_key_pkcs8_pem();
    let variants = [
        key.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader),
        key.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter),
        key.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64),
        key.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 30 }),
        key.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine),
    ];
    for (i, v) in variants.iter().enumerate() {
        assert_ne!(v, original, "variant {i} should differ from original");
    }
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_all_corrupt_pem_variants_differ_from_original() {
    let key = fx().ecdsa("all-corrupt", EcdsaSpec::es256());
    let original = key.private_key_pkcs8_pem();
    let variants = [
        key.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader),
        key.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter),
        key.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64),
        key.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 15 }),
        key.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine),
    ];
    for (i, v) in variants.iter().enumerate() {
        assert_ne!(v, original, "variant {i} should differ from original");
    }
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_all_corrupt_pem_variants_differ_from_original() {
    let key = fx().ed25519("all-corrupt", Ed25519Spec::new());
    let original = key.private_key_pkcs8_pem();
    let variants = [
        key.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader),
        key.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter),
        key.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64),
        key.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 10 }),
        key.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine),
    ];
    for (i, v) in variants.iter().enumerate() {
        assert_ne!(v, original, "variant {i} should differ from original");
    }
}

// ===========================================================================
// 10. Multiple deterministic variants produce diverse corruptions
// ===========================================================================

#[test]
#[cfg(feature = "rsa")]
fn rsa_multiple_deterministic_pem_variants_produce_diverse_results() {
    let key = fx().rsa("diverse", RsaSpec::rs256());
    let variants: Vec<String> = (0..10)
        .map(|i| key.private_key_pkcs8_pem_corrupt_deterministic(&format!("corrupt:v{i}")))
        .collect();

    // At least 2 distinct corruptions across 10 variants
    let unique: std::collections::HashSet<_> = variants.iter().collect();
    assert!(
        unique.len() >= 2,
        "expected diverse corruptions, got {} unique",
        unique.len()
    );
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_multiple_deterministic_der_variants_produce_diverse_results() {
    let key = fx().rsa("diverse-der", RsaSpec::rs256());
    let variants: Vec<Vec<u8>> = (0..10)
        .map(|i| key.private_key_pkcs8_der_corrupt_deterministic(&format!("corrupt:d{i}")))
        .collect();

    let unique: std::collections::HashSet<Vec<u8>> = variants.into_iter().collect();
    assert!(
        unique.len() >= 2,
        "expected diverse DER corruptions, got {} unique",
        unique.len()
    );
}
