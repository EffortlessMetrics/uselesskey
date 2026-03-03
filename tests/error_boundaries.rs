//! Error boundary and edge-case tests.
//!
//! Validates that the library handles unusual inputs gracefully:
//! - Empty, long, and unicode labels
//! - Extreme seed values (all-zero, all-0xFF)
//! - Factory reuse after cache clearing
//! - Double corruption (negative on negative)
//! - CorruptPem variant structure
//! - truncate_der boundary lengths
//! - Mismatch key verification

mod testutil;

use uselesskey_core::negative::{CorruptPem, corrupt_pem, truncate_der};
use uselesskey_core::{Factory, Seed};
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

// =========================================================================
// Helpers
// =========================================================================

fn fx() -> Factory {
    testutil::fx()
}

fn deterministic_factory(seed_byte: u8) -> Factory {
    Factory::deterministic(Seed::new([seed_byte; 32]))
}

// =========================================================================
// 1. Empty label strings
// =========================================================================

#[test]
fn empty_label_ecdsa_produces_valid_pem() {
    let fx = fx();
    let kp = fx.ecdsa("", EcdsaSpec::es256());
    let pem = kp.private_key_pkcs8_pem();
    assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(!pem.is_empty());
}

#[test]
fn empty_label_ed25519_produces_valid_pem() {
    let fx = fx();
    let kp = fx.ed25519("", Ed25519Spec::new());
    assert!(
        kp.private_key_pkcs8_pem()
            .contains("-----BEGIN PRIVATE KEY-----")
    );
}

#[test]
fn empty_label_is_distinct_from_nonempty() {
    let fx = deterministic_factory(0xAB);
    let empty = fx.ecdsa("", EcdsaSpec::es256());
    let named = fx.ecdsa("a", EcdsaSpec::es256());
    assert_ne!(empty.private_key_pkcs8_der(), named.private_key_pkcs8_der());
}

// =========================================================================
// 2. Very long label strings (1000+ chars)
// =========================================================================

#[test]
fn long_label_ecdsa_works() {
    let label: String = "x".repeat(2000);
    let fx = fx();
    let kp = fx.ecdsa(&label, EcdsaSpec::es256());
    assert!(
        kp.private_key_pkcs8_pem()
            .contains("-----BEGIN PRIVATE KEY-----")
    );
}

#[test]
fn long_label_ed25519_works() {
    let label: String = "y".repeat(1500);
    let fx = fx();
    let kp = fx.ed25519(&label, Ed25519Spec::new());
    assert!(!kp.private_key_pkcs8_der().is_empty());
}

#[test]
fn long_label_determinism() {
    let label: String = "z".repeat(1000);
    let fx1 = deterministic_factory(0xCC);
    let fx2 = deterministic_factory(0xCC);
    assert_eq!(
        fx1.ecdsa(&label, EcdsaSpec::es256())
            .private_key_pkcs8_der(),
        fx2.ecdsa(&label, EcdsaSpec::es256())
            .private_key_pkcs8_der(),
    );
}

// =========================================================================
// 3. Unicode labels (emoji, CJK, RTL text)
// =========================================================================

#[test]
fn emoji_label_works() {
    let fx = fx();
    let kp = fx.ecdsa("🔑🔐🗝️", EcdsaSpec::es256());
    assert!(
        kp.private_key_pkcs8_pem()
            .contains("-----BEGIN PRIVATE KEY-----")
    );
}

#[test]
fn cjk_label_works() {
    let fx = fx();
    let kp = fx.ed25519("测试密钥生成器", Ed25519Spec::new());
    assert!(!kp.private_key_pkcs8_der().is_empty());
}

#[test]
fn rtl_label_works() {
    let fx = fx();
    let kp = fx.ecdsa("مفتاح_اختبار", EcdsaSpec::es384());
    assert!(
        kp.public_key_spki_pem()
            .contains("-----BEGIN PUBLIC KEY-----")
    );
}

#[test]
fn unicode_labels_are_distinct() {
    let fx = deterministic_factory(0xDD);
    let a = fx.ecdsa("🔑", EcdsaSpec::es256());
    let b = fx.ecdsa("🔐", EcdsaSpec::es256());
    assert_ne!(a.private_key_pkcs8_der(), b.private_key_pkcs8_der());
}

// =========================================================================
// 4. Seed with all zeros
// =========================================================================

#[test]
fn all_zero_seed_produces_valid_keys() {
    let fx = deterministic_factory(0x00);
    let kp = fx.ecdsa("zero-seed", EcdsaSpec::es256());
    assert!(
        kp.private_key_pkcs8_pem()
            .contains("-----BEGIN PRIVATE KEY-----")
    );
    assert!(!kp.public_key_spki_der().is_empty());
}

#[test]
fn all_zero_seed_determinism() {
    let fx1 = deterministic_factory(0x00);
    let fx2 = deterministic_factory(0x00);
    assert_eq!(
        fx1.ed25519("same", Ed25519Spec::new())
            .private_key_pkcs8_pem(),
        fx2.ed25519("same", Ed25519Spec::new())
            .private_key_pkcs8_pem(),
    );
}

// =========================================================================
// 5. Seed with all 0xFF
// =========================================================================

#[test]
fn all_ff_seed_produces_valid_keys() {
    let fx = deterministic_factory(0xFF);
    let kp = fx.ecdsa("ff-seed", EcdsaSpec::es256());
    assert!(
        kp.private_key_pkcs8_pem()
            .contains("-----BEGIN PRIVATE KEY-----")
    );
}

#[test]
fn all_ff_seed_differs_from_all_zero() {
    let fx_zero = deterministic_factory(0x00);
    let fx_ff = deterministic_factory(0xFF);
    assert_ne!(
        fx_zero
            .ecdsa("same", EcdsaSpec::es256())
            .private_key_pkcs8_der(),
        fx_ff
            .ecdsa("same", EcdsaSpec::es256())
            .private_key_pkcs8_der(),
    );
}

#[test]
fn all_ff_seed_ed25519_works() {
    let fx = deterministic_factory(0xFF);
    let kp = fx.ed25519("ff-ed25519", Ed25519Spec::new());
    assert!(!kp.private_key_pkcs8_der().is_empty());
    assert!(!kp.public_key_spki_der().is_empty());
}

// =========================================================================
// 6. Factory reuse after clear_cache
// =========================================================================

#[test]
fn factory_works_after_clear_cache() {
    let fx = deterministic_factory(0xAA);
    let before = fx
        .ecdsa("cached", EcdsaSpec::es256())
        .private_key_pkcs8_pem()
        .to_string();
    fx.clear_cache();
    let after = fx
        .ecdsa("cached", EcdsaSpec::es256())
        .private_key_pkcs8_pem()
        .to_string();
    assert_eq!(
        before, after,
        "deterministic output must survive cache clear"
    );
}

#[test]
fn clear_cache_ed25519_consistency() {
    let fx = deterministic_factory(0xBB);
    let before = fx
        .ed25519("cc", Ed25519Spec::new())
        .private_key_pkcs8_der()
        .to_vec();
    fx.clear_cache();
    let after = fx
        .ed25519("cc", Ed25519Spec::new())
        .private_key_pkcs8_der()
        .to_vec();
    assert_eq!(before, after);
}

#[test]
fn clear_cache_multiple_times() {
    let fx = deterministic_factory(0xCC);
    let original = fx
        .ecdsa("multi", EcdsaSpec::es256())
        .private_key_pkcs8_pem()
        .to_string();
    for _ in 0..5 {
        fx.clear_cache();
        let regenerated = fx
            .ecdsa("multi", EcdsaSpec::es256())
            .private_key_pkcs8_pem()
            .to_string();
        assert_eq!(original, regenerated);
    }
}

// =========================================================================
// 7. Double corruption (negative fixtures on already-negative material)
// =========================================================================

#[test]
fn double_corrupt_pem_bad_header_then_bad_footer() {
    let fx = fx();
    let kp = fx.ecdsa("double-neg", EcdsaSpec::es256());
    let once = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    let twice = corrupt_pem(&once, CorruptPem::BadFooter);
    // First corruption replaced header; second replaced footer
    assert!(twice.contains("CORRUPTED KEY"));
    assert_ne!(once, twice);
}

#[test]
fn double_corrupt_pem_bad_base64_twice_does_not_panic() {
    let fx = fx();
    let kp = fx.ed25519("double-b64", Ed25519Spec::new());
    let once = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    // Second corruption on already-bad base64 should not panic
    let twice = corrupt_pem(&once, CorruptPem::BadBase64);
    assert!(!twice.is_empty());
}

#[test]
fn double_corrupt_pem_truncate_then_truncate() {
    let fx = fx();
    let kp = fx.ecdsa("double-trunc", EcdsaSpec::es256());
    let pem = kp.private_key_pkcs8_pem();
    let once = corrupt_pem(pem, CorruptPem::Truncate { bytes: 80 });
    let twice = corrupt_pem(&once, CorruptPem::Truncate { bytes: 40 });
    assert_eq!(twice.len(), 40);
    assert!(twice.len() < once.len());
}

// =========================================================================
// 8. All CorruptPem variants produce valid-ish PEM structure
// =========================================================================

#[test]
fn corrupt_pem_bad_header_has_begin_line() {
    let fx = fx();
    let kp = fx.ecdsa("cpem-hdr", EcdsaSpec::es256());
    let corrupted = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(
        corrupted.contains("-----BEGIN "),
        "BadHeader should still have a BEGIN line"
    );
    assert!(
        corrupted.contains("-----END PRIVATE KEY-----"),
        "BadHeader should keep original footer"
    );
}

#[test]
fn corrupt_pem_bad_footer_has_end_line() {
    let fx = fx();
    let kp = fx.ecdsa("cpem-ftr", EcdsaSpec::es256());
    let corrupted = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    assert!(
        corrupted.contains("-----BEGIN PRIVATE KEY-----"),
        "BadFooter should keep original header"
    );
    assert!(
        corrupted.contains("-----END "),
        "BadFooter should still have an END line"
    );
}

#[test]
fn corrupt_pem_bad_base64_still_has_pem_envelope() {
    let fx = fx();
    let kp = fx.ed25519("cpem-b64", Ed25519Spec::new());
    let corrupted = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    assert!(corrupted.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(corrupted.contains("-----END PRIVATE KEY-----"));
}

#[test]
fn corrupt_pem_truncate_is_shorter() {
    let fx = fx();
    let kp = fx.ecdsa("cpem-trunc", EcdsaSpec::es256());
    let original = kp.private_key_pkcs8_pem();
    let truncated = kp.private_key_pkcs8_pem_corrupt(CorruptPem::Truncate { bytes: 30 });
    assert!(truncated.len() <= 30);
    assert!(truncated.len() < original.len());
}

#[test]
fn corrupt_pem_extra_blank_line_is_longer() {
    let fx = fx();
    let kp = fx.ecdsa("cpem-blank", EcdsaSpec::es256());
    let original = kp.private_key_pkcs8_pem();
    let with_blank = kp.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine);
    assert!(
        with_blank.len() > original.len(),
        "ExtraBlankLine should add content"
    );
    assert!(with_blank.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(with_blank.contains("-----END PRIVATE KEY-----"));
}

#[test]
fn all_corrupt_pem_variants_produce_nonempty_output() {
    let fx = fx();
    let kp = fx.ecdsa("cpem-all", EcdsaSpec::es256());
    let variants = [
        CorruptPem::BadHeader,
        CorruptPem::BadFooter,
        CorruptPem::BadBase64,
        CorruptPem::Truncate { bytes: 50 },
        CorruptPem::ExtraBlankLine,
    ];
    for variant in variants {
        let corrupted = kp.private_key_pkcs8_pem_corrupt(variant);
        assert!(
            !corrupted.is_empty(),
            "CorruptPem variant {variant:?} produced empty output"
        );
    }
}

// =========================================================================
// 9. truncate_der at various boundary lengths (0, 1, half, full-1)
// =========================================================================

#[test]
fn truncate_der_at_zero() {
    let fx = fx();
    let kp = fx.ecdsa("trunc-0", EcdsaSpec::es256());
    let der = kp.private_key_pkcs8_der();
    let truncated = truncate_der(der, 0);
    assert!(truncated.is_empty());
}

#[test]
fn truncate_der_at_one() {
    let fx = fx();
    let kp = fx.ecdsa("trunc-1", EcdsaSpec::es256());
    let der = kp.private_key_pkcs8_der();
    let truncated = truncate_der(der, 1);
    assert_eq!(truncated.len(), 1);
    assert_eq!(truncated[0], der[0]);
}

#[test]
fn truncate_der_at_half() {
    let fx = fx();
    let kp = fx.ed25519("trunc-half", Ed25519Spec::new());
    let der = kp.private_key_pkcs8_der();
    let half = der.len() / 2;
    let truncated = truncate_der(der, half);
    assert_eq!(truncated.len(), half);
    assert_eq!(&truncated[..], &der[..half]);
}

#[test]
fn truncate_der_at_full_minus_one() {
    let fx = fx();
    let kp = fx.ecdsa("trunc-full-1", EcdsaSpec::es256());
    let der = kp.private_key_pkcs8_der();
    let len = der.len();
    let truncated = truncate_der(der, len - 1);
    assert_eq!(truncated.len(), len - 1);
    assert_eq!(&truncated[..], &der[..len - 1]);
}

#[test]
fn truncate_der_at_full_length_returns_original() {
    let fx = fx();
    let kp = fx.ed25519("trunc-full", Ed25519Spec::new());
    let der = kp.private_key_pkcs8_der();
    let truncated = truncate_der(der, der.len());
    assert_eq!(truncated, der);
}

#[test]
fn truncate_der_beyond_length_returns_original() {
    let fx = fx();
    let kp = fx.ecdsa("trunc-beyond", EcdsaSpec::es256());
    let der = kp.private_key_pkcs8_der();
    let truncated = truncate_der(der, der.len() + 100);
    assert_eq!(truncated, der);
}

// =========================================================================
// 10. Mismatch keys are truly mismatched
// =========================================================================

#[test]
fn rsa_mismatch_public_differs_from_private_key_public() {
    let fx = fx();
    let kp = fx.rsa("mismatch-rsa", RsaSpec::rs256());
    let normal_pub = kp.public_key_spki_der();
    let mismatched_pub = kp.mismatched_public_key_spki_der();
    assert_ne!(
        normal_pub,
        mismatched_pub.as_slice(),
        "mismatched public key must differ from the keypair's own public key"
    );
    // Mismatched key should still be valid DER (starts with ASN.1 SEQUENCE)
    assert_eq!(
        mismatched_pub[0], 0x30,
        "mismatched public key should be valid ASN.1"
    );
}

#[test]
fn ecdsa_mismatch_public_differs_from_private_key_public() {
    let fx = fx();
    let kp = fx.ecdsa("mismatch-ec", EcdsaSpec::es256());
    let normal_pub = kp.public_key_spki_der();
    let mismatched_pub = kp.mismatched_public_key_spki_der();
    assert_ne!(normal_pub, mismatched_pub.as_slice());
    assert_eq!(mismatched_pub[0], 0x30);
}

#[test]
fn ed25519_mismatch_public_differs_from_private_key_public() {
    let fx = fx();
    let kp = fx.ed25519("mismatch-ed", Ed25519Spec::new());
    let normal_pub = kp.public_key_spki_der();
    let mismatched_pub = kp.mismatched_public_key_spki_der();
    assert_ne!(normal_pub, mismatched_pub.as_slice());
    assert_eq!(mismatched_pub[0], 0x30);
}

#[test]
fn mismatch_is_deterministic() {
    let fx1 = deterministic_factory(0xEE);
    let fx2 = deterministic_factory(0xEE);
    let m1 = fx1
        .ecdsa("det-mm", EcdsaSpec::es256())
        .mismatched_public_key_spki_der();
    let m2 = fx2
        .ecdsa("det-mm", EcdsaSpec::es256())
        .mismatched_public_key_spki_der();
    assert_eq!(m1, m2, "mismatched key must be deterministic");
}

#[test]
fn mismatch_public_key_has_same_length_class() {
    let fx = fx();
    let kp = fx.ecdsa("mm-len", EcdsaSpec::es256());
    let normal_len = kp.public_key_spki_der().len();
    let mismatched_len = kp.mismatched_public_key_spki_der().len();
    // Same curve → same SPKI length
    assert_eq!(
        normal_len, mismatched_len,
        "mismatched ECDSA P-256 public key should have the same SPKI length"
    );
}
