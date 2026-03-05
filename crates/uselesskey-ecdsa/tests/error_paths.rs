//! Error path and boundary condition tests for uselesskey-ecdsa.

mod testutil;

use testutil::fx;
use uselesskey_core::negative::CorruptPem;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

// =========================================================================
// Corrupted PEM is unparsable for both curves
// =========================================================================

#[test]
fn es256_corrupt_pem_bad_header_is_unparsable() {
    let fx = fx();
    let kp = fx.ecdsa("corrupt-hdr-256", EcdsaSpec::es256());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);

    assert!(bad.contains("CORRUPTED"));
    // A corrupted PEM should not be parseable as a valid PKCS#8 key
    assert!(
        !bad.starts_with("-----BEGIN PRIVATE KEY-----"),
        "corrupted header should not match valid PEM header"
    );
}

#[test]
fn es384_corrupt_pem_bad_header_is_unparsable() {
    let fx = fx();
    let kp = fx.ecdsa("corrupt-hdr-384", EcdsaSpec::es384());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);

    assert!(bad.contains("CORRUPTED"));
}

#[test]
fn es256_corrupt_pem_bad_base64_contains_marker() {
    let fx = fx();
    let kp = fx.ecdsa("corrupt-b64-256", EcdsaSpec::es256());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);

    assert!(bad.contains("THIS_IS_NOT_BASE64!!!"));
}

#[test]
fn es384_corrupt_pem_bad_base64_contains_marker() {
    let fx = fx();
    let kp = fx.ecdsa("corrupt-b64-384", EcdsaSpec::es384());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);

    assert!(bad.contains("THIS_IS_NOT_BASE64!!!"));
}

// =========================================================================
// Truncated DER edge cases
// =========================================================================

#[test]
fn es256_truncated_der_is_short() {
    let fx = fx();
    let kp = fx.ecdsa("trunc-256", EcdsaSpec::es256());
    let truncated = kp.private_key_pkcs8_der_truncated(5);

    assert_eq!(truncated.len(), 5);
}

#[test]
fn es384_truncated_der_is_short() {
    let fx = fx();
    let kp = fx.ecdsa("trunc-384", EcdsaSpec::es384());
    let truncated = kp.private_key_pkcs8_der_truncated(5);

    assert_eq!(truncated.len(), 5);
}

#[test]
fn truncated_der_zero_returns_empty() {
    let fx = fx();
    let kp = fx.ecdsa("trunc-zero", EcdsaSpec::es256());
    let truncated = kp.private_key_pkcs8_der_truncated(0);

    assert!(truncated.is_empty());
}

#[test]
fn truncated_der_beyond_length_clamps() {
    let fx = fx();
    let kp = fx.ecdsa("trunc-clamp", EcdsaSpec::es256());
    let original_len = kp.private_key_pkcs8_der().len();
    let truncated = kp.private_key_pkcs8_der_truncated(original_len + 1000);

    assert!(truncated.len() <= original_len);
}

// =========================================================================
// Mismatched key is valid but different
// =========================================================================

#[test]
fn es256_mismatched_key_differs() {
    let fx = fx();
    let kp = fx.ecdsa("mm-256", EcdsaSpec::es256());
    let wrong = kp.mismatched_public_key_spki_der();

    assert_ne!(
        wrong,
        kp.public_key_spki_der(),
        "mismatched key must differ from original"
    );
    assert!(!wrong.is_empty(), "mismatched key must not be empty");
}

#[test]
fn es384_mismatched_key_differs() {
    let fx = fx();
    let kp = fx.ecdsa("mm-384", EcdsaSpec::es384());
    let wrong = kp.mismatched_public_key_spki_der();

    assert_ne!(wrong, kp.public_key_spki_der());
    assert!(!wrong.is_empty());
}

// =========================================================================
// Deterministic corruption stability
// =========================================================================

#[test]
fn deterministic_corrupt_pem_is_stable() {
    let fx = fx();
    let kp = fx.ecdsa("det-pem", EcdsaSpec::es256());

    let a = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
    let b = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
    assert_eq!(a, b, "same variant must produce same corruption");
}

#[test]
fn deterministic_corrupt_der_is_stable() {
    let fx = fx();
    let kp = fx.ecdsa("det-der", EcdsaSpec::es256());

    let a = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:v1");
    let b = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:v1");
    assert_eq!(a, b);
}

// =========================================================================
// Debug does not leak key material
// =========================================================================

#[test]
fn ecdsa_keypair_debug_does_not_leak_keys() {
    let fx = fx();
    let kp = fx.ecdsa("debug-test", EcdsaSpec::es256());
    let dbg = format!("{:?}", kp);

    assert!(dbg.contains("EcdsaKeyPair"));
    assert!(dbg.contains("debug-test"));
    assert!(!dbg.contains("BEGIN PRIVATE KEY"));
}

// =========================================================================
// Spec edge cases
// =========================================================================

#[test]
fn different_specs_same_label_produce_different_keys() {
    let fx = fx();
    let es256 = fx.ecdsa("same-label", EcdsaSpec::es256());
    let es384 = fx.ecdsa("same-label", EcdsaSpec::es384());

    assert_ne!(
        es256.private_key_pkcs8_der(),
        es384.private_key_pkcs8_der(),
        "different curves must produce different keys"
    );
}

// =========================================================================
// Empty label works
// =========================================================================

#[test]
fn empty_label_does_not_panic() {
    let fx = fx();
    let kp = fx.ecdsa("", EcdsaSpec::es256());
    assert!(!kp.private_key_pkcs8_der().is_empty());
}

// =========================================================================
// All CorruptPem variants work for both curves
// =========================================================================

#[test]
fn all_corrupt_pem_variants_produce_non_original_output() {
    let fx = fx();

    for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
        let kp = fx.ecdsa(format!("all-corrupt-{}", spec.alg_name()), spec);
        let original = kp.private_key_pkcs8_pem();

        for corrupt in [
            CorruptPem::BadHeader,
            CorruptPem::BadFooter,
            CorruptPem::BadBase64,
            CorruptPem::ExtraBlankLine,
            CorruptPem::Truncate { bytes: 20 },
        ] {
            let bad = kp.private_key_pkcs8_pem_corrupt(corrupt);
            assert_ne!(
                bad,
                original,
                "corrupt variant {:?} for {} should differ from original",
                corrupt,
                spec.alg_name()
            );
        }
    }
}
