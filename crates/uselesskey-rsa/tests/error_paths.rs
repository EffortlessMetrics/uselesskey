//! Error path and boundary condition tests for uselesskey-rsa.
//!
//! Tests panic behavior for invalid specs, negative fixture edge cases,
//! and boundary conditions.

mod testutil;

use testutil::fx;
use uselesskey_core::negative::CorruptPem;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

// =========================================================================
// Invalid bit sizes panic with descriptive messages
// =========================================================================

#[test]
#[should_panic(expected = "RSA bits too small")]
fn rsa_512_bits_panics() {
    let fx = fx();
    let _ = fx.rsa("test", RsaSpec::new(512));
}

#[test]
#[should_panic(expected = "RSA bits too small")]
fn rsa_0_bits_panics() {
    let fx = fx();
    let _ = fx.rsa("test", RsaSpec::new(0));
}

#[test]
#[should_panic(expected = "RSA bits too small")]
fn rsa_1023_bits_panics() {
    let fx = fx();
    let _ = fx.rsa("test", RsaSpec::new(1023));
}

#[test]
fn rsa_1024_bits_does_not_panic() {
    let fx = fx();
    let kp = fx.rsa("test-1024", RsaSpec::new(1024));
    assert!(!kp.private_key_pkcs8_der().is_empty());
}

// =========================================================================
// Unsupported exponent panics
// =========================================================================

#[test]
#[should_panic(expected = "custom RSA public exponent not supported")]
fn rsa_exponent_3_panics() {
    let fx = fx();
    let spec = RsaSpec {
        bits: 2048,
        exponent: 3,
    };
    let _ = fx.rsa("test", spec);
}

#[test]
#[should_panic(expected = "custom RSA public exponent not supported")]
fn rsa_exponent_0_panics() {
    let fx = fx();
    let spec = RsaSpec {
        bits: 2048,
        exponent: 0,
    };
    let _ = fx.rsa("test", spec);
}

// =========================================================================
// Corrupted key material is truly broken
// =========================================================================

#[test]
fn corrupt_pem_bad_header_is_unparseable() {
    let fx = fx();
    let kp = fx.rsa("corrupt-hdr", RsaSpec::rs256());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);

    assert!(
        bad.contains("CORRUPTED"),
        "bad header should contain CORRUPTED marker"
    );
    let parse = rsa::RsaPrivateKey::from_pkcs8_pem(&bad);
    assert!(parse.is_err(), "corrupted PEM header must be unparseable");
}

#[test]
fn corrupt_pem_bad_footer_is_unparseable() {
    let fx = fx();
    let kp = fx.rsa("corrupt-ftr", RsaSpec::rs256());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);

    let parse = rsa::RsaPrivateKey::from_pkcs8_pem(&bad);
    assert!(parse.is_err(), "corrupted PEM footer must be unparseable");
}

#[test]
fn corrupt_pem_bad_base64_is_unparseable() {
    let fx = fx();
    let kp = fx.rsa("corrupt-b64", RsaSpec::rs256());
    let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);

    assert!(bad.contains("THIS_IS_NOT_BASE64!!!"));
    let parse = rsa::RsaPrivateKey::from_pkcs8_pem(&bad);
    assert!(parse.is_err(), "bad base64 PEM must be unparseable");
}

use rsa::pkcs8::DecodePrivateKey;

#[test]
fn truncated_der_is_unparseable() {
    let fx = fx();
    let kp = fx.rsa("trunc-der", RsaSpec::rs256());
    let truncated = kp.private_key_pkcs8_der_truncated(10);

    assert_eq!(truncated.len(), 10);
    let parse = rsa::RsaPrivateKey::from_pkcs8_der(&truncated);
    assert!(parse.is_err(), "truncated DER must be unparseable");
}

#[test]
fn truncated_der_zero_bytes_returns_empty() {
    let fx = fx();
    let kp = fx.rsa("trunc-zero", RsaSpec::rs256());
    let truncated = kp.private_key_pkcs8_der_truncated(0);

    assert!(truncated.is_empty());
}

#[test]
fn truncated_der_larger_than_original_returns_full() {
    let fx = fx();
    let kp = fx.rsa("trunc-large", RsaSpec::rs256());
    let original_len = kp.private_key_pkcs8_der().len();
    let truncated = kp.private_key_pkcs8_der_truncated(original_len + 100);

    // Should not exceed original length
    assert!(truncated.len() <= original_len);
}

// =========================================================================
// Mismatched key is valid but different
// =========================================================================

#[test]
fn mismatched_public_key_is_parseable_but_different() {
    use rsa::pkcs8::DecodePublicKey;

    let fx = fx();
    let kp = fx.rsa("mismatch-test", RsaSpec::rs256());

    let good_pub = rsa::RsaPublicKey::from_public_key_der(kp.public_key_spki_der()).unwrap();
    let bad_pub =
        rsa::RsaPublicKey::from_public_key_der(&kp.mismatched_public_key_spki_der()).unwrap();

    use rsa::traits::PublicKeyParts;
    assert_ne!(good_pub.n(), bad_pub.n(), "mismatched key must differ");
}

// =========================================================================
// Deterministic corruption is stable
// =========================================================================

#[test]
fn deterministic_corrupt_pem_is_stable() {
    let fx = fx();
    let kp = fx.rsa("det-corrupt", RsaSpec::rs256());

    let a = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
    let b = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v1");
    assert_eq!(a, b, "same variant must produce same corruption");

    let c = kp.private_key_pkcs8_pem_corrupt_deterministic("corrupt:v2");
    // Different variants may or may not differ, but the call should not panic
    let _ = c;
}

#[test]
fn deterministic_corrupt_der_is_stable() {
    let fx = fx();
    let kp = fx.rsa("det-corrupt-der", RsaSpec::rs256());

    let a = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:v1");
    let b = kp.private_key_pkcs8_der_corrupt_deterministic("corrupt:v1");
    assert_eq!(a, b, "same variant must produce same DER corruption");
}

// =========================================================================
// stable_bytes edge cases
// =========================================================================

#[test]
fn stable_bytes_max_bits_does_not_panic() {
    let spec = RsaSpec::new(usize::MAX);
    let bytes = spec.stable_bytes();
    // Should clamp to u32::MAX
    assert_eq!(&bytes[..4], &u32::MAX.to_be_bytes());
}

// =========================================================================
// Debug does not leak key material
// =========================================================================

#[test]
fn rsa_keypair_debug_does_not_leak_keys() {
    let fx = fx();
    let kp = fx.rsa("debug-test", RsaSpec::rs256());
    let dbg = format!("{:?}", kp);

    assert!(dbg.contains("RsaKeyPair"));
    assert!(dbg.contains("debug-test"));
    assert!(!dbg.contains("BEGIN PRIVATE KEY"));
    assert!(!dbg.contains("BEGIN PUBLIC KEY"));
}
