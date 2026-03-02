//! Format roundtrip integration tests for Ed25519.

mod testutil;

use testutil::fx;
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

// ---------------------------------------------------------------------------
// PEM
// ---------------------------------------------------------------------------

#[test]
fn private_pem_has_pkcs8_headers() {
    let kp = fx().ed25519("pem-hdr", Ed25519Spec::new());
    let pem = kp.private_key_pkcs8_pem();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
}

#[test]
fn public_pem_has_spki_headers() {
    let kp = fx().ed25519("pem-pub", Ed25519Spec::new());
    let pem = kp.public_key_spki_pem();
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
}

// ---------------------------------------------------------------------------
// DER
// ---------------------------------------------------------------------------

#[test]
fn private_der_starts_with_sequence_tag() {
    let kp = fx().ed25519("der-priv", Ed25519Spec::new());
    assert_eq!(kp.private_key_pkcs8_der()[0], 0x30);
}

#[test]
fn ed25519_der_is_compact() {
    let kp = fx().ed25519("der-size", Ed25519Spec::new());
    let priv_der = kp.private_key_pkcs8_der();
    let pub_der = kp.public_key_spki_der();
    // Ed25519 keys are small: ~48 bytes private, ~44 bytes public
    assert!(
        priv_der.len() < 200,
        "Ed25519 private DER should be compact"
    );
    assert!(pub_der.len() < 100, "Ed25519 public DER should be compact");
}

// ---------------------------------------------------------------------------
// JWK (requires `jwk` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "jwk")]
mod jwk_tests {
    use super::*;

    #[test]
    fn jwk_has_okp_fields() {
        let kp = fx().ed25519("jwk-okp", Ed25519Spec::new());
        let v = kp.private_key_jwk().to_value();
        assert_eq!(v["kty"], "OKP");
        assert_eq!(v["crv"], "Ed25519");
        assert!(v["x"].is_string(), "OKP JWK must have 'x'");
        assert!(v["d"].is_string(), "private OKP JWK must have 'd'");
    }

    #[test]
    fn public_jwk_omits_d() {
        let kp = fx().ed25519("jwk-pub", Ed25519Spec::new());
        let v = kp.public_jwk().to_value();
        assert_eq!(v["kty"], "OKP");
        assert!(v["d"].is_null(), "public JWK must not contain 'd'");
    }

    #[test]
    fn jwks_wraps_key_in_array() {
        let kp = fx().ed25519("jwks-okp", Ed25519Spec::new());
        let v = kp.public_jwks().to_value();
        let keys = v["keys"].as_array().expect("JWKS must have 'keys'");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "OKP");
    }
}

// ---------------------------------------------------------------------------
// Negative fixtures
// ---------------------------------------------------------------------------

#[test]
fn mismatch_public_key_differs_from_original() {
    let kp = fx().ed25519("mismatch-ed", Ed25519Spec::new());
    let original = kp.public_key_spki_der();
    let mismatched = kp.mismatched_public_key_spki_der();
    assert_ne!(original, mismatched.as_slice());
}

#[test]
fn corrupt_pem_alters_header() {
    let kp = fx().ed25519("corrupt-ed", Ed25519Spec::new());
    let corrupt =
        kp.private_key_pkcs8_pem_corrupt(uselesskey_core::negative::CorruptPem::BadHeader);
    assert!(!corrupt.starts_with("-----BEGIN PRIVATE KEY-----"));
}

#[test]
fn truncated_der_is_prefix_of_original() {
    let kp = fx().ed25519("trunc-ed", Ed25519Spec::new());
    let original = kp.private_key_pkcs8_der();
    let truncated = kp.private_key_pkcs8_der_truncated(16);
    assert_eq!(truncated.len(), 16);
    assert_eq!(&original[..16], truncated.as_slice());
}
