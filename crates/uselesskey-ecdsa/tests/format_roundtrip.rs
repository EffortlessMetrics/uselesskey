//! Format roundtrip integration tests for ECDSA.

mod testutil;

use testutil::fx;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

// ---------------------------------------------------------------------------
// PEM
// ---------------------------------------------------------------------------

#[test]
fn private_pem_has_pkcs8_headers() {
    let kp = fx().ecdsa("pem-hdr", EcdsaSpec::es256());
    let pem = kp.private_key_pkcs8_pem();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
}

#[test]
fn public_pem_has_spki_headers() {
    let kp = fx().ecdsa("pem-pub", EcdsaSpec::es256());
    let pem = kp.public_key_spki_pem();
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
}

// ---------------------------------------------------------------------------
// DER
// ---------------------------------------------------------------------------

#[test]
fn private_der_starts_with_sequence_tag() {
    let kp = fx().ecdsa("der-priv", EcdsaSpec::es256());
    assert_eq!(kp.private_key_pkcs8_der()[0], 0x30);
}

#[test]
fn public_der_starts_with_sequence_tag() {
    let kp = fx().ecdsa("der-pub", EcdsaSpec::es384());
    assert_eq!(kp.public_key_spki_der()[0], 0x30);
}

#[test]
fn p384_keys_are_larger_than_p256() {
    let fx = fx();
    let p256 = fx.ecdsa("size-256", EcdsaSpec::es256());
    let p384 = fx.ecdsa("size-384", EcdsaSpec::es384());
    assert!(
        p384.private_key_pkcs8_der().len() > p256.private_key_pkcs8_der().len(),
        "P-384 DER should be larger than P-256 DER"
    );
}

// ---------------------------------------------------------------------------
// JWK (requires `jwk` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "jwk")]
mod jwk_tests {
    use super::*;

    #[test]
    fn jwk_has_ec_fields() {
        let kp = fx().ecdsa("jwk-ec", EcdsaSpec::es256());
        let v = kp.private_key_jwk().to_value();
        assert_eq!(v["kty"], "EC");
        assert_eq!(v["crv"], "P-256");
        assert!(v["x"].is_string(), "EC JWK must have 'x'");
        assert!(v["y"].is_string(), "EC JWK must have 'y'");
        assert!(v["d"].is_string(), "private EC JWK must have 'd'");
    }

    #[test]
    fn public_jwk_omits_private_component() {
        let kp = fx().ecdsa("jwk-pub", EcdsaSpec::es384());
        let v = kp.public_jwk().to_value();
        assert_eq!(v["kty"], "EC");
        assert_eq!(v["crv"], "P-384");
        assert!(v["d"].is_null(), "public JWK must not contain 'd'");
    }

    #[test]
    fn jwks_has_keys_array() {
        let kp = fx().ecdsa("jwks-ec", EcdsaSpec::es256());
        let v = kp.public_jwks().to_value();
        let keys = v["keys"].as_array().expect("JWKS must have 'keys'");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "EC");
    }
}

// ---------------------------------------------------------------------------
// Negative fixtures
// ---------------------------------------------------------------------------

#[test]
fn mismatch_public_key_differs_from_original() {
    let kp = fx().ecdsa("mismatch-ec", EcdsaSpec::es256());
    let original = kp.public_key_spki_der();
    let mismatched = kp.mismatched_public_key_spki_der();
    assert_ne!(original, mismatched.as_slice());
}

#[test]
fn corrupt_pem_is_not_parseable_as_valid_key() {
    let kp = fx().ecdsa("corrupt-ec", EcdsaSpec::es256());
    let corrupt =
        kp.private_key_pkcs8_pem_corrupt(uselesskey_core::negative::CorruptPem::BadHeader);
    assert!(!corrupt.starts_with("-----BEGIN PRIVATE KEY-----"));
}

#[test]
fn truncated_der_has_exact_length() {
    let kp = fx().ecdsa("trunc-ec", EcdsaSpec::es256());
    let truncated = kp.private_key_pkcs8_der_truncated(8);
    assert_eq!(truncated.len(), 8);
}
