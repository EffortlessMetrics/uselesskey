//! Format roundtrip integration tests for RSA.
//!
//! Validates PEM structure, DER ASN.1 framing, and JWK/JWKS field
//! correctness for RSA key pairs.

mod testutil;

use testutil::fx;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

// ---------------------------------------------------------------------------
// PEM roundtrip
// ---------------------------------------------------------------------------

#[test]
fn private_pem_has_correct_headers() {
    let kp = fx().rsa("pem-hdr", RsaSpec::rs256());
    let pem = kp.private_key_pkcs8_pem();
    assert!(
        pem.starts_with("-----BEGIN PRIVATE KEY-----"),
        "private PEM must start with PKCS#8 header"
    );
    assert!(
        pem.trim_end().ends_with("-----END PRIVATE KEY-----"),
        "private PEM must end with PKCS#8 footer"
    );
}

#[test]
fn public_pem_has_correct_headers() {
    let kp = fx().rsa("pem-pub", RsaSpec::rs256());
    let pem = kp.public_key_spki_pem();
    assert!(
        pem.starts_with("-----BEGIN PUBLIC KEY-----"),
        "public PEM must start with SPKI header"
    );
    assert!(
        pem.trim_end().ends_with("-----END PUBLIC KEY-----"),
        "public PEM must end with SPKI footer"
    );
}

#[test]
fn private_pem_body_is_valid_base64_lines() {
    let kp = fx().rsa("pem-b64", RsaSpec::rs256());
    let pem = kp.private_key_pkcs8_pem();
    for line in pem.lines() {
        if line.starts_with("-----") {
            continue;
        }
        assert!(
            line.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
            "PEM body line must be valid base64: {line}"
        );
    }
}

// ---------------------------------------------------------------------------
// DER structure
// ---------------------------------------------------------------------------

#[test]
fn private_der_starts_with_sequence_tag() {
    let kp = fx().rsa("der-priv", RsaSpec::rs256());
    let der = kp.private_key_pkcs8_der();
    assert!(!der.is_empty(), "DER must not be empty");
    assert_eq!(
        der[0], 0x30,
        "PKCS#8 DER must start with SEQUENCE tag (0x30)"
    );
}

#[test]
fn public_der_starts_with_sequence_tag() {
    let kp = fx().rsa("der-pub", RsaSpec::rs256());
    let der = kp.public_key_spki_der();
    assert_eq!(der[0], 0x30, "SPKI DER must start with SEQUENCE tag (0x30)");
}

#[test]
fn der_length_is_reasonable() {
    let kp = fx().rsa("der-len", RsaSpec::rs256());
    let priv_der = kp.private_key_pkcs8_der();
    let pub_der = kp.public_key_spki_der();
    // RSA-2048 private key DER is typically ~1200 bytes
    assert!(priv_der.len() > 500, "RSA-2048 private DER too short");
    assert!(priv_der.len() < 3000, "RSA-2048 private DER too long");
    // RSA-2048 public key DER is typically ~300 bytes
    assert!(pub_der.len() > 200, "RSA-2048 public DER too short");
    assert!(pub_der.len() < 600, "RSA-2048 public DER too long");
}

// ---------------------------------------------------------------------------
// JWK roundtrip (requires `jwk` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "jwk")]
mod jwk_tests {
    use super::*;

    #[test]
    fn jwk_has_required_rsa_fields() {
        let kp = fx().rsa("jwk-fields", RsaSpec::rs256());
        let v = kp.private_key_jwk().to_value();
        assert_eq!(v["kty"], "RSA", "JWK kty must be RSA");
        assert!(v["n"].is_string(), "JWK must have modulus 'n'");
        assert!(v["e"].is_string(), "JWK must have exponent 'e'");
        assert!(v["d"].is_string(), "private JWK must have 'd'");
        assert!(v["kid"].is_string(), "JWK must have 'kid'");
    }

    #[test]
    fn public_jwk_omits_private_fields() {
        let kp = fx().rsa("jwk-pub", RsaSpec::rs256());
        let v = kp.public_jwk().to_value();
        assert_eq!(v["kty"], "RSA");
        assert!(v["d"].is_null(), "public JWK must not contain 'd'");
        assert!(v["p"].is_null(), "public JWK must not contain 'p'");
        assert!(v["q"].is_null(), "public JWK must not contain 'q'");
    }

    #[test]
    fn jwks_wraps_single_key_in_keys_array() {
        let kp = fx().rsa("jwks-arr", RsaSpec::rs256());
        let v = kp.public_jwks().to_value();
        let keys = v["keys"].as_array().expect("JWKS must have 'keys' array");
        assert_eq!(keys.len(), 1, "single-key JWKS must have exactly 1 entry");
        assert_eq!(keys[0]["kty"], "RSA");
    }
}
