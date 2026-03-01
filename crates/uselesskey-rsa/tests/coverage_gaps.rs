//! Coverage-gap tests for uselesskey-rsa.
//!
//! Fills gaps not covered by existing prop/snapshot/unit tests:
//! - RSA-3072 key generation, parsing, and determinism
//! - RSA-4096 key generation, parsing, and determinism
//! - Mismatch variant for non-2048 specs
//! - Random mode basic smoke tests
//! - Tempfile outputs for larger key sizes

mod testutil;

use testutil::fx;
use uselesskey_core::negative::CorruptPem;
use uselesskey_core::{Factory, Seed};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

// =========================================================================
// RSA-3072 tests
// =========================================================================

#[test]
fn rsa_3072_produces_parseable_keys() {
    let fx = fx();
    let kp = fx.rsa("rsa3072-parse", RsaSpec::new(3072));

    let priv_result = rsa::RsaPrivateKey::from_pkcs8_der(kp.private_key_pkcs8_der());
    assert!(priv_result.is_ok(), "RSA-3072 private DER should parse");

    let priv_pem_result = rsa::RsaPrivateKey::from_pkcs8_pem(kp.private_key_pkcs8_pem());
    assert!(priv_pem_result.is_ok(), "RSA-3072 private PEM should parse");

    let pub_result = rsa::RsaPublicKey::from_public_key_der(kp.public_key_spki_der());
    assert!(pub_result.is_ok(), "RSA-3072 public DER should parse");

    let pub_pem_result = rsa::RsaPublicKey::from_public_key_pem(kp.public_key_spki_pem());
    assert!(pub_pem_result.is_ok(), "RSA-3072 public PEM should parse");
}

use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};

#[test]
fn rsa_3072_deterministic_is_stable() {
    let fx = Factory::deterministic(Seed::from_env_value("rsa3072-det").unwrap());
    let k1 = fx.rsa("issuer", RsaSpec::new(3072));
    let k2 = fx.rsa("issuer", RsaSpec::new(3072));

    assert_eq!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
    assert_eq!(k1.public_key_spki_der(), k2.public_key_spki_der());
}

#[test]
fn rsa_3072_mismatch_is_parseable_and_different() {
    let fx = fx();
    let kp = fx.rsa("rsa3072-mm", RsaSpec::new(3072));

    let good = rsa::RsaPublicKey::from_public_key_der(kp.public_key_spki_der()).unwrap();
    let other =
        rsa::RsaPublicKey::from_public_key_der(&kp.mismatched_public_key_spki_der()).unwrap();

    use rsa::traits::PublicKeyParts;
    assert_ne!(good.n(), other.n());
}

// =========================================================================
// RSA-4096 tests
// =========================================================================

#[test]
fn rsa_4096_produces_parseable_keys() {
    let fx = fx();
    let kp = fx.rsa("rsa4096-parse", RsaSpec::new(4096));

    let priv_result = rsa::RsaPrivateKey::from_pkcs8_der(kp.private_key_pkcs8_der());
    assert!(priv_result.is_ok(), "RSA-4096 private DER should parse");

    let pub_result = rsa::RsaPublicKey::from_public_key_der(kp.public_key_spki_der());
    assert!(pub_result.is_ok(), "RSA-4096 public DER should parse");
}

#[test]
fn rsa_4096_deterministic_is_stable() {
    let fx = Factory::deterministic(Seed::from_env_value("rsa4096-det").unwrap());
    let k1 = fx.rsa("issuer", RsaSpec::new(4096));
    let k2 = fx.rsa("issuer", RsaSpec::new(4096));

    assert_eq!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
    assert_eq!(k1.public_key_spki_der(), k2.public_key_spki_der());
}

#[test]
fn rsa_4096_mismatch_is_parseable_and_different() {
    let fx = fx();
    let kp = fx.rsa("rsa4096-mm", RsaSpec::new(4096));

    let good = rsa::RsaPublicKey::from_public_key_der(kp.public_key_spki_der()).unwrap();
    let other =
        rsa::RsaPublicKey::from_public_key_der(&kp.mismatched_public_key_spki_der()).unwrap();

    use rsa::traits::PublicKeyParts;
    assert_ne!(good.n(), other.n());
}

// =========================================================================
// Different specs produce different keys for the same label
// =========================================================================

#[test]
fn different_bit_sizes_produce_different_keys() {
    let fx = fx();
    let k2048 = fx.rsa("same-label", RsaSpec::new(2048));
    let k3072 = fx.rsa("same-label", RsaSpec::new(3072));
    let k4096 = fx.rsa("same-label", RsaSpec::new(4096));

    assert_ne!(k2048.private_key_pkcs8_der(), k3072.private_key_pkcs8_der());
    assert_ne!(k2048.private_key_pkcs8_der(), k4096.private_key_pkcs8_der());
    assert_ne!(k3072.private_key_pkcs8_der(), k4096.private_key_pkcs8_der());
}

// =========================================================================
// Random mode smoke tests
// =========================================================================

#[test]
fn random_mode_produces_valid_keys() {
    let fx = Factory::random();
    let kp = fx.rsa("random-test", RsaSpec::rs256());

    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(kp.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));

    let parsed = rsa::RsaPrivateKey::from_pkcs8_der(kp.private_key_pkcs8_der());
    assert!(parsed.is_ok());
}

#[test]
fn random_mode_caches_same_identity() {
    let fx = Factory::random();
    let k1 = fx.rsa("cache-test", RsaSpec::rs256());
    let k2 = fx.rsa("cache-test", RsaSpec::rs256());

    assert_eq!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
}

// =========================================================================
// Negative fixtures for non-2048 specs
// =========================================================================

#[test]
fn corrupt_pem_for_3072_and_4096() {
    let fx = fx();

    for bits in [3072, 4096] {
        let kp = fx.rsa(format!("corrupt-{bits}"), RsaSpec::new(bits));
        let original = kp.private_key_pkcs8_pem();
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
        assert_ne!(bad, original);
        assert!(rsa::RsaPrivateKey::from_pkcs8_pem(&bad).is_err());
    }
}

#[test]
fn truncated_der_for_3072_and_4096() {
    let fx = fx();

    for bits in [3072, 4096] {
        let kp = fx.rsa(format!("trunc-{bits}"), RsaSpec::new(bits));
        let truncated = kp.private_key_pkcs8_der_truncated(16);
        assert_eq!(truncated.len(), 16);
    }
}

// =========================================================================
// JWK tests for non-2048 specs (feature-gated)
// =========================================================================

#[cfg(feature = "jwk")]
mod jwk_coverage_gaps {
    use super::*;

    #[test]
    fn rsa_3072_jwk_has_rs384_alg() {
        let fx = fx();
        let kp = fx.rsa("jwk-3072", RsaSpec::new(3072));
        let jwk = kp.public_jwk().to_value();

        assert_eq!(jwk["kty"], "RSA");
        assert_eq!(jwk["alg"], "RS384");
        assert_eq!(jwk["use"], "sig");
        assert!(jwk["kid"].is_string());
    }

    #[test]
    fn rsa_4096_jwk_has_rs512_alg() {
        let fx = fx();
        let kp = fx.rsa("jwk-4096", RsaSpec::new(4096));
        let jwk = kp.public_jwk().to_value();

        assert_eq!(jwk["kty"], "RSA");
        assert_eq!(jwk["alg"], "RS512");
        assert_eq!(jwk["use"], "sig");
        assert!(jwk["kid"].is_string());
    }

    #[test]
    fn rsa_3072_private_jwk_has_all_fields() {
        let fx = fx();
        let kp = fx.rsa("priv-jwk-3072", RsaSpec::new(3072));
        let jwk = kp.private_key_jwk().to_value();

        for field in ["n", "e", "d", "p", "q", "dp", "dq", "qi"] {
            assert!(jwk.get(field).is_some(), "Missing field: {field}");
            assert!(jwk[field].is_string(), "Field {field} should be string");
        }
        assert_eq!(jwk["alg"], "RS384");
    }

    #[test]
    fn rsa_4096_private_jwk_has_all_fields() {
        let fx = fx();
        let kp = fx.rsa("priv-jwk-4096", RsaSpec::new(4096));
        let jwk = kp.private_key_jwk().to_value();

        for field in ["n", "e", "d", "p", "q", "dp", "dq", "qi"] {
            assert!(jwk.get(field).is_some(), "Missing field: {field}");
            assert!(jwk[field].is_string(), "Field {field} should be string");
        }
        assert_eq!(jwk["alg"], "RS512");
    }

    #[test]
    fn rsa_3072_jwks_wraps_correctly() {
        let fx = fx();
        let kp = fx.rsa("jwks-3072", RsaSpec::new(3072));
        let jwks = kp.public_jwks().to_value();
        let keys = jwks["keys"].as_array().expect("keys array");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["alg"], "RS384");
    }

    #[test]
    fn rsa_n_length_scales_with_bits() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let fx = fx();

        let kp_2048 = fx.rsa("n-len-2048", RsaSpec::new(2048));
        let kp_3072 = fx.rsa("n-len-3072", RsaSpec::new(3072));
        let kp_4096 = fx.rsa("n-len-4096", RsaSpec::new(4096));

        let n_2048 = URL_SAFE_NO_PAD
            .decode(kp_2048.public_jwk().to_value()["n"].as_str().unwrap())
            .unwrap();
        let n_3072 = URL_SAFE_NO_PAD
            .decode(kp_3072.public_jwk().to_value()["n"].as_str().unwrap())
            .unwrap();
        let n_4096 = URL_SAFE_NO_PAD
            .decode(kp_4096.public_jwk().to_value()["n"].as_str().unwrap())
            .unwrap();

        assert!(
            n_3072.len() > n_2048.len(),
            "3072-bit n should be longer than 2048-bit"
        );
        assert!(
            n_4096.len() > n_3072.len(),
            "4096-bit n should be longer than 3072-bit"
        );
    }
}
