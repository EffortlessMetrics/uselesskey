//! Coverage-gap tests for uselesskey-ecdsa.
//!
//! Fills gaps not covered by existing prop/keypair/jwk tests:
//! - P-384 tempfile round-trip
//! - Random mode smoke for both specs
//! - Different specs produce different keys for same label
//! - Determinism across separate factories for P-384
//! - Corrupt PEM variants beyond BadBase64
//! - P-384 JWK private key d field length

#[allow(dead_code)]
mod testutil;

use uselesskey_core::negative::CorruptPem;
use uselesskey_core::{Factory, Seed};
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

// =========================================================================
// P-384 tempfile round-trip
// =========================================================================

#[test]
fn p384_tempfiles_match_in_memory() {
    let fx = Factory::random();
    let key = fx.ecdsa("p384-tempfile", EcdsaSpec::es384());

    let priv_tf = key.write_private_key_pkcs8_pem().expect("private tempfile");
    let pub_tf = key.write_public_key_spki_pem().expect("public tempfile");

    let priv_contents = std::fs::read_to_string(priv_tf.path()).expect("read private");
    let pub_contents = std::fs::read_to_string(pub_tf.path()).expect("read public");

    assert_eq!(priv_contents, key.private_key_pkcs8_pem());
    assert_eq!(pub_contents, key.public_key_spki_pem());
}

// =========================================================================
// Random mode smoke tests
// =========================================================================

#[test]
fn random_mode_es256_produces_valid_keys() {
    let fx = Factory::random();
    let key = fx.ecdsa("random-es256", EcdsaSpec::es256());

    assert!(key.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(key.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
    assert!(!key.private_key_pkcs8_der().is_empty());
    assert!(!key.public_key_spki_der().is_empty());
}

#[test]
fn random_mode_es384_produces_valid_keys() {
    let fx = Factory::random();
    let key = fx.ecdsa("random-es384", EcdsaSpec::es384());

    assert!(key.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(key.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));

    use p384::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
    assert!(p384::SecretKey::from_pkcs8_der(key.private_key_pkcs8_der()).is_ok());
    assert!(p384::PublicKey::from_public_key_der(key.public_key_spki_der()).is_ok());
}

#[test]
fn random_mode_caches_same_identity() {
    let fx = Factory::random();
    let k1 = fx.ecdsa("cache-test", EcdsaSpec::es256());
    let k2 = fx.ecdsa("cache-test", EcdsaSpec::es256());

    assert_eq!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
}

// =========================================================================
// Different specs produce different keys for same label
// =========================================================================

#[test]
fn different_specs_produce_different_keys_for_same_label() {
    let fx = Factory::deterministic(Seed::from_env_value("ecdsa-spec-iso").unwrap());
    let es256 = fx.ecdsa("same-label", EcdsaSpec::es256());
    let es384 = fx.ecdsa("same-label", EcdsaSpec::es384());

    assert_ne!(es256.private_key_pkcs8_der(), es384.private_key_pkcs8_der());
    assert_ne!(es256.public_key_spki_der(), es384.public_key_spki_der());
}

// =========================================================================
// Determinism across separate factories for P-384
// =========================================================================

#[test]
fn p384_determinism_across_factories() {
    let seed1 = Seed::from_env_value("ecdsa-p384-cross").unwrap();
    let seed2 = Seed::from_env_value("ecdsa-p384-cross").unwrap();
    let fx1 = Factory::deterministic(seed1);
    let fx2 = Factory::deterministic(seed2);

    let k1 = fx1.ecdsa("cross-factory", EcdsaSpec::es384());
    let k2 = fx2.ecdsa("cross-factory", EcdsaSpec::es384());

    assert_eq!(k1.private_key_pkcs8_der(), k2.private_key_pkcs8_der());
    assert_eq!(k1.public_key_spki_der(), k2.public_key_spki_der());
}

// =========================================================================
// Corrupt PEM variants beyond BadBase64
// =========================================================================

#[test]
fn corrupt_pem_bad_header_for_both_specs() {
    let fx = Factory::random();

    for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
        let key = fx.ecdsa("corrupt-hdr", spec);
        let bad = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));
        assert_ne!(bad, key.private_key_pkcs8_pem());
    }
}

#[test]
fn corrupt_pem_bad_footer_for_both_specs() {
    let fx = Factory::random();

    for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
        let key = fx.ecdsa("corrupt-ftr", spec);
        let bad = key.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
        assert_ne!(bad, key.private_key_pkcs8_pem());
    }
}

#[test]
fn corrupt_pem_extra_blank_line_for_both_specs() {
    let fx = Factory::random();

    for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
        let key = fx.ecdsa("corrupt-blank", spec);
        let bad = key.private_key_pkcs8_pem_corrupt(CorruptPem::ExtraBlankLine);
        assert_ne!(bad, key.private_key_pkcs8_pem());
    }
}

// =========================================================================
// P-384 JWK coverage (feature-gated)
// =========================================================================

#[cfg(feature = "jwk")]
mod jwk_coverage_gaps {
    use super::*;

    #[test]
    fn p384_private_jwk_d_length_is_48() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let fx = Factory::deterministic(Seed::from_env_value("ecdsa-p384-jwk-d").unwrap());
        let key = fx.ecdsa("p384-d-len", EcdsaSpec::es384());
        let jwk = key.private_key_jwk().to_value();

        let d = jwk["d"].as_str().unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(d).expect("valid base64url");
        assert_eq!(decoded.len(), 48, "P-384 private scalar should be 48 bytes");
    }

    #[test]
    fn p256_private_jwk_d_length_is_32() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let fx = Factory::deterministic(Seed::from_env_value("ecdsa-p256-jwk-d").unwrap());
        let key = fx.ecdsa("p256-d-len", EcdsaSpec::es256());
        let jwk = key.private_key_jwk().to_value();

        let d = jwk["d"].as_str().unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(d).expect("valid base64url");
        assert_eq!(decoded.len(), 32, "P-256 private scalar should be 32 bytes");
    }

    #[test]
    fn p384_jwks_wraps_correctly() {
        let fx = Factory::deterministic(Seed::from_env_value("ecdsa-p384-jwks").unwrap());
        let key = fx.ecdsa("p384-jwks", EcdsaSpec::es384());
        let jwks = key.public_jwks().to_value();
        let keys = jwks["keys"].as_array().expect("keys array");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["crv"], "P-384");
        assert_eq!(keys[0]["alg"], "ES384");
    }

    #[test]
    fn p384_json_helpers_match_to_value() {
        let fx = Factory::deterministic(Seed::from_env_value("ecdsa-p384-json").unwrap());
        let key = fx.ecdsa("p384-json", EcdsaSpec::es384());

        assert_eq!(key.public_jwk_json(), key.public_jwk().to_value());
        assert_eq!(key.public_jwks_json(), key.public_jwks().to_value());
        assert_eq!(key.private_key_jwk_json(), key.private_key_jwk().to_value());
    }

    #[test]
    fn p384_kid_differs_from_p256_kid_for_same_label() {
        let fx = Factory::deterministic(Seed::from_env_value("ecdsa-kid-diff").unwrap());
        let k256 = fx.ecdsa("same-label", EcdsaSpec::es256());
        let k384 = fx.ecdsa("same-label", EcdsaSpec::es384());

        assert_ne!(k256.kid(), k384.kid());
    }
}
