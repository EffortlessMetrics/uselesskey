mod testutil;

use proptest::prelude::*;
use rsa::traits::PublicKeyParts;
use rsa::{pkcs8::DecodePrivateKey, pkcs8::DecodePublicKey};

use testutil::fx;
use uselesskey_core::negative::CorruptPem;
use uselesskey_core::{Factory, Seed};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

#[test]
#[should_panic(expected = "RSA bits too small")]
fn rsa_bits_too_small_panics() {
    let fx = fx();
    let _ = fx.rsa("issuer", RsaSpec::new(512));
}

#[test]
#[should_panic(expected = "custom RSA public exponent not supported")]
fn rsa_custom_exponent_panics() {
    let fx = fx();
    let spec = RsaSpec {
        bits: 2048,
        exponent: 3,
    };
    let _ = fx.rsa("issuer", spec);
}

#[test]
fn pkcs8_pem_is_parseable() {
    let fx = fx();
    let rsa = fx.rsa("issuer", RsaSpec::rs256());

    let parsed = rsa::RsaPrivateKey::from_pkcs8_pem(rsa.private_key_pkcs8_pem());
    assert!(parsed.is_ok());
}

#[test]
fn corrupt_pem_fails_to_parse() {
    let fx = fx();
    let rsa = fx.rsa("issuer", RsaSpec::rs256());

    let bad = rsa.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    let parsed = rsa::RsaPrivateKey::from_pkcs8_pem(&bad);
    assert!(parsed.is_err());
}

#[test]
fn mismatched_public_key_is_parseable_and_different() {
    let fx = fx();
    let rsa = fx.rsa("issuer", RsaSpec::rs256());

    let good_pub = rsa::RsaPublicKey::from_public_key_der(rsa.public_key_spki_der()).unwrap();
    let other_pub =
        rsa::RsaPublicKey::from_public_key_der(&rsa.mismatched_public_key_spki_der()).unwrap();

    // Extremely likely: modulus differs.
    assert_ne!(good_pub.n(), other_pub.n());
}

#[test]
fn pkcs8_der_truncated_shortens() {
    let fx = fx();
    let rsa = fx.rsa("issuer", RsaSpec::rs256());

    let truncated = rsa.private_key_pkcs8_der_truncated(12);
    assert_eq!(truncated.len(), 12);
}

#[test]
fn debug_includes_label_and_type() {
    let fx = fx();
    let rsa = fx.rsa("debug-label", RsaSpec::rs256());

    let dbg = format!("{:?}", rsa);
    assert!(dbg.contains("RsaKeyPair"));
    assert!(dbg.contains("debug-label"));
}

proptest! {
    #[test]
    fn deterministic_rsa_key_is_stable(seed in any::<[u8;32]>(), label in "[-_a-zA-Z0-9]{1,24}") {
        let fx = Factory::deterministic(Seed::new(seed));
        let rsa1 = fx.rsa(&label, RsaSpec::rs256());
        let rsa2 = fx.rsa(&label, RsaSpec::rs256());

        prop_assert_eq!(rsa1.private_key_pkcs8_der(), rsa2.private_key_pkcs8_der());
        prop_assert_eq!(rsa1.public_key_spki_der(), rsa2.public_key_spki_der());
    }

    // =========================================================================
    // All spec configurations produce valid parseable keys
    // =========================================================================

    /// All supported bit sizes produce valid parseable RSA keys.
    /// Note: We test only 2048 bits in property tests to keep runtime reasonable.
    /// The spec requires bits >= 1024 and exponent == 65537.
    #[test]
    fn all_spec_configs_produce_parseable_keys(
        seed in any::<[u8; 32]>(),
        label in "[a-zA-Z0-9]{1,16}"
    ) {
        let fx = Factory::deterministic(Seed::new(seed));

        // Test rs256 spec (2048 bits, 65537 exponent).
        let spec = RsaSpec::rs256();
        let rsa = fx.rsa(&label, spec);

        // Verify private key is parseable.
        let priv_result = rsa::RsaPrivateKey::from_pkcs8_der(rsa.private_key_pkcs8_der());
        prop_assert!(priv_result.is_ok(), "Private key DER should be parseable");

        let priv_pem_result = rsa::RsaPrivateKey::from_pkcs8_pem(rsa.private_key_pkcs8_pem());
        prop_assert!(priv_pem_result.is_ok(), "Private key PEM should be parseable");

        // Verify public key is parseable.
        let pub_result = rsa::RsaPublicKey::from_public_key_der(rsa.public_key_spki_der());
        prop_assert!(pub_result.is_ok(), "Public key DER should be parseable");

        let pub_pem_result = rsa::RsaPublicKey::from_public_key_pem(rsa.public_key_spki_pem());
        prop_assert!(pub_pem_result.is_ok(), "Public key PEM should be parseable");
    }

    // =========================================================================
    // Tempfile outputs match in-memory values
    // =========================================================================

    /// Tempfile outputs contain the same content as in-memory values.
    #[test]
    fn tempfile_outputs_match_in_memory(
        seed in any::<[u8; 32]>(),
        label in "[a-zA-Z0-9]{1,16}"
    ) {
        let fx = Factory::deterministic(Seed::new(seed));
        let rsa = fx.rsa(&label, RsaSpec::rs256());

        // Write to tempfiles.
        let priv_temp = rsa.write_private_key_pkcs8_pem()
            .expect("Failed to write private key tempfile");
        let pub_temp = rsa.write_public_key_spki_pem()
            .expect("Failed to write public key tempfile");

        // Read back and compare.
        let priv_content = std::fs::read_to_string(priv_temp.path())
            .expect("Failed to read private key tempfile");
        let pub_content = std::fs::read_to_string(pub_temp.path())
            .expect("Failed to read public key tempfile");

        prop_assert_eq!(
            priv_content.trim(),
            rsa.private_key_pkcs8_pem().trim(),
            "Private key tempfile should match in-memory value"
        );
        prop_assert_eq!(
            pub_content.trim(),
            rsa.public_key_spki_pem().trim(),
            "Public key tempfile should match in-memory value"
        );
    }

    // =========================================================================
    // kid determinism tests
    // =========================================================================

    /// kid is deterministic: same key produces same kid.
    #[test]
    #[cfg(feature = "jwk")]
    fn kid_is_deterministic(
        seed in any::<[u8; 32]>(),
        label in "[a-zA-Z0-9]{1,16}"
    ) {
        let fx = Factory::deterministic(Seed::new(seed));
        let rsa1 = fx.rsa(&label, RsaSpec::rs256());
        let rsa2 = fx.rsa(&label, RsaSpec::rs256());

        prop_assert_eq!(rsa1.kid(), rsa2.kid(), "Same key should produce same kid");
    }

    /// Different keys produce different kids.
    #[test]
    #[cfg(feature = "jwk")]
    fn different_keys_produce_different_kids(
        seed in any::<[u8; 32]>(),
        label1 in "[a-zA-Z0-9]{1,16}",
        label2 in "[a-zA-Z0-9]{1,16}"
    ) {
        prop_assume!(label1 != label2);

        let fx = Factory::deterministic(Seed::new(seed));
        let rsa1 = fx.rsa(&label1, RsaSpec::rs256());
        let rsa2 = fx.rsa(&label2, RsaSpec::rs256());

        prop_assert_ne!(
            rsa1.kid(), rsa2.kid(),
            "Different keys should produce different kids"
        );
    }
}

// =========================================================================
// JWK tests (feature-gated)
// =========================================================================

#[cfg(feature = "jwk")]
mod jwk_tests {
    use super::*;

    proptest! {
        /// JWK contains required fields: kty, alg, use, kid, n, e.
        #[test]
        fn jwk_contains_required_fields(
            seed in any::<[u8; 32]>(),
            label in "[a-zA-Z0-9]{1,16}"
        ) {
            let fx = Factory::deterministic(Seed::new(seed));
            let rsa = fx.rsa(&label, RsaSpec::rs256());

            let jwk = rsa.public_jwk().to_value();

            // Check all required fields exist and have correct types.
            prop_assert!(jwk.get("kty").is_some(), "JWK should have 'kty' field");
            prop_assert_eq!(jwk["kty"].as_str(), Some("RSA"), "kty should be 'RSA'");

            prop_assert!(jwk.get("alg").is_some(), "JWK should have 'alg' field");
            prop_assert_eq!(jwk["alg"].as_str(), Some("RS256"), "alg should be 'RS256'");

            prop_assert!(jwk.get("use").is_some(), "JWK should have 'use' field");
            prop_assert_eq!(jwk["use"].as_str(), Some("sig"), "use should be 'sig'");

            prop_assert!(jwk.get("kid").is_some(), "JWK should have 'kid' field");
            prop_assert!(jwk["kid"].is_string(), "kid should be a string");

            prop_assert!(jwk.get("n").is_some(), "JWK should have 'n' field");
            prop_assert!(jwk["n"].is_string(), "n should be a string");

            prop_assert!(jwk.get("e").is_some(), "JWK should have 'e' field");
            prop_assert!(jwk["e"].is_string(), "e should be a string");
        }

        /// JWKS wraps JWK correctly in a "keys" array.
        #[test]
        fn jwks_wraps_jwk_correctly(
            seed in any::<[u8; 32]>(),
            label in "[a-zA-Z0-9]{1,16}"
        ) {
            let fx = Factory::deterministic(Seed::new(seed));
            let rsa = fx.rsa(&label, RsaSpec::rs256());

            let jwks = rsa.public_jwks().to_value();
            let jwk = rsa.public_jwk().to_value();

            // JWKS should have a "keys" array.
            prop_assert!(jwks.get("keys").is_some(), "JWKS should have 'keys' field");
            prop_assert!(jwks["keys"].is_array(), "'keys' should be an array");

            // The array should contain exactly one key.
            let keys = jwks["keys"].as_array().unwrap();
            prop_assert_eq!(keys.len(), 1, "JWKS should contain exactly one key");

            // The key in JWKS should match the standalone JWK.
            prop_assert_eq!(&keys[0], &jwk, "JWKS key should match standalone JWK");
        }

        /// JWK n and e fields are valid base64url encoded.
        #[test]
        fn jwk_n_and_e_are_valid_base64url(
            seed in any::<[u8; 32]>(),
            label in "[a-zA-Z0-9]{1,16}"
        ) {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine as _;

            let fx = Factory::deterministic(Seed::new(seed));
            let rsa = fx.rsa(&label, RsaSpec::rs256());

            let jwk = rsa.public_jwk().to_value();

            let n_str = jwk["n"].as_str().unwrap();
            let e_str = jwk["e"].as_str().unwrap();

            // Verify they decode successfully.
            let n_decoded = URL_SAFE_NO_PAD.decode(n_str);
            prop_assert!(n_decoded.is_ok(), "n should be valid base64url: {:?}", n_decoded.err());

            let e_decoded = URL_SAFE_NO_PAD.decode(e_str);
            prop_assert!(e_decoded.is_ok(), "e should be valid base64url: {:?}", e_decoded.err());

            // n should decode to a substantial size (2048 bits = 256 bytes).
            let n_bytes = n_decoded.unwrap();
            prop_assert!(
                n_bytes.len() >= 250, // Allow slight variation due to leading zeros.
                "n should be ~256 bytes for 2048-bit key, got {} bytes",
                n_bytes.len()
            );
        }

        /// Private JWK contains required fields: d, p, q, dp, dq, qi.
        #[test]
        fn private_jwk_contains_required_fields(
            seed in any::<[u8; 32]>(),
            label in "[a-zA-Z0-9]{1,16}"
        ) {
            let fx = Factory::deterministic(Seed::new(seed));
            let rsa = fx.rsa(&label, RsaSpec::rs256());

            let jwk = rsa.private_key_jwk().to_value();

            for key in ["d", "p", "q", "dp", "dq", "qi"] {
                prop_assert!(jwk.get(key).is_some(), "JWK should have '{}' field", key);
                prop_assert!(jwk[key].is_string(), "{} should be a string", key);
            }
        }

        /// Private JWK fields are valid base64url encoded.
        #[test]
        fn private_jwk_fields_are_valid_base64url(
            seed in any::<[u8; 32]>(),
            label in "[a-zA-Z0-9]{1,16}"
        ) {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine as _;

            let fx = Factory::deterministic(Seed::new(seed));
            let rsa = fx.rsa(&label, RsaSpec::rs256());
            let jwk = rsa.private_key_jwk().to_value();

            for key in ["d", "p", "q", "dp", "dq", "qi"] {
                let val = jwk[key].as_str().unwrap();
                let decoded = URL_SAFE_NO_PAD.decode(val);
                prop_assert!(decoded.is_ok(), "{} should be valid base64url", key);
            }
        }
    }

    #[test]
    fn public_key_jwk_alias_matches_public_jwk() {
        let fx = Factory::deterministic(Seed::from_env_value("rsa-alias").unwrap());
        let rsa = fx.rsa("issuer", RsaSpec::rs256());
        assert_eq!(rsa.public_key_jwk().to_value(), rsa.public_jwk().to_value());
    }

    #[test]
    fn json_helpers_match_to_value() {
        let fx = Factory::deterministic(Seed::from_env_value("rsa-json").unwrap());
        let rsa = fx.rsa("issuer", RsaSpec::rs256());

        assert_eq!(rsa.public_jwk_json(), rsa.public_jwk().to_value());
        assert_eq!(rsa.public_jwks_json(), rsa.public_jwks().to_value());
        assert_eq!(rsa.private_key_jwk_json(), rsa.private_key_jwk().to_value());
    }
}
