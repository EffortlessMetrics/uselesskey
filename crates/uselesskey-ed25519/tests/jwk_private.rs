#[cfg(feature = "jwk")]
mod jwk_private_tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use uselesskey_core::{Factory, Seed};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    fn decode_b64url(v: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(v).expect("valid base64url")
    }

    fn expected_kid(spki_der: &[u8]) -> String {
        uselesskey_core_kid::kid_from_bytes(spki_der)
    }

    #[test]
    fn private_jwk_has_d() {
        let fx = Factory::deterministic(Seed::from_env_value("ed25519-jwk").unwrap());
        let key = fx.ed25519("issuer", Ed25519Spec::new());
        let jwk = key.private_key_jwk().to_value();

        assert!(jwk["d"].is_string(), "d should be present");
        assert!(
            !jwk["d"].as_str().unwrap().is_empty(),
            "d should not be empty"
        );
    }

    #[test]
    fn private_jwk_d_is_base64url() {
        let fx = Factory::deterministic(Seed::from_env_value("ed25519-jwk").unwrap());
        let key = fx.ed25519("issuer", Ed25519Spec::new());
        let jwk = key.private_key_jwk().to_value();

        let d = jwk["d"].as_str().unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(d);
        assert!(decoded.is_ok(), "d should be valid base64url");
    }

    #[test]
    fn public_jwk_has_expected_fields() {
        let fx = Factory::deterministic(Seed::from_env_value("ed25519-public-jwk").unwrap());
        let key = fx.ed25519("issuer", Ed25519Spec::new());
        let jwk = key.public_jwk().to_value();

        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["alg"], "EdDSA");
        assert_eq!(jwk["use"], "sig");
        assert!(jwk["kid"].is_string());
        assert!(jwk["x"].is_string());
    }

    #[test]
    fn public_key_jwk_alias_matches_public_jwk() {
        let fx = Factory::deterministic(Seed::from_env_value("ed25519-alias").unwrap());
        let key = fx.ed25519("issuer", Ed25519Spec::new());
        assert_eq!(key.public_key_jwk().to_value(), key.public_jwk().to_value());
    }

    #[test]
    fn jwks_wraps_public_jwk() {
        let fx = Factory::deterministic(Seed::from_env_value("ed25519-jwks").unwrap());
        let key = fx.ed25519("issuer", Ed25519Spec::new());
        let jwks = key.public_jwks().to_value();
        let jwk = key.public_jwk().to_value();

        let keys = jwks["keys"].as_array().expect("keys array");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], jwk);
    }

    #[test]
    fn kid_is_deterministic() {
        let fx = Factory::deterministic(Seed::from_env_value("ed25519-kid").unwrap());
        let k1 = fx.ed25519("issuer", Ed25519Spec::new());
        let k2 = fx.ed25519("issuer", Ed25519Spec::new());
        assert_eq!(k1.kid(), k2.kid());
    }

    #[test]
    fn kid_matches_public_key_hash_prefix() {
        let fx = Factory::deterministic(Seed::from_env_value("ed25519-kid-shape").unwrap());
        let key = fx.ed25519("issuer", Ed25519Spec::new());
        let kid = key.kid();

        assert_eq!(kid, expected_kid(key.public_key_spki_der()));
        assert_eq!(decode_b64url(&kid).len(), 12);
    }

    #[test]
    fn public_jwk_x_matches_spki_public_key_bytes() {
        use ed25519_dalek::pkcs8::DecodePublicKey as _;

        let fx = Factory::deterministic(Seed::from_env_value("ed25519-jwk-public-bytes").unwrap());
        let key = fx.ed25519("issuer", Ed25519Spec::new());
        let jwk = key.public_jwk().to_value();

        let x = decode_b64url(jwk["x"].as_str().expect("x"));
        assert_eq!(x.len(), 32);

        let public = ed25519_dalek::VerifyingKey::from_public_key_der(key.public_key_spki_der())
            .expect("SPKI should parse");
        assert_eq!(x.as_slice(), public.as_bytes());
    }

    #[test]
    fn private_jwk_d_matches_pkcs8_secret_bytes() {
        use ed25519_dalek::pkcs8::DecodePrivateKey as _;

        let fx = Factory::deterministic(Seed::from_env_value("ed25519-jwk-private-bytes").unwrap());
        let key = fx.ed25519("issuer", Ed25519Spec::new());
        let jwk = key.private_key_jwk().to_value();

        let x = decode_b64url(jwk["x"].as_str().expect("x"));
        let d = decode_b64url(jwk["d"].as_str().expect("d"));
        assert_eq!(x.len(), 32);
        assert_eq!(d.len(), 32);

        let private = ed25519_dalek::SigningKey::from_pkcs8_der(key.private_key_pkcs8_der())
            .expect("PKCS#8 should parse");
        assert_eq!(x.as_slice(), private.verifying_key().as_bytes());
        assert_eq!(d.as_slice(), private.to_bytes().as_ref());
    }

    #[test]
    fn json_helpers_match_to_value() {
        let fx = Factory::deterministic(Seed::from_env_value("ed25519-json").unwrap());
        let key = fx.ed25519("issuer", Ed25519Spec::new());
        assert_eq!(key.public_jwk_json(), key.public_jwk().to_value());
        assert_eq!(key.public_jwks_json(), key.public_jwks().to_value());
        assert_eq!(key.private_key_jwk_json(), key.private_key_jwk().to_value());
    }
}
