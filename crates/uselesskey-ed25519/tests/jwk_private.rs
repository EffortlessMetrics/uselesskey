#[cfg(feature = "jwk")]
mod jwk_private_tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use uselesskey_core::{Factory, Seed};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

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
    fn json_helpers_match_to_value() {
        let fx = Factory::deterministic(Seed::from_env_value("ed25519-json").unwrap());
        let key = fx.ed25519("issuer", Ed25519Spec::new());
        assert_eq!(key.public_jwk_json(), key.public_jwk().to_value());
        assert_eq!(key.public_jwks_json(), key.public_jwks().to_value());
        assert_eq!(key.private_key_jwk_json(), key.private_key_jwk().to_value());
    }
}
