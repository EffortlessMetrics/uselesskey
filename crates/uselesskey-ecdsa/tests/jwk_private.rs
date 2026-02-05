#[cfg(feature = "jwk")]
mod jwk_private_tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use uselesskey_core::{Factory, Seed};
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn private_jwk_has_d() {
        let fx = Factory::deterministic(Seed::from_env_value("ecdsa-jwk").unwrap());
        let key = fx.ecdsa("issuer", EcdsaSpec::es256());
        let jwk = key.private_key_jwk().to_value();

        assert!(jwk["d"].is_string(), "d should be present");
        assert!(
            !jwk["d"].as_str().unwrap().is_empty(),
            "d should not be empty"
        );
    }

    #[test]
    fn private_jwk_d_is_base64url() {
        let fx = Factory::deterministic(Seed::from_env_value("ecdsa-jwk").unwrap());
        let key = fx.ecdsa("issuer", EcdsaSpec::es384());
        let jwk = key.private_key_jwk().to_value();

        let d = jwk["d"].as_str().unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(d);
        assert!(decoded.is_ok(), "d should be valid base64url");
    }
}
