#[cfg(feature = "jwk")]
mod jwk_private_tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use uselesskey_core::{Factory, Seed};
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    fn decode_b64url(v: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(v).expect("valid base64url")
    }

    fn expected_kid(spki_der: &[u8]) -> String {
        let hash = blake3::hash(spki_der);
        URL_SAFE_NO_PAD.encode(&hash.as_bytes()[..12])
    }

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

    #[test]
    fn public_jwk_has_expected_fields() {
        let fx = Factory::deterministic(Seed::from_env_value("ecdsa-public-jwk").unwrap());

        let cases = [
            (EcdsaSpec::es256(), "ES256", "P-256"),
            (EcdsaSpec::es384(), "ES384", "P-384"),
        ];

        for (spec, alg, crv) in cases {
            let key = fx.ecdsa("issuer", spec);
            let jwk = key.public_jwk().to_value();

            assert_eq!(jwk["kty"], "EC");
            assert_eq!(jwk["alg"], alg);
            assert_eq!(jwk["crv"], crv);
            assert_eq!(jwk["use"], "sig");
            assert!(jwk["kid"].is_string());
            assert!(jwk["x"].is_string());
            assert!(jwk["y"].is_string());
        }
    }

    #[test]
    fn public_key_jwk_alias_matches_public_jwk() {
        let fx = Factory::deterministic(Seed::from_env_value("ecdsa-alias").unwrap());
        let key = fx.ecdsa("issuer", EcdsaSpec::es256());
        assert_eq!(key.public_key_jwk().to_value(), key.public_jwk().to_value());
    }

    #[test]
    fn jwks_wraps_public_jwk() {
        let fx = Factory::deterministic(Seed::from_env_value("ecdsa-jwks").unwrap());
        let key = fx.ecdsa("issuer", EcdsaSpec::es256());
        let jwks = key.public_jwks().to_value();
        let jwk = key.public_jwk().to_value();

        let keys = jwks["keys"].as_array().expect("keys array");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], jwk);
    }

    #[test]
    fn kid_is_deterministic() {
        let fx = Factory::deterministic(Seed::from_env_value("ecdsa-kid").unwrap());
        let k1 = fx.ecdsa("issuer", EcdsaSpec::es256());
        let k2 = fx.ecdsa("issuer", EcdsaSpec::es256());
        assert_eq!(k1.kid(), k2.kid());
    }

    #[test]
    fn kid_matches_public_key_hash_prefix() {
        let fx = Factory::deterministic(Seed::from_env_value("ecdsa-kid-shape").unwrap());

        for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
            let key = fx.ecdsa("issuer", spec);
            let kid = key.kid();

            assert_eq!(kid, expected_kid(key.public_key_spki_der()));

            let decoded = decode_b64url(&kid);
            assert_eq!(decoded.len(), 12);
        }
    }

    #[test]
    fn public_jwk_coordinates_match_public_key_material() {
        let fx = Factory::deterministic(Seed::from_env_value("ecdsa-public-jwk-bytes").unwrap());

        for (spec, coord_len) in [(EcdsaSpec::es256(), 32usize), (EcdsaSpec::es384(), 48usize)] {
            let key = fx.ecdsa("issuer", spec);
            let jwk = key.public_jwk().to_value();
            let x = decode_b64url(jwk["x"].as_str().expect("x"));
            let y = decode_b64url(jwk["y"].as_str().expect("y"));

            assert_eq!(x.len(), coord_len);
            assert_eq!(y.len(), coord_len);

            match spec {
                EcdsaSpec::Es256 => {
                    use p256::elliptic_curve::sec1::ToEncodedPoint as _;
                    use p256::pkcs8::DecodePublicKey as _;

                    let public = p256::PublicKey::from_public_key_der(key.public_key_spki_der())
                        .expect("P-256 SPKI should parse");
                    let encoded = public.to_encoded_point(false);
                    let bytes = encoded.as_bytes();

                    assert_eq!(x.as_slice(), &bytes[1..1 + coord_len]);
                    assert_eq!(y.as_slice(), &bytes[1 + coord_len..]);
                }
                EcdsaSpec::Es384 => {
                    use p384::elliptic_curve::sec1::ToEncodedPoint as _;
                    use p384::pkcs8::DecodePublicKey as _;

                    let public = p384::PublicKey::from_public_key_der(key.public_key_spki_der())
                        .expect("P-384 SPKI should parse");
                    let encoded = public.to_encoded_point(false);
                    let bytes = encoded.as_bytes();

                    assert_eq!(x.as_slice(), &bytes[1..1 + coord_len]);
                    assert_eq!(y.as_slice(), &bytes[1 + coord_len..]);
                }
            }
        }
    }

    #[test]
    fn private_jwk_matches_private_scalar_and_public_coordinates() {
        let fx = Factory::deterministic(Seed::from_env_value("ecdsa-private-jwk-bytes").unwrap());

        for (spec, coord_len) in [(EcdsaSpec::es256(), 32usize), (EcdsaSpec::es384(), 48usize)] {
            let key = fx.ecdsa("issuer", spec);
            let jwk = key.private_key_jwk().to_value();
            let x = decode_b64url(jwk["x"].as_str().expect("x"));
            let y = decode_b64url(jwk["y"].as_str().expect("y"));
            let d = decode_b64url(jwk["d"].as_str().expect("d"));

            assert_eq!(x.len(), coord_len);
            assert_eq!(y.len(), coord_len);
            assert_eq!(d.len(), coord_len);

            match spec {
                EcdsaSpec::Es256 => {
                    use p256::elliptic_curve::sec1::ToEncodedPoint as _;
                    use p256::pkcs8::DecodePrivateKey as _;

                    let secret = p256::SecretKey::from_pkcs8_der(key.private_key_pkcs8_der())
                        .expect("P-256 PKCS#8 should parse");
                    let public = secret.public_key();
                    let encoded = public.to_encoded_point(false);
                    let bytes = encoded.as_bytes();
                    let scalar = secret.to_bytes();

                    assert_eq!(x.as_slice(), &bytes[1..1 + coord_len]);
                    assert_eq!(y.as_slice(), &bytes[1 + coord_len..]);
                    assert_eq!(d.as_slice(), &scalar[..]);
                }
                EcdsaSpec::Es384 => {
                    use p384::elliptic_curve::sec1::ToEncodedPoint as _;
                    use p384::pkcs8::DecodePrivateKey as _;

                    let secret = p384::SecretKey::from_pkcs8_der(key.private_key_pkcs8_der())
                        .expect("P-384 PKCS#8 should parse");
                    let public = secret.public_key();
                    let encoded = public.to_encoded_point(false);
                    let bytes = encoded.as_bytes();
                    let scalar = secret.to_bytes();

                    assert_eq!(x.as_slice(), &bytes[1..1 + coord_len]);
                    assert_eq!(y.as_slice(), &bytes[1 + coord_len..]);
                    assert_eq!(d.as_slice(), &scalar[..]);
                }
            }
        }
    }

    #[test]
    fn json_helpers_match_to_value() {
        let fx = Factory::deterministic(Seed::from_env_value("ecdsa-json").unwrap());
        let key = fx.ecdsa("issuer", EcdsaSpec::es384());
        assert_eq!(key.public_jwk_json(), key.public_jwk().to_value());
        assert_eq!(key.public_jwks_json(), key.public_jwks().to_value());
        assert_eq!(key.private_key_jwk_json(), key.private_key_jwk().to_value());
    }
}
