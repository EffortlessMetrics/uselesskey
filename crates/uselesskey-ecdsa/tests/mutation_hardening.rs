//! Mutation-hardening tests for uselesskey-ecdsa JWK methods.
//!
//! Targets surviving mutants in `EcdsaKeyPair::kid()`, `public_key_jwk()`,
//! `public_jwk()`, `private_key_jwk()`, `public_jwks()`, JSON helpers,
//! and arithmetic mutations in EC coordinate slicing.

#[allow(dead_code)]
mod testutil;

#[cfg(feature = "jwk")]
mod jwk_mutation_hardening {
    use crate::testutil::fx;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    // ── kid() must return non-empty, non-trivial string ──────────────────

    #[test]
    fn kid_is_non_empty_and_non_trivial_es256() {
        let fx = fx();
        let kp = fx.ecdsa("kid-mut-256", EcdsaSpec::es256());
        let kid = kp.kid();
        assert!(!kid.is_empty(), "kid must not be empty");
        assert_ne!(kid, "xyzzy", "kid must not be trivial placeholder");
    }

    #[test]
    fn kid_is_non_empty_and_non_trivial_es384() {
        let fx = fx();
        let kp = fx.ecdsa("kid-mut-384", EcdsaSpec::es384());
        let kid = kp.kid();
        assert!(!kid.is_empty());
        assert_ne!(kid, "xyzzy");
    }

    #[test]
    fn kid_is_deterministic() {
        let fx = fx();
        let k1 = fx.ecdsa("kid-det", EcdsaSpec::es256());
        let k2 = fx.ecdsa("kid-det", EcdsaSpec::es256());
        assert_eq!(k1.kid(), k2.kid());
    }

    // ── public_key_jwk() alias must match public_jwk() ─────────────────

    #[test]
    fn public_key_jwk_matches_public_jwk() {
        let fx = fx();
        for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
            let kp = fx.ecdsa("alias-mut", spec);
            assert_eq!(
                kp.public_key_jwk().to_value(),
                kp.public_jwk().to_value(),
                "alias must match for {spec:?}"
            );
        }
    }

    // ── public_jwk() must return well-formed EC JWK with correct coords ─

    #[test]
    fn public_jwk_has_expected_fields_es256() {
        let fx = fx();
        let kp = fx.ecdsa("pub-jwk-256", EcdsaSpec::es256());
        let jwk = kp.public_jwk().to_value();

        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["alg"], "ES256");
        assert!(jwk["kid"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(jwk["x"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(jwk["y"].as_str().is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn public_jwk_has_expected_fields_es384() {
        let fx = fx();
        let kp = fx.ecdsa("pub-jwk-384", EcdsaSpec::es384());
        let jwk = kp.public_jwk().to_value();

        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-384");
        assert_eq!(jwk["alg"], "ES384");
        assert!(jwk["x"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(jwk["y"].as_str().is_some_and(|s| !s.is_empty()));
    }

    // ── Coordinate lengths must match curve size (kills arithmetic mutants) ─

    #[test]
    fn public_jwk_x_y_decode_to_32_bytes_for_p256() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let fx = fx();
        let kp = fx.ecdsa("coord-p256", EcdsaSpec::es256());
        let jwk = kp.public_jwk().to_value();
        let x = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap();
        let y = URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap();
        assert_eq!(x.len(), 32, "P-256 x coordinate must be 32 bytes");
        assert_eq!(y.len(), 32, "P-256 y coordinate must be 32 bytes");
    }

    #[test]
    fn public_jwk_x_y_decode_to_48_bytes_for_p384() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let fx = fx();
        let kp = fx.ecdsa("coord-p384", EcdsaSpec::es384());
        let jwk = kp.public_jwk().to_value();
        let x = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap();
        let y = URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap();
        assert_eq!(x.len(), 48, "P-384 x coordinate must be 48 bytes");
        assert_eq!(y.len(), 48, "P-384 y coordinate must be 48 bytes");
    }

    // ── x and y must differ (catches swapped/duplicated slicing) ────────

    #[test]
    fn public_jwk_x_and_y_differ() {
        let fx = fx();
        for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
            let kp = fx.ecdsa("xy-diff", spec);
            let jwk = kp.public_jwk().to_value();
            assert_ne!(
                jwk["x"].as_str().unwrap(),
                jwk["y"].as_str().unwrap(),
                "x and y must differ for {spec:?}"
            );
        }
    }

    // ── private_key_jwk() must have d field with correct coords ─────────

    #[test]
    fn private_key_jwk_has_d_and_coords_es256() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let fx = fx();
        let kp = fx.ecdsa("priv-jwk-256", EcdsaSpec::es256());
        let jwk = kp.private_key_jwk().to_value();

        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["alg"], "ES256");
        assert!(jwk["d"].as_str().is_some_and(|s| !s.is_empty()));

        let x = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap();
        let y = URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap();
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
        assert_ne!(
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap(),
            "private JWK x and y must differ"
        );
    }

    #[test]
    fn private_key_jwk_has_d_and_coords_es384() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let fx = fx();
        let kp = fx.ecdsa("priv-jwk-384", EcdsaSpec::es384());
        let jwk = kp.private_key_jwk().to_value();

        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-384");
        assert_eq!(jwk["alg"], "ES384");

        let x = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap();
        let y = URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap();
        let d = URL_SAFE_NO_PAD.decode(jwk["d"].as_str().unwrap()).unwrap();
        assert_eq!(x.len(), 48);
        assert_eq!(y.len(), 48);
        assert_eq!(d.len(), 48);
        assert_ne!(
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap(),
            "private JWK x and y must differ"
        );
    }

    // ── public_jwks() must wrap a single public key ─────────────────────

    #[test]
    fn public_jwks_contains_one_ec_key() {
        let fx = fx();
        for (spec, crv) in [(EcdsaSpec::es256(), "P-256"), (EcdsaSpec::es384(), "P-384")] {
            let kp = fx.ecdsa("jwks-mut", spec);
            let jwks = kp.public_jwks().to_value();
            let keys = jwks["keys"].as_array().expect("keys array");
            assert_eq!(keys.len(), 1, "jwks must have one key for {spec:?}");
            assert_eq!(keys[0]["kty"], "EC");
            assert_eq!(keys[0]["crv"], crv);
        }
    }

    // ── JSON helpers must return non-null, non-empty objects ─────────────

    #[test]
    fn public_jwk_json_has_kty() {
        let fx = fx();
        for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
            let kp = fx.ecdsa("pub-json", spec);
            let val = kp.public_jwk_json();
            assert_eq!(
                val["kty"], "EC",
                "public_jwk_json must have kty for {spec:?}"
            );
        }
    }

    #[test]
    fn public_jwks_json_has_keys_array() {
        let fx = fx();
        for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
            let kp = fx.ecdsa("jwks-json", spec);
            let val = kp.public_jwks_json();
            assert!(
                val["keys"].as_array().is_some_and(|a| !a.is_empty()),
                "public_jwks_json must have keys for {spec:?}"
            );
        }
    }

    #[test]
    fn private_key_jwk_json_has_d_field() {
        let fx = fx();
        for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
            let kp = fx.ecdsa("priv-json", spec);
            let val = kp.private_key_jwk_json();
            assert!(
                val["d"].as_str().is_some_and(|s| !s.is_empty()),
                "private_key_jwk_json must have d for {spec:?}"
            );
        }
    }

    // ── kid embedded in JWKs matches standalone kid() ───────────────────

    #[test]
    fn jwk_kid_matches_standalone_kid() {
        let fx = fx();
        for spec in [EcdsaSpec::es256(), EcdsaSpec::es384()] {
            let kp = fx.ecdsa("kid-embed", spec);
            let jwk = kp.public_jwk().to_value();
            assert_eq!(
                jwk["kid"].as_str().unwrap(),
                kp.kid(),
                "JWK kid must match standalone kid for {spec:?}"
            );
        }
    }
}
