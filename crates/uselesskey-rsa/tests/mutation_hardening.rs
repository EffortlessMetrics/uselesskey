//! Mutation-hardening tests for uselesskey-rsa JWK methods.
//!
//! Targets surviving mutants in `RsaKeyPair::jwk_alg()`, `kid()`,
//! `public_key_jwk()`, `public_jwk()`, `private_key_jwk()`, `public_jwks()`,
//! and the JSON helpers.

#[allow(dead_code)]
mod testutil;

#[cfg(feature = "jwk")]
mod jwk_mutation_hardening {
    use crate::testutil::fx;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    // ── jwk_alg() match arms: each bit size must map correctly ──────────

    #[test]
    fn jwk_alg_rs256_for_2048() {
        let fx = fx();
        let kp = fx.rsa("alg-2048", RsaSpec::new(2048));
        let jwk = kp.public_jwk().to_value();
        assert_eq!(jwk["alg"], "RS256", "2048-bit RSA must use RS256");
    }

    #[test]
    fn jwk_alg_rs384_for_3072() {
        let fx = fx();
        let kp = fx.rsa("alg-3072", RsaSpec::new(3072));
        let jwk = kp.public_jwk().to_value();
        assert_eq!(jwk["alg"], "RS384", "3072-bit RSA must use RS384");
    }

    #[test]
    fn jwk_alg_rs512_for_4096() {
        let fx = fx();
        let kp = fx.rsa("alg-4096", RsaSpec::new(4096));
        let jwk = kp.public_jwk().to_value();
        assert_eq!(jwk["alg"], "RS512", "4096-bit RSA must use RS512");
    }

    #[test]
    fn jwk_alg_values_are_all_distinct() {
        let fx = fx();
        let alg_2048 = fx
            .rsa("alg-dist-2048", RsaSpec::new(2048))
            .public_jwk()
            .to_value()["alg"]
            .as_str()
            .unwrap()
            .to_string();
        let alg_3072 = fx
            .rsa("alg-dist-3072", RsaSpec::new(3072))
            .public_jwk()
            .to_value()["alg"]
            .as_str()
            .unwrap()
            .to_string();
        let alg_4096 = fx
            .rsa("alg-dist-4096", RsaSpec::new(4096))
            .public_jwk()
            .to_value()["alg"]
            .as_str()
            .unwrap()
            .to_string();

        assert_ne!(alg_2048, alg_3072, "2048 and 3072 alg must differ");
        assert_ne!(alg_2048, alg_4096, "2048 and 4096 alg must differ");
        assert_ne!(alg_3072, alg_4096, "3072 and 4096 alg must differ");
    }

    // ── kid() must return non-empty, non-trivial string ─────────────────

    #[test]
    fn kid_is_non_empty_and_non_trivial() {
        let fx = fx();
        let kp = fx.rsa("kid-mut", RsaSpec::rs256());
        let kid = kp.kid();
        assert!(!kid.is_empty(), "kid must not be empty");
        assert_ne!(kid, "xyzzy", "kid must not be trivial placeholder");
    }

    #[test]
    fn kid_is_deterministic() {
        let fx = fx();
        let k1 = fx.rsa("kid-det", RsaSpec::rs256());
        let k2 = fx.rsa("kid-det", RsaSpec::rs256());
        assert_eq!(k1.kid(), k2.kid());
    }

    // ── public_key_jwk() alias must match public_jwk() ─────────────────

    #[test]
    fn public_key_jwk_matches_public_jwk() {
        let fx = fx();
        let kp = fx.rsa("alias-mut", RsaSpec::rs256());
        assert_eq!(kp.public_key_jwk().to_value(), kp.public_jwk().to_value());
    }

    // ── public_jwk() must return well-formed RSA JWK ────────────────────

    #[test]
    fn public_jwk_has_expected_fields() {
        let fx = fx();
        let kp = fx.rsa("pub-jwk-mut", RsaSpec::rs256());
        let jwk = kp.public_jwk().to_value();

        assert_eq!(jwk["kty"], "RSA");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["alg"], "RS256");
        assert!(jwk["kid"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(jwk["n"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(jwk["e"].as_str().is_some_and(|s| !s.is_empty()));
    }

    // ── private_key_jwk() must have all RSA CRT fields ──────────────────

    #[test]
    fn private_key_jwk_has_all_crt_fields() {
        let fx = fx();
        let kp = fx.rsa("priv-jwk-mut", RsaSpec::rs256());
        let jwk = kp.private_key_jwk().to_value();

        assert_eq!(jwk["kty"], "RSA");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["alg"], "RS256");
        for field in ["n", "e", "d", "p", "q", "dp", "dq", "qi"] {
            assert!(
                jwk[field].as_str().is_some_and(|s| !s.is_empty()),
                "Missing or empty field: {field}"
            );
        }
    }

    // ── public_jwks() must wrap a single public key ─────────────────────

    #[test]
    fn public_jwks_contains_one_rsa_key() {
        let fx = fx();
        let kp = fx.rsa("jwks-mut", RsaSpec::rs256());
        let jwks = kp.public_jwks().to_value();
        let keys = jwks["keys"].as_array().expect("keys array");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "RSA");
    }

    // ── JSON helpers must return non-null, non-empty objects ─────────────

    #[test]
    fn public_jwk_json_has_kty() {
        let fx = fx();
        let kp = fx.rsa("pub-json-mut", RsaSpec::rs256());
        let val = kp.public_jwk_json();
        assert_eq!(val["kty"], "RSA");
    }

    #[test]
    fn public_jwks_json_has_keys_array() {
        let fx = fx();
        let kp = fx.rsa("jwks-json-mut", RsaSpec::rs256());
        let val = kp.public_jwks_json();
        assert!(val["keys"].as_array().is_some_and(|a| !a.is_empty()));
    }

    #[test]
    fn private_key_jwk_json_has_d_field() {
        let fx = fx();
        let kp = fx.rsa("priv-json-mut", RsaSpec::rs256());
        let val = kp.private_key_jwk_json();
        assert!(val["d"].as_str().is_some_and(|s| !s.is_empty()));
    }

    // ── kid embedded in JWKs matches standalone kid() ───────────────────

    #[test]
    fn jwk_kid_matches_standalone_kid() {
        let fx = fx();
        let kp = fx.rsa("kid-embed", RsaSpec::rs256());
        let jwk = kp.public_jwk().to_value();
        assert_eq!(jwk["kid"].as_str().unwrap(), kp.kid());
    }
}
