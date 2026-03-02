//! Mutation-hardening tests for uselesskey-ed25519 JWK methods.
//!
//! Targets surviving mutants in `Ed25519KeyPair::kid()`, `public_key_jwk()`,
//! `public_jwk()`, `private_key_jwk()`, `public_jwks()`, and the JSON helpers.

#[allow(dead_code)]
mod testutil;

#[cfg(feature = "jwk")]
mod jwk_mutation_hardening {
    use crate::testutil::fx;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    // ── kid() must return non-empty, non-trivial string ──────────────────

    #[test]
    fn kid_is_non_empty_and_non_trivial() {
        let fx = fx();
        let kp = fx.ed25519("kid-mut", Ed25519Spec::new());
        let kid = kp.kid();
        assert!(!kid.is_empty(), "kid must not be empty");
        assert_ne!(kid, "xyzzy", "kid must not be trivial placeholder");
    }

    #[test]
    fn kid_is_deterministic() {
        let fx = fx();
        let k1 = fx.ed25519("kid-det", Ed25519Spec::new());
        let k2 = fx.ed25519("kid-det", Ed25519Spec::new());
        assert_eq!(k1.kid(), k2.kid());
    }

    // ── public_key_jwk() alias must match public_jwk() ─────────────────

    #[test]
    fn public_key_jwk_matches_public_jwk() {
        let fx = fx();
        let kp = fx.ed25519("alias-mut", Ed25519Spec::new());
        assert_eq!(kp.public_key_jwk().to_value(), kp.public_jwk().to_value());
    }

    // ── public_jwk() must return well-formed OKP JWK ────────────────────

    #[test]
    fn public_jwk_has_expected_fields() {
        let fx = fx();
        let kp = fx.ed25519("pub-jwk-mut", Ed25519Spec::new());
        let jwk = kp.public_jwk().to_value();

        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["alg"], "EdDSA");
        assert!(jwk["kid"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(jwk["x"].as_str().is_some_and(|s| !s.is_empty()));
        // Public JWK must NOT have "d"
        assert!(jwk.get("d").is_none(), "public JWK must not contain d");
    }

    #[test]
    fn public_jwk_x_decodes_to_32_bytes() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let fx = fx();
        let kp = fx.ed25519("pub-x-len", Ed25519Spec::new());
        let jwk = kp.public_jwk().to_value();
        let x = URL_SAFE_NO_PAD
            .decode(jwk["x"].as_str().unwrap())
            .expect("valid base64url");
        assert_eq!(x.len(), 32, "Ed25519 public key x must be 32 bytes");
    }

    // ── private_key_jwk() must return well-formed OKP private JWK ───────

    #[test]
    fn private_key_jwk_has_expected_fields() {
        let fx = fx();
        let kp = fx.ed25519("priv-jwk-mut", Ed25519Spec::new());
        let jwk = kp.private_key_jwk().to_value();

        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["alg"], "EdDSA");
        assert!(jwk["kid"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(jwk["x"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(jwk["d"].as_str().is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn private_key_jwk_d_decodes_to_32_bytes() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let fx = fx();
        let kp = fx.ed25519("priv-d-len", Ed25519Spec::new());
        let jwk = kp.private_key_jwk().to_value();
        let d = URL_SAFE_NO_PAD
            .decode(jwk["d"].as_str().unwrap())
            .expect("valid base64url");
        assert_eq!(d.len(), 32, "Ed25519 private key d must be 32 bytes");
    }

    // ── public_jwks() must wrap a single public key ─────────────────────

    #[test]
    fn public_jwks_contains_one_okp_key() {
        let fx = fx();
        let kp = fx.ed25519("jwks-mut", Ed25519Spec::new());
        let jwks = kp.public_jwks().to_value();
        let keys = jwks["keys"].as_array().expect("keys array");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "OKP");
        assert_eq!(keys[0]["crv"], "Ed25519");
    }

    // ── JSON helpers must return non-null, non-empty objects ─────────────

    #[test]
    fn public_jwk_json_has_kty() {
        let fx = fx();
        let kp = fx.ed25519("pub-json-mut", Ed25519Spec::new());
        let val = kp.public_jwk_json();
        assert_eq!(val["kty"], "OKP");
    }

    #[test]
    fn public_jwks_json_has_keys_array() {
        let fx = fx();
        let kp = fx.ed25519("jwks-json-mut", Ed25519Spec::new());
        let val = kp.public_jwks_json();
        assert!(val["keys"].as_array().is_some_and(|a| !a.is_empty()));
    }

    #[test]
    fn private_key_jwk_json_has_d_field() {
        let fx = fx();
        let kp = fx.ed25519("priv-json-mut", Ed25519Spec::new());
        let val = kp.private_key_jwk_json();
        assert!(val["d"].as_str().is_some_and(|s| !s.is_empty()));
    }

    // ── kid embedded in JWKs matches standalone kid() ───────────────────

    #[test]
    fn jwk_kid_matches_standalone_kid() {
        let fx = fx();
        let kp = fx.ed25519("kid-embed", Ed25519Spec::new());
        let jwk = kp.public_jwk().to_value();
        assert_eq!(jwk["kid"].as_str().unwrap(), kp.kid());
    }
}
