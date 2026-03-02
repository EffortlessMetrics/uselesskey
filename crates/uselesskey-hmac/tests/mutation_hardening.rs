//! Mutation-hardening tests for uselesskey-hmac JWK methods.
//!
//! These tests target surviving mutants in `HmacSecret::kid()`, `jwk()`, and `jwks()`.
//! Each test asserts concrete field values so that replacing the return with
//! `Default::default()`, `String::new()`, or `"xyzzy"` will fail.

#[allow(dead_code)]
mod testutil;

#[cfg(feature = "jwk")]
mod jwk_mutation_hardening {
    use crate::testutil::fx;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    // ── kid() must return non-empty, non-trivial string ──────────────────

    #[test]
    fn kid_is_non_empty_and_non_trivial() {
        let fx = fx();
        for spec in [HmacSpec::hs256(), HmacSpec::hs384(), HmacSpec::hs512()] {
            let secret = fx.hmac("kid-mut", spec);
            let kid = secret.kid();
            assert!(!kid.is_empty(), "kid must not be empty for {spec:?}");
            assert_ne!(kid, "xyzzy", "kid must not be trivial for {spec:?}");
        }
    }

    #[test]
    fn kid_is_deterministic() {
        let fx = fx();
        let s1 = fx.hmac("kid-det", HmacSpec::hs256());
        let s2 = fx.hmac("kid-det", HmacSpec::hs256());
        assert_eq!(s1.kid(), s2.kid());
    }

    // ── jwk() must return well-formed octet JWK ─────────────────────────

    #[test]
    fn jwk_has_expected_fields_hs256() {
        let fx = fx();
        let secret = fx.hmac("jwk-mut-256", HmacSpec::hs256());
        let jwk = secret.jwk().to_value();

        assert_eq!(jwk["kty"], "oct");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["alg"], "HS256");
        assert!(jwk["kid"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(jwk["k"].as_str().is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn jwk_has_expected_fields_hs384() {
        let fx = fx();
        let secret = fx.hmac("jwk-mut-384", HmacSpec::hs384());
        let jwk = secret.jwk().to_value();

        assert_eq!(jwk["kty"], "oct");
        assert_eq!(jwk["alg"], "HS384");
        assert!(jwk["k"].as_str().is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn jwk_has_expected_fields_hs512() {
        let fx = fx();
        let secret = fx.hmac("jwk-mut-512", HmacSpec::hs512());
        let jwk = secret.jwk().to_value();

        assert_eq!(jwk["kty"], "oct");
        assert_eq!(jwk["alg"], "HS512");
        assert!(jwk["k"].as_str().is_some_and(|s| !s.is_empty()));
    }

    // ── jwks() must wrap a single key ───────────────────────────────────

    #[test]
    fn jwks_contains_one_key_with_correct_alg() {
        let fx = fx();
        for (spec, expected_alg) in [
            (HmacSpec::hs256(), "HS256"),
            (HmacSpec::hs384(), "HS384"),
            (HmacSpec::hs512(), "HS512"),
        ] {
            let secret = fx.hmac("jwks-mut", spec);
            let jwks = secret.jwks().to_value();
            let keys = jwks["keys"].as_array().expect("keys array");
            assert_eq!(keys.len(), 1, "jwks should have one key for {spec:?}");
            assert_eq!(
                keys[0]["alg"], expected_alg,
                "wrong alg in jwks for {spec:?}"
            );
        }
    }

    // ── kid embedded in jwk matches standalone kid() ────────────────────

    #[test]
    fn jwk_kid_matches_standalone_kid() {
        let fx = fx();
        let secret = fx.hmac("kid-embed", HmacSpec::hs256());
        let jwk = secret.jwk().to_value();
        assert_eq!(jwk["kid"].as_str().unwrap(), secret.kid());
    }
}
