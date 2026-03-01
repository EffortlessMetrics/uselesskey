use proptest::prelude::*;
use uselesskey_core_jwk_shape::{
    AnyJwk, EcPublicJwk, Jwks, OctJwk, OkpPublicJwk, PrivateJwk, PublicJwk, RsaPublicJwk,
};

fn arb_rsa_public(kid: String, n: String) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid,
        n,
        e: "AQAB".to_string(),
    })
}

fn arb_ec_public(kid: String, x: String) -> PublicJwk {
    PublicJwk::Ec(EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid,
        x,
        y: "y-coord".to_string(),
    })
}

fn arb_okp_public(kid: String, x: String) -> PublicJwk {
    PublicJwk::Okp(OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid,
        x,
    })
}

fn arb_oct_private(kid: String, k: String) -> PrivateJwk {
    PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid,
        k,
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// to_value produces valid JSON with the expected kid field.
    #[test]
    fn public_jwk_to_value_contains_kid(
        kid in "[a-zA-Z0-9._-]{1,24}",
        n in "[A-Za-z0-9]{1,32}",
    ) {
        let jwk = arb_rsa_public(kid.clone(), n);
        let val = jwk.to_value();
        prop_assert_eq!(val["kid"].as_str().unwrap(), kid.as_str());
        prop_assert_eq!(val["kty"].as_str().unwrap(), "RSA");
    }

    /// Display and to_value produce equivalent JSON.
    #[test]
    fn display_equals_to_value(
        kid in "[a-zA-Z0-9._-]{1,24}",
        n in "[A-Za-z0-9]{1,32}",
    ) {
        let jwk = arb_rsa_public(kid, n);
        let from_display: serde_json::Value = serde_json::from_str(&jwk.to_string())
            .expect("Display should produce valid JSON");
        let from_value = jwk.to_value();
        prop_assert_eq!(from_display, from_value);
    }

    /// kid() accessor returns the correct value for all PublicJwk variants.
    #[test]
    fn public_jwk_kid_accessor(
        kid in "[a-zA-Z0-9._-]{1,24}",
        variant in 0u8..3,
    ) {
        let jwk = match variant {
            0 => arb_rsa_public(kid.clone(), "n".into()),
            1 => arb_ec_public(kid.clone(), "x".into()),
            _ => arb_okp_public(kid.clone(), "x".into()),
        };
        prop_assert_eq!(jwk.kid(), kid.as_str());
    }

    /// kid() accessor returns the correct value for PrivateJwk::Oct.
    #[test]
    fn private_oct_kid_accessor(
        kid in "[a-zA-Z0-9._-]{1,24}",
        k in "[A-Za-z0-9]{1,32}",
    ) {
        let jwk = arb_oct_private(kid.clone(), k);
        prop_assert_eq!(jwk.kid(), kid.as_str());
    }

    /// AnyJwk::from conversions preserve kid.
    #[test]
    fn any_jwk_from_preserves_kid(
        kid in "[a-zA-Z0-9._-]{1,24}",
    ) {
        let pub_jwk = arb_rsa_public(kid.clone(), "n".into());
        let any = AnyJwk::from(pub_jwk);
        prop_assert_eq!(any.kid(), kid.as_str());
    }

    /// Jwks serialization always produces a JSON object with "keys" array.
    #[test]
    fn jwks_has_keys_array(
        kid_a in "[a-zA-Z0-9._-]{1,16}",
        kid_b in "[a-zA-Z0-9._-]{1,16}",
    ) {
        let jwks = Jwks {
            keys: vec![
                AnyJwk::from(arb_rsa_public(kid_a, "n1".into())),
                AnyJwk::from(arb_okp_public(kid_b, "x1".into())),
            ],
        };
        let val = jwks.to_value();
        let keys = val["keys"].as_array().expect("keys should be an array");
        prop_assert_eq!(keys.len(), 2);
    }

    /// Debug output for private JWK types never contains the secret material.
    #[test]
    fn debug_omits_secret(
        kid in "[a-zA-Z0-9._-]{1,24}",
        secret in "[A-Za-z0-9]{8,32}",
    ) {
        let jwk = arb_oct_private(kid, secret.clone());
        let dbg = format!("{:?}", jwk);
        prop_assert!(!dbg.contains(&secret));
    }
}
