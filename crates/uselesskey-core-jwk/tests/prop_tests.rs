//! Property-based tests for `uselesskey-core-jwk`.

use proptest::prelude::*;
use serde_json::Value;
use uselesskey_core_jwk::{
    AnyJwk, EcPublicJwk, JwksBuilder, OctJwk, OkpPublicJwk, PrivateJwk, PublicJwk, RsaPublicJwk,
};

fn arb_rsa_public(kid: String, n: String, e: String) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid,
        n,
        e,
    })
}

fn arb_ec_public(kid: String, x: String, y: String) -> PublicJwk {
    PublicJwk::Ec(EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid,
        x,
        y,
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

    #[test]
    fn rsa_public_to_value_is_valid_json(
        kid in "[a-zA-Z0-9._-]{1,32}",
        n in "[A-Za-z0-9+/]{1,64}",
        e in "[A-Za-z0-9+/]{1,8}",
    ) {
        let jwk = arb_rsa_public(kid.clone(), n, e);
        let val = jwk.to_value();
        prop_assert_eq!(val["kty"].as_str(), Some("RSA"));
        prop_assert_eq!(val["kid"].as_str(), Some(kid.as_str()));

        // Display round-trip produces valid JSON
        let text = jwk.to_string();
        let parsed: Value = serde_json::from_str(&text).unwrap();
        prop_assert_eq!(val, parsed);
    }

    #[test]
    fn ec_public_to_value_is_valid_json(
        kid in "[a-zA-Z0-9._-]{1,32}",
        x in "[A-Za-z0-9+/]{1,64}",
        y in "[A-Za-z0-9+/]{1,64}",
    ) {
        let jwk = arb_ec_public(kid.clone(), x, y);
        let val = jwk.to_value();
        prop_assert_eq!(val["kty"].as_str(), Some("EC"));
        prop_assert_eq!(val["kid"].as_str(), Some(kid.as_str()));
    }

    #[test]
    fn okp_public_to_value_is_valid_json(
        kid in "[a-zA-Z0-9._-]{1,32}",
        x in "[A-Za-z0-9+/]{1,64}",
    ) {
        let jwk = arb_okp_public(kid.clone(), x);
        let val = jwk.to_value();
        prop_assert_eq!(val["kty"].as_str(), Some("OKP"));
        prop_assert_eq!(val["kid"].as_str(), Some(kid.as_str()));
    }

    #[test]
    fn oct_private_debug_never_leaks_secret(
        kid in "[a-zA-Z0-9._-]{1,32}",
        k in "[A-Za-z0-9+/]{8,64}",
    ) {
        let jwk = arb_oct_private(kid, k.clone());
        let dbg = format!("{jwk:?}");
        prop_assert!(!dbg.contains(&k), "Debug must not contain secret key material");
    }

    #[test]
    fn kid_accessor_returns_input_for_all_variants(
        kid in "[a-zA-Z0-9._-]{1,32}",
    ) {
        let rsa = arb_rsa_public(kid.clone(), "n".into(), "e".into());
        prop_assert_eq!(rsa.kid(), kid.as_str());

        let ec = arb_ec_public(kid.clone(), "x".into(), "y".into());
        prop_assert_eq!(ec.kid(), kid.as_str());

        let okp = arb_okp_public(kid.clone(), "x".into());
        prop_assert_eq!(okp.kid(), kid.as_str());

        let oct = arb_oct_private(kid.clone(), "k".into());
        prop_assert_eq!(oct.kid(), kid.as_str());
    }

    #[test]
    fn clone_preserves_serialization(
        kid in "[a-zA-Z0-9._-]{1,32}",
        n in "[A-Za-z0-9+/]{1,32}",
    ) {
        let original = arb_rsa_public(kid, n, "AQAB".into());
        let cloned = original.clone();
        prop_assert_eq!(original.to_value(), cloned.to_value());
        prop_assert_eq!(original.kid(), cloned.kid());
    }

    #[test]
    fn any_jwk_preserves_kid(
        kid in "[a-zA-Z0-9._-]{1,32}",
    ) {
        let pub_jwk = arb_rsa_public(kid.clone(), "n".into(), "e".into());
        let any = AnyJwk::from(pub_jwk);
        prop_assert_eq!(any.kid(), kid.as_str());

        let priv_jwk = arb_oct_private(kid.clone(), "k".into());
        let any = AnyJwk::from(priv_jwk);
        prop_assert_eq!(any.kid(), kid.as_str());
    }

    #[test]
    fn jwks_builder_sorts_by_kid(
        kid_a in "[a-z]{1,8}",
        kid_b in "[a-z]{1,8}",
        kid_c in "[a-z]{1,8}",
    ) {
        let jwks = JwksBuilder::new()
            .add_public(arb_rsa_public(kid_a.clone(), "n".into(), "e".into()))
            .add_public(arb_ec_public(kid_b.clone(), "x".into(), "y".into()))
            .add_public(arb_okp_public(kid_c.clone(), "x".into()))
            .build();

        let mut expected = [kid_a, kid_b, kid_c];
        expected.sort();

        let actual: Vec<&str> = jwks.keys.iter().map(|k| k.kid()).collect();
        // Keys should be sorted by kid
        let mut sorted_actual = actual.clone();
        sorted_actual.sort();
        prop_assert_eq!(actual, sorted_actual);
    }

    #[test]
    fn use_field_serialized_without_underscore(
        kid in "[a-zA-Z0-9._-]{1,16}",
    ) {
        let jwk = arb_rsa_public(kid, "n".into(), "e".into());
        let val = jwk.to_value();
        prop_assert!(val.get("use").is_some(), "should have 'use' field");
        prop_assert!(val.get("use_").is_none(), "should not have 'use_' field");
    }
}
