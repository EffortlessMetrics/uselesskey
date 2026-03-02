//! Property tests for the uselesskey-jwk re-export / builder layer.

use proptest::prelude::*;
use uselesskey_jwk::*;

fn arb_rsa_public_jwk(kid: String) -> RsaPublicJwk {
    RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid,
        n: "modulus".to_string(),
        e: "AQAB".to_string(),
    }
}

fn arb_ec_public_jwk(kid: String) -> EcPublicJwk {
    EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid,
        x: "x-value".to_string(),
        y: "y-value".to_string(),
    }
}

fn arb_okp_public_jwk(kid: String) -> OkpPublicJwk {
    OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid,
        x: "x-value".to_string(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// kid() accessor always returns the kid passed at construction.
    #[test]
    fn kid_accessor_returns_correct_value(kid in "[a-zA-Z0-9_-]{1,30}") {
        let rsa = PublicJwk::Rsa(arb_rsa_public_jwk(kid.clone()));
        prop_assert_eq!(rsa.kid(), kid.as_str());

        let ec = PublicJwk::Ec(arb_ec_public_jwk(kid.clone()));
        prop_assert_eq!(ec.kid(), kid.as_str());

        let okp = PublicJwk::Okp(arb_okp_public_jwk(kid.clone()));
        prop_assert_eq!(okp.kid(), kid.as_str());
    }

    /// AnyJwk delegates kid() correctly for all public variants.
    #[test]
    fn any_jwk_kid_delegation(kid in "[a-zA-Z0-9_-]{1,30}") {
        let rsa = AnyJwk::Public(PublicJwk::Rsa(arb_rsa_public_jwk(kid.clone())));
        prop_assert_eq!(rsa.kid(), kid.as_str());

        let ec = AnyJwk::Public(PublicJwk::Ec(arb_ec_public_jwk(kid.clone())));
        prop_assert_eq!(ec.kid(), kid.as_str());

        let okp = AnyJwk::Public(PublicJwk::Okp(arb_okp_public_jwk(kid.clone())));
        prop_assert_eq!(okp.kid(), kid.as_str());
    }

    /// JwksBuilder produces keys sorted by kid.
    #[test]
    fn builder_sorts_by_kid(
        kid_a in "[a-zA-Z][a-zA-Z0-9]{0,10}",
        kid_b in "[a-zA-Z][a-zA-Z0-9]{0,10}",
    ) {
        let jwks = JwksBuilder::new()
            .add_public(PublicJwk::Rsa(arb_rsa_public_jwk(kid_a.clone())))
            .add_public(PublicJwk::Ec(arb_ec_public_jwk(kid_b.clone())))
            .build();

        prop_assert_eq!(jwks.keys.len(), 2);
        // Keys should be sorted by kid.
        prop_assert!(jwks.keys[0].kid() <= jwks.keys[1].kid());
    }

    /// JWKS Display is always valid JSON with a "keys" array.
    #[test]
    fn jwks_display_is_valid_json(kid in "[a-zA-Z0-9_]{1,15}") {
        let jwks = JwksBuilder::new()
            .add_public(PublicJwk::Rsa(arb_rsa_public_jwk(kid)))
            .build();

        let json: serde_json::Value = serde_json::from_str(&jwks.to_string())
            .expect("JWKS Display should be valid JSON");
        prop_assert!(json["keys"].is_array());
        prop_assert_eq!(json["keys"].as_array().unwrap().len(), 1);
    }

    /// Serialized JWK always contains "use" field, not "use_".
    #[test]
    fn serde_uses_use_not_use_underscore(kid in "[a-zA-Z0-9]{1,10}") {
        let jwk = arb_rsa_public_jwk(kid);
        let json = serde_json::to_value(&jwk).unwrap();
        prop_assert!(json.get("use").is_some(), "should have 'use' field");
        prop_assert!(json.get("use_").is_none(), "should NOT have 'use_' field");
    }

    /// PublicJwk Display is always valid JSON with correct kty.
    #[test]
    fn public_jwk_display_valid_json(kid in "[a-zA-Z0-9_]{1,15}", variant in 0u8..3) {
        let jwk = match variant {
            0 => PublicJwk::Rsa(arb_rsa_public_jwk(kid)),
            1 => PublicJwk::Ec(arb_ec_public_jwk(kid)),
            _ => PublicJwk::Okp(arb_okp_public_jwk(kid)),
        };
        let json: serde_json::Value = serde_json::from_str(&jwk.to_string())
            .expect("PublicJwk Display should be valid JSON");
        prop_assert!(json["kty"].is_string());
        prop_assert!(json["kid"].is_string());
    }
}
