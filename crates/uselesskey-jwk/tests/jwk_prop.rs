//! Property-based tests for the uselesskey-jwk facade.

use proptest::prelude::*;
use serde_json::Value;
use uselesskey_jwk::{AnyJwk, JwksBuilder, PublicJwk, RsaPublicJwk};

fn kid_strategy() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9._-]{1,24}"
}

proptest! {
    /// Builder output length matches the number of keys added.
    #[test]
    fn builder_preserves_count(
        kids in prop::collection::vec(kid_strategy(), 0..16),
    ) {
        let mut builder = JwksBuilder::new();
        for kid in &kids {
            builder.push_public(PublicJwk::Rsa(RsaPublicJwk {
                kty: "RSA", use_: "sig", alg: "RS256",
                kid: kid.clone(), n: "n".into(), e: "AQAB".into(),
            }));
        }
        let jwks = builder.build();
        prop_assert_eq!(jwks.keys.len(), kids.len());
    }

    /// Builder sorts output by kid.
    #[test]
    fn builder_output_is_kid_sorted(
        kids in prop::collection::vec(kid_strategy(), 0..16),
    ) {
        let mut builder = JwksBuilder::new();
        for kid in &kids {
            builder.push_public(PublicJwk::Rsa(RsaPublicJwk {
                kty: "RSA", use_: "sig", alg: "RS256",
                kid: kid.clone(), n: "n".into(), e: "AQAB".into(),
            }));
        }
        let jwks = builder.build();
        for pair in jwks.keys.windows(2) {
            prop_assert!(pair[0].kid() <= pair[1].kid(),
                "not sorted: {} > {}", pair[0].kid(), pair[1].kid());
        }
    }

    /// Facade JWKS serialization roundtrips through JSON.
    #[test]
    fn jwks_json_roundtrip(
        kids in prop::collection::vec(kid_strategy(), 1..8),
    ) {
        let mut builder = JwksBuilder::new();
        for kid in &kids {
            builder.push_public(PublicJwk::Rsa(RsaPublicJwk {
                kty: "RSA", use_: "sig", alg: "RS256",
                kid: kid.clone(), n: "n".into(), e: "AQAB".into(),
            }));
        }
        let jwks = builder.build();
        let value = jwks.to_value();
        let parsed: Value = serde_json::from_str(&jwks.to_string()).unwrap();
        prop_assert_eq!(&value, &parsed);

        let arr = value["keys"].as_array().unwrap();
        prop_assert_eq!(arr.len(), kids.len());
    }

    /// Every kid added appears in the output.
    #[test]
    fn all_kids_present_in_output(
        kids in prop::collection::vec(kid_strategy(), 0..16),
    ) {
        let mut builder = JwksBuilder::new();
        for kid in &kids {
            builder.push_any(AnyJwk::from(PublicJwk::Rsa(RsaPublicJwk {
                kty: "RSA", use_: "sig", alg: "RS256",
                kid: kid.clone(), n: "n".into(), e: "AQAB".into(),
            })));
        }
        let jwks = builder.build();
        let mut expected: Vec<&str> = kids.iter().map(|s| s.as_str()).collect();
        expected.sort();
        let mut actual: Vec<&str> = jwks.keys.iter().map(|k| k.kid()).collect();
        actual.sort();
        prop_assert_eq!(expected, actual);
    }
}
