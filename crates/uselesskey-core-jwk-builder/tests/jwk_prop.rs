use std::collections::BTreeMap;

use proptest::prelude::*;
use uselesskey_core_jwk::{AnyJwk, PublicJwk, RsaPublicJwk};
use uselesskey_core_jwk_builder::JwksBuilder;

fn sample_rsa_public(kid: &str, n: &str) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: n.to_string(),
        e: "AQAB".to_string(),
    })
}

proptest! {
    #[test]
    fn builder_sorts_by_kid_and_preserves_relative_order_for_duplicates(
        kids in prop::collection::vec("[a-z0-9]{1,8}", 1..64)
    ) {
        let mut builder = JwksBuilder::new();
        let mut expected_by_kid: BTreeMap<String, Vec<usize>> = BTreeMap::new();

        for (index, kid) in kids.iter().enumerate() {
            expected_by_kid.entry(kid.clone()).or_default().push(index);
            builder.push_public(sample_rsa_public(kid, &index.to_string()));
        }

        let jwks = builder.build();

        let mut actual_kids = Vec::new();
        let mut actual_by_kid: BTreeMap<String, Vec<usize>> = BTreeMap::new();

        for any in jwks.keys {
            let AnyJwk::Public(PublicJwk::Rsa(jwk)) = any else {
                panic!("expected RSA public JWK in property test");
            };

            actual_kids.push(jwk.kid.clone());
            let original_index = jwk.n.parse::<usize>().expect("index in n");
            actual_by_kid
                .entry(jwk.kid)
                .or_default()
                .push(original_index);
        }

        let mut sorted_kids = actual_kids.clone();
        sorted_kids.sort();
        prop_assert_eq!(actual_kids, sorted_kids, "kids should be lexicographically sorted");
        prop_assert_eq!(
            actual_by_kid,
            expected_by_kid,
            "duplicate kid entries should preserve insertion order"
        );
    }
}
