use uselesskey_core_jwk_builder::JwksBuilder;
use uselesskey_core_jwk_shape::{AnyJwk, PublicJwk, RsaPublicJwk};

fn rsa(kid: &str, n: &str) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: n.to_string(),
        e: "AQAB".to_string(),
    })
}

#[test]
fn integration_orders_jwks_keys_by_kid() {
    let jwks = JwksBuilder::new()
        .add_public(rsa("z", "nz"))
        .add_public(rsa("a", "na"))
        .add_public(rsa("m", "nm"))
        .build();

    let kids: Vec<_> = jwks.keys.iter().map(AnyJwk::kid).collect();
    assert_eq!(kids, vec!["a", "m", "z"]);
}

#[test]
fn integration_preserves_duplicate_kids_in_insertion_order() {
    let jwks = JwksBuilder::new()
        .add_public(rsa("dup", "n1"))
        .add_public(rsa("dup", "n2"))
        .add_public(rsa("a", "n3"))
        .build();
    let n_values: Vec<_> = jwks
        .keys
        .into_iter()
        .filter_map(|jwk| {
            jwk.to_value()
                .get("n")
                .and_then(|value| value.as_str())
                .map(|n| n.to_string())
        })
        .collect();

    assert_eq!(n_values, vec!["n3", "n1", "n2"]);
}
