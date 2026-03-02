//! Mutant-killing tests for JWKS builder.

use uselesskey_core_jwk_builder::JwksBuilder;
use uselesskey_core_jwk_shape::{
    AnyJwk, EcPublicJwk, OctJwk, OkpPublicJwk, PrivateJwk, PublicJwk, RsaPublicJwk,
};

fn rsa_pub(kid: &str) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "n".to_string(),
        e: "e".to_string(),
    })
}

fn oct_priv(kid: &str) -> PrivateJwk {
    PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.to_string(),
        k: "k".to_string(),
    })
}

#[test]
fn empty_builder_produces_empty_jwks() {
    let jwks = JwksBuilder::new().build();
    assert!(jwks.keys.is_empty());
}

#[test]
fn add_public_preserves_key() {
    let jwks = JwksBuilder::new().add_public(rsa_pub("k1")).build();
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].kid(), "k1");
}

#[test]
fn add_private_preserves_key() {
    let jwks = JwksBuilder::new().add_private(oct_priv("k2")).build();
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].kid(), "k2");
}

#[test]
fn add_any_preserves_key() {
    let any = AnyJwk::from(rsa_pub("k3"));
    let jwks = JwksBuilder::new().add_any(any).build();
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].kid(), "k3");
}

#[test]
fn builder_sorts_by_kid() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("c"))
        .add_public(rsa_pub("a"))
        .add_public(rsa_pub("b"))
        .build();

    assert_eq!(jwks.keys[0].kid(), "a");
    assert_eq!(jwks.keys[1].kid(), "b");
    assert_eq!(jwks.keys[2].kid(), "c");
}

#[test]
fn builder_preserves_insertion_order_for_same_kid() {
    let jwks = JwksBuilder::new()
        .add_public(PublicJwk::Rsa(RsaPublicJwk {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: "same".to_string(),
            n: "first".to_string(),
            e: "e".to_string(),
        }))
        .add_public(PublicJwk::Rsa(RsaPublicJwk {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: "same".to_string(),
            n: "second".to_string(),
            e: "e".to_string(),
        }))
        .build();

    assert_eq!(jwks.keys[0].to_value()["n"], "first");
    assert_eq!(jwks.keys[1].to_value()["n"], "second");
}

#[test]
fn push_methods_are_equivalent_to_add() {
    let mut builder = JwksBuilder::new();
    builder.push_public(rsa_pub("p1"));
    builder.push_private(oct_priv("p2"));
    builder.push_any(AnyJwk::from(rsa_pub("p3")));
    let jwks = builder.build();

    assert_eq!(jwks.keys.len(), 3);
    // Sorted order: p1, p2, p3
    assert_eq!(jwks.keys[0].kid(), "p1");
    assert_eq!(jwks.keys[1].kid(), "p2");
    assert_eq!(jwks.keys[2].kid(), "p3");
}

#[test]
fn mixed_types_sorted_correctly() {
    let ec_pub = PublicJwk::Ec(EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: "b-ec".to_string(),
        x: "x".to_string(),
        y: "y".to_string(),
    });
    let okp_pub = PublicJwk::Okp(OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: "a-okp".to_string(),
        x: "x".to_string(),
    });

    let jwks = JwksBuilder::new()
        .add_public(ec_pub)
        .add_public(okp_pub)
        .add_private(oct_priv("c-oct"))
        .build();

    assert_eq!(jwks.keys[0].kid(), "a-okp");
    assert_eq!(jwks.keys[1].kid(), "b-ec");
    assert_eq!(jwks.keys[2].kid(), "c-oct");
}
