use uselesskey_jwk as jwk;

fn sample_rsa_public(kid: &str) -> jwk::PublicJwk {
    jwk::PublicJwk::Rsa(jwk::RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "n".to_string(),
        e: "AQAB".to_string(),
    })
}

#[test]
fn public_root_exposes_jwk_shapes() {
    fn accepts_public_type(_: jwk::PublicJwk) {}

    let public_jwk = sample_rsa_public("kid-public");
    accepts_public_type(public_jwk.clone());

    let any: jwk::AnyJwk = jwk::AnyJwk::from(public_jwk);
    assert_eq!(any.kid(), "kid-public");
}

#[test]
fn public_builder_accepts_public_values() {
    let jwks = jwk::JwksBuilder::new()
        .add_public(sample_rsa_public("kid-b"))
        .add_public(sample_rsa_public("kid-a"))
        .build();

    assert_eq!(jwks.keys.len(), 2);
    assert_eq!(jwks.keys[0].kid(), "kid-a");
    assert_eq!(jwks.keys[1].kid(), "kid-b");
}
