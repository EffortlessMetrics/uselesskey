use uselesskey_core_jwk as core;
use uselesskey_jwk as facade;

fn sample_rsa_public(kid: &str) -> core::PublicJwk {
    core::PublicJwk::Rsa(core::RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "n".to_string(),
        e: "AQAB".to_string(),
    })
}

#[test]
fn facade_and_core_public_types_are_compatible() {
    fn accepts_facade_type(_: facade::PublicJwk) {}

    let core_jwk = sample_rsa_public("kid-core");
    accepts_facade_type(core_jwk.clone());

    let any: facade::AnyJwk = facade::AnyJwk::from(core_jwk);
    assert_eq!(any.kid(), "kid-core");
}

#[test]
fn facade_builder_accepts_core_values() {
    let jwks = facade::JwksBuilder::new()
        .add_public(sample_rsa_public("kid-b"))
        .add_public(sample_rsa_public("kid-a"))
        .build();

    assert_eq!(jwks.keys.len(), 2);
    assert_eq!(jwks.keys[0].kid(), "kid-a");
    assert_eq!(jwks.keys[1].kid(), "kid-b");
}
