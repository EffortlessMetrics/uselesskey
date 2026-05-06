use uselesskey_jwk::{AnyJwk, Jwks, NegativeJwk, NegativeJwks, PublicJwk, RsaPublicJwk};

fn rsa_public(kid: &str) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "modulus".to_string(),
        e: "AQAB".to_string(),
    })
}

#[test]
fn facade_reexports_negative_jwk_variants() {
    let value = rsa_public("facade").negative_value(NegativeJwk::UnsupportedAlg);

    assert_eq!(value["kid"], "facade");
    assert_eq!(value["alg"], "UK-UNSUPPORTED");
}

#[test]
fn facade_reexports_negative_jwks_variants() {
    let jwks = Jwks {
        keys: vec![AnyJwk::from(rsa_public("facade-jwks"))],
    };

    let value = jwks.negative_value(NegativeJwks::DuplicateKey);
    let keys = value["keys"].as_array().expect("keys array");

    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1]);
    assert_eq!(keys[0]["kid"], "facade-jwks");
}
