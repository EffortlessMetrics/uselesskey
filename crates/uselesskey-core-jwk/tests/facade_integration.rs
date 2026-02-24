use uselesskey_core_jwk::{AnyJwk, Jwks, OctJwk, PrivateJwk, PublicJwk, RsaPublicJwk};

#[test]
fn core_jwk_facade_exports_shape_items() {
    let public = PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: "facade-kid".to_string(),
        n: "n".to_string(),
        e: "AQAB".to_string(),
    });

    let jwks = Jwks {
        keys: vec![
            AnyJwk::Public(public.clone()),
            AnyJwk::Private(PrivateJwk::Oct(OctJwk {
                kty: "oct",
                use_: "sig",
                alg: "HS256",
                kid: "oct-kid".to_string(),
                k: "abc".to_string(),
            })),
        ],
    };

    let serialized = jwks.to_string();
    assert!(serialized.contains("\"keys\""));
    assert!(serialized.contains("\"facade-kid\""));
    assert!(serialized.contains("\"oct-kid\""));
    assert_eq!(public.kid(), "facade-kid");
}
