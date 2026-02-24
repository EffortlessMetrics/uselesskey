use uselesskey_core_jwk_shape::{AnyJwk, Jwks, OctJwk, PrivateJwk, PublicJwk, RsaPublicJwk};

#[test]
fn integration_builds_shape_collection_round_trip() {
    let mut keys = Vec::<AnyJwk>::new();

    let public = PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: "integration-rsa".to_string(),
        n: "n-value".to_string(),
        e: "AQAB".to_string(),
    });

    keys.push(AnyJwk::Public(public));
    keys.push(AnyJwk::Private(PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: "integration-oct".to_string(),
        k: "secret".to_string(),
    })));

    let jwks = Jwks { keys };
    let json = jwks.to_string();
    let round_trip: serde_json::Value = serde_json::from_str(&json).expect("jwks JSON");

    let raw_keys = round_trip["keys"].as_array().expect("keys array");
    assert_eq!(raw_keys.len(), 2);
    assert_eq!(raw_keys[0]["kid"], "integration-rsa");
    assert_eq!(raw_keys[1]["kid"], "integration-oct");
}
