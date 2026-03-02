//! Serde roundtrip tests for the re-exported JWK types and JwksBuilder.
//!
//! Verifies that the facade re-exports serialize identically to the
//! underlying shape crate types.

use serde_json::Value;
use uselesskey_core_jwk::{
    AnyJwk, EcPublicJwk, JwksBuilder, OctJwk, OkpPublicJwk, PrivateJwk, PublicJwk, RsaPublicJwk,
};

#[test]
fn reexported_rsa_public_jwk_serializes() {
    let jwk = RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: "re-rsa".to_string(),
        n: "n-val".to_string(),
        e: "AQAB".to_string(),
    };

    let v = serde_json::to_value(&jwk).unwrap();
    assert_eq!(v["kty"], "RSA");
    assert_eq!(v["use"], "sig");
    assert_eq!(v["kid"], "re-rsa");
}

#[test]
fn reexported_jwks_builder_roundtrip() {
    let jwks = JwksBuilder::new()
        .add_public(PublicJwk::Ec(EcPublicJwk {
            kty: "EC",
            use_: "sig",
            alg: "ES256",
            crv: "P-256",
            kid: "ec-1".to_string(),
            x: "x".to_string(),
            y: "y".to_string(),
        }))
        .add_public(PublicJwk::Okp(OkpPublicJwk {
            kty: "OKP",
            use_: "sig",
            alg: "EdDSA",
            crv: "Ed25519",
            kid: "okp-1".to_string(),
            x: "x".to_string(),
        }))
        .build();

    let json_str = serde_json::to_string(&jwks).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();
    let direct = jwks.to_value();

    assert_eq!(parsed, direct);

    let keys = parsed["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
}

#[test]
fn reexported_any_jwk_roundtrip() {
    let any = AnyJwk::Private(PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: "oct-1".to_string(),
        k: "secret".to_string(),
    }));

    let json_str = serde_json::to_string(&any).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();
    let direct = serde_json::to_value(&any).unwrap();

    assert_eq!(parsed, direct);
    assert_eq!(parsed["kty"], "oct");
}

#[test]
fn reexported_builder_deterministic() {
    let build = || {
        JwksBuilder::new()
            .add_public(PublicJwk::Rsa(RsaPublicJwk {
                kty: "RSA",
                use_: "sig",
                alg: "RS256",
                kid: "det".to_string(),
                n: "n".to_string(),
                e: "e".to_string(),
            }))
            .build()
    };

    let json1 = serde_json::to_string(&build()).unwrap();
    let json2 = serde_json::to_string(&build()).unwrap();
    assert_eq!(json1, json2);
}
