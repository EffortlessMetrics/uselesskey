//! Insta snapshot tests for uselesskey-jwk (public facade).
//!
//! Verifies the top-level facade re-exports with key material redacted.

use serde::Serialize;
use uselesskey_jwk::{
    AnyJwk, EcPublicJwk, JwksBuilder, OctJwk, OkpPublicJwk, PrivateJwk, PublicJwk, RsaPublicJwk,
};

fn rsa_pub(kid: &str) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.into(),
        n: "rsa-n".into(),
        e: "AQAB".into(),
    })
}

fn oct_priv(kid: &str) -> PrivateJwk {
    PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.into(),
        k: "secret-k".into(),
    })
}

#[test]
fn snapshot_jwk_facade_builder_ordering() {
    #[derive(Serialize)]
    struct JwksInfo {
        key_count: usize,
        kids: Vec<String>,
    }

    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("beta"))
        .add_public(PublicJwk::Ec(EcPublicJwk {
            kty: "EC",
            use_: "sig",
            alg: "ES256",
            crv: "P-256",
            kid: "alpha".into(),
            x: "x".into(),
            y: "y".into(),
        }))
        .add_public(PublicJwk::Okp(OkpPublicJwk {
            kty: "OKP",
            use_: "sig",
            alg: "EdDSA",
            crv: "Ed25519",
            kid: "gamma".into(),
            x: "x".into(),
        }))
        .build();

    let info = JwksInfo {
        key_count: jwks.keys.len(),
        kids: jwks.keys.iter().map(|k| k.kid().to_string()).collect(),
    };

    insta::assert_yaml_snapshot!("jwk_facade_builder_ordering", info);
}

#[test]
fn snapshot_jwk_facade_mixed_keys() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("pub-key"))
        .add_private(oct_priv("priv-key"))
        .build();

    let value = jwks.to_value();
    insta::assert_yaml_snapshot!("jwk_facade_mixed_keys", value, {
        ".keys[].n" => "[REDACTED]",
        ".keys[].e" => "[REDACTED]",
        ".keys[].k" => "[REDACTED]",
    });
}

#[test]
fn snapshot_jwk_facade_any_jwk_conversion() {
    #[derive(Serialize)]
    struct ConversionCheck {
        public_kid: String,
        private_kid: String,
    }

    let pub_any = AnyJwk::from(rsa_pub("from-pub"));
    let priv_any = AnyJwk::from(oct_priv("from-priv"));

    let check = ConversionCheck {
        public_kid: pub_any.kid().to_string(),
        private_kid: priv_any.kid().to_string(),
    };

    insta::assert_yaml_snapshot!("jwk_facade_any_conversion", check);
}

#[test]
fn snapshot_jwk_facade_display_roundtrip() {
    let jwks = JwksBuilder::new().add_public(rsa_pub("key-1")).build();

    let display = jwks.to_string();
    let parsed: serde_json::Value = serde_json::from_str(&display).unwrap();

    #[derive(Serialize)]
    struct RoundtripCheck {
        is_valid_json: bool,
        has_keys_array: bool,
        key_count: usize,
    }

    let check = RoundtripCheck {
        is_valid_json: true,
        has_keys_array: parsed["keys"].is_array(),
        key_count: parsed["keys"].as_array().unwrap().len(),
    };

    insta::assert_yaml_snapshot!("jwk_facade_display_roundtrip", check);
}
