//! Insta snapshot tests for uselesskey-core-jwk-builder.
//!
//! Snapshot JWKS builder ordering and composition with key material redacted.

use serde::Serialize;
use uselesskey_core_jwk_builder::JwksBuilder;
use uselesskey_core_jwk_shape::{
    AnyJwk, EcPublicJwk, OctJwk, OkpPublicJwk, PrivateJwk, PublicJwk, RsaPublicJwk,
};

fn rsa_pub(kid: &str) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.into(),
        n: "modulus-data".into(),
        e: "AQAB".into(),
    })
}

fn ec_pub(kid: &str) -> PublicJwk {
    PublicJwk::Ec(EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.into(),
        x: "ec-x-data".into(),
        y: "ec-y-data".into(),
    })
}

fn okp_pub(kid: &str) -> PublicJwk {
    PublicJwk::Okp(OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.into(),
        x: "okp-x-data".into(),
    })
}

fn oct_priv(kid: &str) -> PrivateJwk {
    PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.into(),
        k: "secret-key-data".into(),
    })
}

#[derive(Serialize)]
struct JwksSnapshot {
    key_count: usize,
    kids: Vec<String>,
    ktys: Vec<String>,
}

fn snapshot_from_builder(builder: JwksBuilder) -> JwksSnapshot {
    let jwks = builder.build();
    JwksSnapshot {
        key_count: jwks.keys.len(),
        kids: jwks.keys.iter().map(|k| k.kid().to_string()).collect(),
        ktys: jwks
            .keys
            .iter()
            .map(|k| k.to_value()["kty"].as_str().unwrap().to_string())
            .collect(),
    }
}

#[test]
fn snapshot_builder_sorts_by_kid() {
    let builder = JwksBuilder::new()
        .add_public(rsa_pub("charlie"))
        .add_public(ec_pub("alpha"))
        .add_public(okp_pub("bravo"));

    insta::assert_yaml_snapshot!("builder_sorts_by_kid", snapshot_from_builder(builder));
}

#[test]
fn snapshot_builder_stable_duplicate_kids() {
    let builder = JwksBuilder::new()
        .add_public(rsa_pub("same"))
        .add_public(ec_pub("same"))
        .add_public(okp_pub("same"));

    insta::assert_yaml_snapshot!(
        "builder_stable_duplicate_kids",
        snapshot_from_builder(builder)
    );
}

#[test]
fn snapshot_builder_mixed_public_private() {
    let builder = JwksBuilder::new()
        .add_public(rsa_pub("key-b"))
        .add_private(oct_priv("key-a"));

    insta::assert_yaml_snapshot!(
        "builder_mixed_public_private",
        snapshot_from_builder(builder)
    );
}

#[test]
fn snapshot_builder_add_any() {
    let builder = JwksBuilder::new()
        .add_any(AnyJwk::from(rsa_pub("z-key")))
        .add_any(AnyJwk::from(oct_priv("a-key")));

    insta::assert_yaml_snapshot!("builder_add_any", snapshot_from_builder(builder));
}

#[test]
fn snapshot_builder_push_methods() {
    let mut builder = JwksBuilder::new();
    builder.push_public(ec_pub("pub-key"));
    builder.push_private(oct_priv("priv-key"));
    builder.push_any(AnyJwk::from(okp_pub("any-key")));

    insta::assert_yaml_snapshot!("builder_push_methods", snapshot_from_builder(builder));
}

#[test]
fn snapshot_builder_empty() {
    let builder = JwksBuilder::new();
    insta::assert_yaml_snapshot!("builder_empty", snapshot_from_builder(builder));
}

#[test]
fn snapshot_builder_jwks_serialized_shape() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("rsa-1"))
        .add_public(ec_pub("ec-1"))
        .build();

    let value = jwks.to_value();
    insta::assert_yaml_snapshot!("builder_jwks_serialized", value, {
        ".keys[].n" => "[REDACTED]",
        ".keys[].e" => "[REDACTED]",
        ".keys[].x" => "[REDACTED]",
        ".keys[].y" => "[REDACTED]",
    });
}
