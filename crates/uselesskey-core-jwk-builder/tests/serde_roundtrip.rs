//! Serde roundtrip tests for JwksBuilder output.
//!
//! Verifies that the JWKS produced by the builder serializes correctly
//! and maintains deterministic ordering in JSON output.

use serde_json::Value;
use uselesskey_core_jwk_builder::JwksBuilder;
use uselesskey_core_jwk_shape::{
    EcPublicJwk, OctJwk, OkpPublicJwk, PrivateJwk, PublicJwk, RsaPublicJwk,
};

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

fn ec_public(kid: &str) -> PublicJwk {
    PublicJwk::Ec(EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: "x-coord".to_string(),
        y: "y-coord".to_string(),
    })
}

fn okp_public(kid: &str) -> PublicJwk {
    PublicJwk::Okp(OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "x-pub".to_string(),
    })
}

fn oct_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.to_string(),
        k: "k-value".to_string(),
    })
}

// ── Builder output → JSON roundtrip ─────────────────────────────────

#[test]
fn builder_output_json_has_keys_array() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("k1"))
        .add_public(ec_public("k2"))
        .build();

    let v = jwks.to_value();
    let keys = v["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
}

#[test]
fn builder_output_roundtrip_via_string() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("rsa-1"))
        .add_public(okp_public("okp-1"))
        .add_private(oct_private("oct-1"))
        .build();

    let json_str = serde_json::to_string(&jwks).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();
    let direct = jwks.to_value();

    assert_eq!(parsed, direct);
}

#[test]
fn builder_sorted_output_preserved_in_json() {
    // Insert out of kid order; builder should sort by kid
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("charlie"))
        .add_public(ec_public("alice"))
        .add_public(okp_public("bob"))
        .build();

    let v = jwks.to_value();
    let keys = v["keys"].as_array().unwrap();

    assert_eq!(keys[0]["kid"], "alice");
    assert_eq!(keys[1]["kid"], "bob");
    assert_eq!(keys[2]["kid"], "charlie");
}

#[test]
fn builder_deterministic_json_output() {
    let build = || {
        JwksBuilder::new()
            .add_public(rsa_public("b"))
            .add_public(ec_public("a"))
            .add_private(oct_private("c"))
            .build()
    };

    let json1 = serde_json::to_string(&build()).unwrap();
    let json2 = serde_json::to_string(&build()).unwrap();

    assert_eq!(json1, json2, "builder must produce deterministic JSON");
}

#[test]
fn builder_empty_produces_empty_keys() {
    let jwks = JwksBuilder::new().build();
    let v = jwks.to_value();

    let keys = v["keys"].as_array().unwrap();
    assert!(keys.is_empty());
}

#[test]
fn builder_mixed_public_private_roundtrip() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("pub-1"))
        .add_private(oct_private("priv-1"))
        .build();

    let json_str = serde_json::to_string(&jwks).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();

    let keys = parsed["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);

    // Each key should have kty and kid
    for key in keys {
        assert!(key["kty"].is_string());
        assert!(key["kid"].is_string());
    }
}

#[test]
fn builder_display_and_to_value_consistency() {
    let jwks = JwksBuilder::new().add_public(ec_public("disp")).build();

    let from_display: Value = serde_json::from_str(&jwks.to_string()).unwrap();
    let from_to_value = jwks.to_value();

    assert_eq!(from_display, from_to_value);
}

#[test]
fn builder_preserves_kty_per_variant() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("rsa"))
        .add_public(ec_public("ec"))
        .add_public(okp_public("okp"))
        .add_private(oct_private("oct"))
        .build();

    let v = jwks.to_value();
    let keys = v["keys"].as_array().unwrap();

    let ktys: Vec<&str> = keys.iter().map(|k| k["kty"].as_str().unwrap()).collect();

    assert!(ktys.contains(&"RSA"));
    assert!(ktys.contains(&"EC"));
    assert!(ktys.contains(&"OKP"));
    assert!(ktys.contains(&"oct"));
}
