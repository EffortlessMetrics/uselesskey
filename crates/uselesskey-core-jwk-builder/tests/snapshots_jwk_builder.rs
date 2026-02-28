//! Insta snapshot tests for JwksBuilder ordering and structure.

use uselesskey_core_jwk_builder::JwksBuilder;
use uselesskey_core_jwk_shape::*;

fn rsa_public(kid: &str) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "n-material".to_string(),
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
        x: "x-material".to_string(),
        y: "y-material".to_string(),
    })
}

fn okp_public(kid: &str) -> PublicJwk {
    PublicJwk::Okp(OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "x-material".to_string(),
    })
}

fn oct_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.to_string(),
        k: "k-material".to_string(),
    })
}

fn redact_jwk(val: &serde_json::Value) -> serde_json::Value {
    let mut map = val.as_object().unwrap().clone();
    for key in ["n", "e", "x", "y", "d", "p", "q", "dp", "dq", "qi", "k"] {
        if map.contains_key(key) {
            map.insert(
                key.to_string(),
                serde_json::Value::String("[REDACTED]".into()),
            );
        }
    }
    serde_json::Value::Object(map)
}

fn redact_jwks(val: &serde_json::Value) -> serde_json::Value {
    let mut root = val.as_object().unwrap().clone();
    if let Some(keys) = root.get("keys").and_then(|k| k.as_array()) {
        let redacted_keys: Vec<serde_json::Value> = keys.iter().map(redact_jwk).collect();
        root.insert("keys".to_string(), serde_json::Value::Array(redacted_keys));
    }
    serde_json::Value::Object(root)
}

// =========================================================================
// Ordering semantics
// =========================================================================

#[test]
fn snapshot_builder_sorts_by_kid() {
    let jwks = JwksBuilder::new()
        .add_public(okp_public("z-key"))
        .add_public(rsa_public("a-key"))
        .add_public(ec_public("m-key"))
        .build();

    let val = jwks.to_value();
    let redacted = redact_jwks(&val);
    insta::assert_yaml_snapshot!(redacted);
}

#[test]
fn snapshot_builder_preserves_insertion_order_for_duplicate_kids() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("dup"))
        .add_public(ec_public("dup"))
        .add_public(okp_public("a-first"))
        .build();

    let val = jwks.to_value();
    let redacted = redact_jwks(&val);
    insta::assert_yaml_snapshot!(redacted);
}

// =========================================================================
// Varied compositions
// =========================================================================

#[test]
fn snapshot_builder_public_and_private_mixed() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("rsa-pub"))
        .add_private(oct_private("hmac-key"))
        .add_public(ec_public("ec-pub"))
        .build();

    let val = jwks.to_value();
    let redacted = redact_jwks(&val);
    insta::assert_yaml_snapshot!(redacted);
}

#[test]
fn snapshot_builder_single_key() {
    let jwks = JwksBuilder::new()
        .add_public(okp_public("only-key"))
        .build();

    let val = jwks.to_value();
    let redacted = redact_jwks(&val);
    insta::assert_yaml_snapshot!(redacted);
}

#[test]
fn snapshot_builder_empty() {
    let jwks = JwksBuilder::new().build();
    let val = jwks.to_value();
    insta::assert_yaml_snapshot!(val);
}

#[test]
fn snapshot_builder_all_key_types() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("key-rsa"))
        .add_public(ec_public("key-ec"))
        .add_public(okp_public("key-okp"))
        .add_private(oct_private("key-oct"))
        .build();

    let val = jwks.to_value();
    let redacted = redact_jwks(&val);
    insta::assert_yaml_snapshot!(redacted);
}
