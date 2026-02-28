//! Insta snapshot tests for uselesskey-jwk JWK/JWKS structures.

use serde_json::Value;
use uselesskey_jwk::*;

fn rsa_public(kid: &str) -> RsaPublicJwk {
    RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "n-material".to_string(),
        e: "AQAB".to_string(),
    }
}

fn ec_public(kid: &str) -> EcPublicJwk {
    EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: "x-material".to_string(),
        y: "y-material".to_string(),
    }
}

fn okp_public(kid: &str) -> OkpPublicJwk {
    OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "x-material".to_string(),
    }
}

fn redact_jwk(val: &Value) -> Value {
    let mut map = val.as_object().unwrap().clone();
    for key in ["n", "e", "x", "y", "d", "p", "q", "dp", "dq", "qi", "k"] {
        if map.contains_key(key) {
            map.insert(key.to_string(), Value::String("[REDACTED]".into()));
        }
    }
    Value::Object(map)
}

fn redact_jwks(val: &Value) -> Value {
    let mut root = val.as_object().unwrap().clone();
    if let Some(keys) = root.get("keys").and_then(|k| k.as_array()) {
        let redacted_keys: Vec<Value> = keys.iter().map(redact_jwk).collect();
        root.insert("keys".to_string(), Value::Array(redacted_keys));
    }
    Value::Object(root)
}

// =========================================================================
// Individual JWK field structure snapshots
// =========================================================================

#[test]
fn snapshot_rsa_public_jwk_fields() {
    let jwk = rsa_public("rsa-kid-1");
    let val = serde_json::to_value(&jwk).unwrap();
    let redacted = redact_jwk(&val);
    insta::assert_yaml_snapshot!(redacted);
}

#[test]
fn snapshot_ec_public_jwk_fields() {
    let jwk = ec_public("ec-kid-1");
    let val = serde_json::to_value(&jwk).unwrap();
    let redacted = redact_jwk(&val);
    insta::assert_yaml_snapshot!(redacted);
}

#[test]
fn snapshot_okp_public_jwk_fields() {
    let jwk = okp_public("okp-kid-1");
    let val = serde_json::to_value(&jwk).unwrap();
    let redacted = redact_jwk(&val);
    insta::assert_yaml_snapshot!(redacted);
}

#[test]
fn snapshot_oct_private_jwk_fields() {
    let jwk = OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: "oct-kid-1".to_string(),
        k: "secret-material".to_string(),
    };
    let val = serde_json::to_value(&jwk).unwrap();
    let redacted = redact_jwk(&val);
    insta::assert_yaml_snapshot!(redacted);
}

// =========================================================================
// JWKS builder with multiple key types
// =========================================================================

#[test]
fn snapshot_jwks_mixed_key_types() {
    let jwks = JwksBuilder::new()
        .add_public(PublicJwk::Rsa(rsa_public("rsa-kid")))
        .add_public(PublicJwk::Ec(ec_public("ec-kid")))
        .add_public(PublicJwk::Okp(okp_public("okp-kid")))
        .build();

    let val = jwks.to_value();
    let redacted = redact_jwks(&val);
    insta::assert_yaml_snapshot!(redacted);
}

#[test]
fn snapshot_jwks_ordering_is_by_kid() {
    let jwks = JwksBuilder::new()
        .add_public(PublicJwk::Okp(okp_public("z-key")))
        .add_public(PublicJwk::Rsa(rsa_public("a-key")))
        .add_public(PublicJwk::Ec(ec_public("m-key")))
        .build();

    let val = jwks.to_value();
    let redacted = redact_jwks(&val);
    insta::assert_yaml_snapshot!(redacted);
}

#[test]
fn snapshot_jwks_empty() {
    let jwks = JwksBuilder::new().build();
    let val = jwks.to_value();
    insta::assert_yaml_snapshot!(val);
}
