//! External unit tests for uselesskey-jwk.
//!
//! These tests cover gaps not covered by the inline `#[cfg(test)]` tests:
//! - serde rename of `use_` → `"use"` across all 7 JWK types
//! - empty builder edge case
//! - Display impls for all enum variants
//! - Debug omission of all private fields on RsaPrivateJwk
//! - AnyJwk kid delegation across all enum paths

use serde_json::Value;
use uselesskey_jwk::*;

// =========================================================================
// Sample constructors (external tests can't use inline helpers)
// =========================================================================

fn rsa_public(kid: &str) -> RsaPublicJwk {
    RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "n-value".to_string(),
        e: "AQAB".to_string(),
    }
}

fn rsa_private(kid: &str) -> RsaPrivateJwk {
    RsaPrivateJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "n-value".to_string(),
        e: "AQAB".to_string(),
        d: "d-value".to_string(),
        p: "p-value".to_string(),
        q: "q-value".to_string(),
        dp: "dp-value".to_string(),
        dq: "dq-value".to_string(),
        qi: "qi-value".to_string(),
    }
}

fn ec_public(kid: &str) -> EcPublicJwk {
    EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: "x-value".to_string(),
        y: "y-value".to_string(),
    }
}

fn ec_private(kid: &str) -> EcPrivateJwk {
    EcPrivateJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: "x-value".to_string(),
        y: "y-value".to_string(),
        d: "d-value".to_string(),
    }
}

fn okp_public(kid: &str) -> OkpPublicJwk {
    OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "x-value".to_string(),
    }
}

fn okp_private(kid: &str) -> OkpPrivateJwk {
    OkpPrivateJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "x-value".to_string(),
        d: "d-value".to_string(),
    }
}

fn oct_jwk(kid: &str) -> OctJwk {
    OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.to_string(),
        k: "k-value".to_string(),
    }
}

// =========================================================================
// Serde rename tests
// =========================================================================

#[test]
fn test_use_field_serializes_as_use_not_use_underscore() {
    let values: Vec<Value> = vec![
        serde_json::to_value(rsa_public("k")).unwrap(),
        serde_json::to_value(rsa_private("k")).unwrap(),
        serde_json::to_value(ec_public("k")).unwrap(),
        serde_json::to_value(ec_private("k")).unwrap(),
        serde_json::to_value(okp_public("k")).unwrap(),
        serde_json::to_value(okp_private("k")).unwrap(),
        serde_json::to_value(oct_jwk("k")).unwrap(),
    ];

    for (i, v) in values.iter().enumerate() {
        assert!(
            v.get("use").is_some(),
            "JWK type index {} should have 'use' field",
            i
        );
        assert!(
            v.get("use_").is_none(),
            "JWK type index {} should NOT have 'use_' field",
            i
        );
        assert_eq!(
            v["use"], "sig",
            "JWK type index {} 'use' should be 'sig'",
            i
        );
    }
}

// =========================================================================
// Builder edge cases
// =========================================================================

#[test]
fn test_empty_builder_produces_empty_jwks() {
    let jwks = JwksBuilder::new().build();
    assert_eq!(jwks.keys.len(), 0);
}

// =========================================================================
// Display tests for all enum variants
// =========================================================================

#[test]
fn test_jwks_display_is_valid_json_with_keys_array() {
    let jwks = JwksBuilder::new()
        .add_public(PublicJwk::Ec(ec_public("k1")))
        .add_private(PrivateJwk::Okp(okp_private("k2")))
        .build();

    let json: Value =
        serde_json::from_str(&jwks.to_string()).expect("JWKS Display should be valid JSON");
    assert!(json["keys"].is_array());
    assert_eq!(json["keys"].as_array().unwrap().len(), 2);
}

#[test]
fn test_all_public_variant_display_valid_json() {
    // Inline tests only cover PublicJwk::Rsa Display; verify Ec and Okp.
    let ec = PublicJwk::Ec(ec_public("ec-kid"));
    let ec_json: Value =
        serde_json::from_str(&ec.to_string()).expect("PublicJwk::Ec Display should be valid JSON");
    assert_eq!(ec_json["kty"], "EC");
    assert_eq!(ec_json["kid"], "ec-kid");
    assert_eq!(ec_json["crv"], "P-256");

    let okp = PublicJwk::Okp(okp_public("okp-kid"));
    let okp_json: Value = serde_json::from_str(&okp.to_string())
        .expect("PublicJwk::Okp Display should be valid JSON");
    assert_eq!(okp_json["kty"], "OKP");
    assert_eq!(okp_json["kid"], "okp-kid");
    assert_eq!(okp_json["crv"], "Ed25519");
}

#[test]
fn test_all_private_variant_display_valid_json() {
    // Inline tests only cover PrivateJwk::Oct Display; verify Rsa, Ec, Okp.
    let rsa = PrivateJwk::Rsa(rsa_private("rsa-kid"));
    let rsa_json: Value = serde_json::from_str(&rsa.to_string())
        .expect("PrivateJwk::Rsa Display should be valid JSON");
    assert_eq!(rsa_json["kty"], "RSA");
    assert_eq!(rsa_json["kid"], "rsa-kid");
    assert!(
        rsa_json["d"].is_string(),
        "private key 'd' field should be present"
    );

    let ec = PrivateJwk::Ec(ec_private("ec-kid"));
    let ec_json: Value =
        serde_json::from_str(&ec.to_string()).expect("PrivateJwk::Ec Display should be valid JSON");
    assert_eq!(ec_json["kty"], "EC");
    assert_eq!(ec_json["kid"], "ec-kid");

    let okp = PrivateJwk::Okp(okp_private("okp-kid"));
    let okp_json: Value = serde_json::from_str(&okp.to_string())
        .expect("PrivateJwk::Okp Display should be valid JSON");
    assert_eq!(okp_json["kty"], "OKP");
    assert_eq!(okp_json["kid"], "okp-kid");
}

// =========================================================================
// Debug omission tests
// =========================================================================

#[test]
fn test_rsa_private_debug_omits_all_private_fields() {
    let rsa = rsa_private("kid-rsa");
    let dbg = format!("{:?}", rsa);

    // Debug should contain the struct name and public identifiers
    assert!(dbg.contains("RsaPrivateJwk"));
    assert!(dbg.contains("kid-rsa"));

    // Debug must NOT contain any private field values
    for field_value in [
        "d-value", "p-value", "q-value", "dp-value", "dq-value", "qi-value",
    ] {
        assert!(
            !dbg.contains(field_value),
            "Debug output should not contain private field value '{}'",
            field_value
        );
    }
}

// =========================================================================
// AnyJwk kid delegation
// =========================================================================

#[test]
fn test_any_jwk_kid_delegates_all_variants() {
    // Public variants via AnyJwk
    let pub_ec = AnyJwk::Public(PublicJwk::Ec(ec_public("pub-ec")));
    assert_eq!(pub_ec.kid(), "pub-ec");

    let pub_okp = AnyJwk::Public(PublicJwk::Okp(okp_public("pub-okp")));
    assert_eq!(pub_okp.kid(), "pub-okp");

    let pub_rsa = AnyJwk::Public(PublicJwk::Rsa(rsa_public("pub-rsa")));
    assert_eq!(pub_rsa.kid(), "pub-rsa");

    // Private variants via AnyJwk
    let priv_rsa = AnyJwk::Private(PrivateJwk::Rsa(rsa_private("priv-rsa")));
    assert_eq!(priv_rsa.kid(), "priv-rsa");

    let priv_ec = AnyJwk::Private(PrivateJwk::Ec(ec_private("priv-ec")));
    assert_eq!(priv_ec.kid(), "priv-ec");

    let priv_okp = AnyJwk::Private(PrivateJwk::Okp(okp_private("priv-okp")));
    assert_eq!(priv_okp.kid(), "priv-okp");

    let priv_oct = AnyJwk::Private(PrivateJwk::Oct(oct_jwk("priv-oct")));
    assert_eq!(priv_oct.kid(), "priv-oct");
}
