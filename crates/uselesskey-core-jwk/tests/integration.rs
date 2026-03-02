//! Integration tests for `uselesskey-core-jwk`.
//!
//! Covers: JWK type construction, serialization round-trips, kid accessors,
//! JwksBuilder ordering, Display/Debug output, clone semantics, and
//! private-material-safety in Debug output.

use serde_json::Value;
use uselesskey_core_jwk::{
    AnyJwk, EcPrivateJwk, EcPublicJwk, Jwks, JwksBuilder, OctJwk, OkpPrivateJwk, OkpPublicJwk,
    PrivateJwk, PublicJwk, RsaPrivateJwk, RsaPublicJwk,
};

// ── helpers ──────────────────────────────────────────────────────────

fn rsa_public(kid: &str) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "test-n".to_string(),
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
        x: "test-x".to_string(),
        y: "test-y".to_string(),
    })
}

fn okp_public(kid: &str) -> PublicJwk {
    PublicJwk::Okp(OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "test-x".to_string(),
    })
}

fn oct_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.to_string(),
        k: "test-secret".to_string(),
    })
}

fn rsa_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Rsa(RsaPrivateJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "n".to_string(),
        e: "e".to_string(),
        d: "secret-d".to_string(),
        p: "secret-p".to_string(),
        q: "secret-q".to_string(),
        dp: "secret-dp".to_string(),
        dq: "secret-dq".to_string(),
        qi: "secret-qi".to_string(),
    })
}

fn ec_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Ec(EcPrivateJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: "x".to_string(),
        y: "y".to_string(),
        d: "secret-d".to_string(),
    })
}

fn okp_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Okp(OkpPrivateJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "x".to_string(),
        d: "secret-d".to_string(),
    })
}

// ── construction & kid ───────────────────────────────────────────────

#[test]
fn rsa_public_jwk_kid_accessor() {
    let jwk = rsa_public("rsa-kid-1");
    assert_eq!(jwk.kid(), "rsa-kid-1");
}

#[test]
fn ec_public_jwk_kid_accessor() {
    let jwk = ec_public("ec-kid-1");
    assert_eq!(jwk.kid(), "ec-kid-1");
}

#[test]
fn okp_public_jwk_kid_accessor() {
    let jwk = okp_public("okp-kid-1");
    assert_eq!(jwk.kid(), "okp-kid-1");
}

#[test]
fn private_jwk_kid_all_variants() {
    assert_eq!(rsa_private("rsa").kid(), "rsa");
    assert_eq!(ec_private("ec").kid(), "ec");
    assert_eq!(okp_private("okp").kid(), "okp");
    assert_eq!(oct_private("oct").kid(), "oct");
}

// ── serialization round-trips ────────────────────────────────────────

#[test]
fn public_jwk_to_value_contains_kty() {
    let rsa = rsa_public("k1");
    assert_eq!(rsa.to_value()["kty"], "RSA");

    let ec = ec_public("k2");
    assert_eq!(ec.to_value()["kty"], "EC");

    let okp = okp_public("k3");
    assert_eq!(okp.to_value()["kty"], "OKP");
}

#[test]
fn public_jwk_display_is_valid_json() {
    let jwk = rsa_public("display-test");
    let json_str = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json_str).expect("Display should produce valid JSON");
    assert_eq!(parsed["kid"], "display-test");
    assert_eq!(parsed["kty"], "RSA");
}

#[test]
fn private_jwk_to_value_round_trip() {
    let jwk = oct_private("oct-rt");
    let val = jwk.to_value();
    assert_eq!(val["kty"], "oct");
    assert_eq!(val["kid"], "oct-rt");
    assert_eq!(val["alg"], "HS256");
}

#[test]
fn private_jwk_display_is_valid_json() {
    let jwk = ec_private("ec-display");
    let json_str = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json_str).expect("Display should produce valid JSON");
    assert_eq!(parsed["kid"], "ec-display");
    assert_eq!(parsed["crv"], "P-256");
}

#[test]
fn rsa_public_serializes_use_as_use() {
    let jwk = rsa_public("use-test");
    let val = jwk.to_value();
    assert_eq!(val["use"], "sig");
    assert!(val.get("use_").is_none());
}

// ── AnyJwk conversion and kid ────────────────────────────────────────

#[test]
fn any_jwk_from_public_preserves_kid() {
    let pub_jwk = rsa_public("any-pub");
    let any: AnyJwk = pub_jwk.into();
    assert_eq!(any.kid(), "any-pub");
}

#[test]
fn any_jwk_from_private_preserves_kid() {
    let priv_jwk = oct_private("any-priv");
    let any: AnyJwk = priv_jwk.into();
    assert_eq!(any.kid(), "any-priv");
}

#[test]
fn any_jwk_to_value_and_display_agree() {
    let any = AnyJwk::from(okp_public("agree-test"));
    let from_value = any.to_value();
    let from_display: Value =
        serde_json::from_str(&any.to_string()).expect("Display should produce valid JSON");
    assert_eq!(from_value, from_display);
}

// ── Jwks and JwksBuilder ─────────────────────────────────────────────

#[test]
fn jwks_direct_construction_serializes_keys_array() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::from(rsa_public("k1")),
            AnyJwk::from(ec_public("k2")),
        ],
    };
    let val = jwks.to_value();
    let keys = val["keys"].as_array().expect("should have keys array");
    assert_eq!(keys.len(), 2);
}

#[test]
fn jwks_display_produces_valid_json() {
    let jwks = Jwks {
        keys: vec![AnyJwk::from(okp_public("disp-jwks"))],
    };
    let json_str = jwks.to_string();
    let parsed: Value =
        serde_json::from_str(&json_str).expect("JWKS Display should produce valid JSON");
    assert_eq!(parsed["keys"][0]["kid"], "disp-jwks");
}

#[test]
fn jwks_builder_sorts_by_kid() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("charlie"))
        .add_public(ec_public("alice"))
        .add_public(okp_public("bob"))
        .build();

    assert_eq!(jwks.keys.len(), 3);
    assert_eq!(jwks.keys[0].kid(), "alice");
    assert_eq!(jwks.keys[1].kid(), "bob");
    assert_eq!(jwks.keys[2].kid(), "charlie");
}

#[test]
fn jwks_builder_preserves_insertion_order_for_same_kid() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("same-kid"))
        .add_public(ec_public("same-kid"))
        .build();

    assert_eq!(jwks.keys.len(), 2);
    assert_eq!(jwks.keys[0].to_value()["kty"], "RSA");
    assert_eq!(jwks.keys[1].to_value()["kty"], "EC");
}

#[test]
fn jwks_builder_add_private_and_add_any() {
    let jwks = JwksBuilder::new()
        .add_private(oct_private("priv-kid"))
        .add_any(AnyJwk::from(rsa_public("any-kid")))
        .build();

    assert_eq!(jwks.keys.len(), 2);
}

#[test]
fn jwks_builder_push_methods_return_self() {
    let mut builder = JwksBuilder::new();
    builder
        .push_public(rsa_public("a"))
        .push_private(oct_private("b"))
        .push_any(AnyJwk::from(ec_public("c")));
    let jwks = builder.build();
    assert_eq!(jwks.keys.len(), 3);
}

// ── Debug safety ─────────────────────────────────────────────────────

#[test]
fn debug_rsa_private_does_not_leak_material() {
    let jwk = rsa_private("safe-rsa");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("RsaPrivateJwk"));
    assert!(!dbg.contains("secret-d"));
    assert!(!dbg.contains("secret-p"));
    assert!(!dbg.contains("secret-q"));
}

#[test]
fn debug_ec_private_does_not_leak_material() {
    let jwk = ec_private("safe-ec");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("EcPrivateJwk"));
    assert!(!dbg.contains("secret-d"));
}

#[test]
fn debug_okp_private_does_not_leak_material() {
    let jwk = okp_private("safe-okp");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("OkpPrivateJwk"));
    assert!(!dbg.contains("secret-d"));
}

#[test]
fn debug_oct_does_not_leak_k_value() {
    let jwk = oct_private("safe-oct");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("OctJwk"));
    assert!(!dbg.contains("test-secret"));
}

// ── clone ────────────────────────────────────────────────────────────

#[test]
fn public_jwk_clone_is_equal_by_serialization() {
    let original = rsa_public("clone-test");
    let cloned = original.clone();
    assert_eq!(original.to_value(), cloned.to_value());
    assert_eq!(original.kid(), cloned.kid());
}
