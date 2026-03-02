//! Mutant-killing tests for JWK shape types.

use serde_json::Value;
use uselesskey_core_jwk_shape::{
    AnyJwk, EcPrivateJwk, EcPublicJwk, Jwks, OctJwk, OkpPrivateJwk, OkpPublicJwk, PrivateJwk,
    PublicJwk, RsaPrivateJwk, RsaPublicJwk,
};

fn rsa_public(kid: &str) -> RsaPublicJwk {
    RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "test-n".to_string(),
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
        x: "test-x".to_string(),
        y: "test-y".to_string(),
    }
}

fn okp_public(kid: &str) -> OkpPublicJwk {
    OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "test-x".to_string(),
    }
}

fn rsa_private(kid: &str) -> RsaPrivateJwk {
    RsaPrivateJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "n".to_string(),
        e: "e".to_string(),
        d: "PRIVATE".to_string(),
        p: "p".to_string(),
        q: "q".to_string(),
        dp: "dp".to_string(),
        dq: "dq".to_string(),
        qi: "qi".to_string(),
    }
}

fn ec_private(kid: &str) -> EcPrivateJwk {
    EcPrivateJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: "x".to_string(),
        y: "y".to_string(),
        d: "PRIVATE".to_string(),
    }
}

fn okp_private(kid: &str) -> OkpPrivateJwk {
    OkpPrivateJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "x".to_string(),
        d: "PRIVATE".to_string(),
    }
}

fn oct_private(kid: &str) -> OctJwk {
    OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.to_string(),
        k: "PRIVATE".to_string(),
    }
}

// ── kid() accessor tests ─────────────────────────────────────────

#[test]
fn rsa_public_kid_returns_field() {
    assert_eq!(rsa_public("rsa-1").kid(), "rsa-1");
}

#[test]
fn ec_public_kid_returns_field() {
    assert_eq!(ec_public("ec-1").kid(), "ec-1");
}

#[test]
fn okp_public_kid_returns_field() {
    assert_eq!(okp_public("okp-1").kid(), "okp-1");
}

#[test]
fn rsa_private_kid_returns_field() {
    assert_eq!(rsa_private("rsa-p").kid(), "rsa-p");
}

#[test]
fn ec_private_kid_returns_field() {
    assert_eq!(ec_private("ec-p").kid(), "ec-p");
}

#[test]
fn okp_private_kid_returns_field() {
    assert_eq!(okp_private("okp-p").kid(), "okp-p");
}

#[test]
fn oct_kid_returns_field() {
    assert_eq!(oct_private("oct-1").kid(), "oct-1");
}

// ── PublicJwk enum kid() dispatch ────────────────────────────────

#[test]
fn public_jwk_rsa_kid() {
    let jwk = PublicJwk::Rsa(rsa_public("rsa-enum"));
    assert_eq!(jwk.kid(), "rsa-enum");
}

#[test]
fn public_jwk_ec_kid() {
    let jwk = PublicJwk::Ec(ec_public("ec-enum"));
    assert_eq!(jwk.kid(), "ec-enum");
}

#[test]
fn public_jwk_okp_kid() {
    let jwk = PublicJwk::Okp(okp_public("okp-enum"));
    assert_eq!(jwk.kid(), "okp-enum");
}

// ── PrivateJwk enum kid() dispatch ───────────────────────────────

#[test]
fn private_jwk_rsa_kid() {
    let jwk = PrivateJwk::Rsa(rsa_private("rsa-pe"));
    assert_eq!(jwk.kid(), "rsa-pe");
}

#[test]
fn private_jwk_ec_kid() {
    let jwk = PrivateJwk::Ec(ec_private("ec-pe"));
    assert_eq!(jwk.kid(), "ec-pe");
}

#[test]
fn private_jwk_okp_kid() {
    let jwk = PrivateJwk::Okp(okp_private("okp-pe"));
    assert_eq!(jwk.kid(), "okp-pe");
}

#[test]
fn private_jwk_oct_kid() {
    let jwk = PrivateJwk::Oct(oct_private("oct-pe"));
    assert_eq!(jwk.kid(), "oct-pe");
}

// ── AnyJwk enum kid() dispatch ───────────────────────────────────

#[test]
fn any_jwk_public_kid() {
    let any = AnyJwk::Public(PublicJwk::Rsa(rsa_public("any-pub")));
    assert_eq!(any.kid(), "any-pub");
}

#[test]
fn any_jwk_private_kid() {
    let any = AnyJwk::Private(PrivateJwk::Oct(oct_private("any-priv")));
    assert_eq!(any.kid(), "any-priv");
}

// ── to_value() field checks ──────────────────────────────────────

#[test]
fn rsa_public_to_value_kty() {
    let jwk = PublicJwk::Rsa(rsa_public("k"));
    let v = jwk.to_value();
    assert_eq!(v["kty"], "RSA");
    assert_eq!(v["use"], "sig");
    assert_eq!(v["alg"], "RS256");
    assert_eq!(v["kid"], "k");
    assert_eq!(v["e"], "AQAB");
}

#[test]
fn ec_public_to_value_fields() {
    let jwk = PublicJwk::Ec(ec_public("k"));
    let v = jwk.to_value();
    assert_eq!(v["kty"], "EC");
    assert_eq!(v["crv"], "P-256");
    assert_eq!(v["alg"], "ES256");
}

#[test]
fn okp_public_to_value_fields() {
    let jwk = PublicJwk::Okp(okp_public("k"));
    let v = jwk.to_value();
    assert_eq!(v["kty"], "OKP");
    assert_eq!(v["crv"], "Ed25519");
    assert_eq!(v["alg"], "EdDSA");
}

#[test]
fn oct_to_value_fields() {
    let jwk = PrivateJwk::Oct(oct_private("k"));
    let v = jwk.to_value();
    assert_eq!(v["kty"], "oct");
    assert_eq!(v["alg"], "HS256");
}

// ── Debug omits private material ─────────────────────────────────

#[test]
fn rsa_private_debug_omits_d() {
    let jwk = rsa_private("k");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("RsaPrivateJwk"));
    assert!(dbg.contains("kid"));
    assert!(dbg.contains("alg"));
    assert!(!dbg.contains("PRIVATE"));
}

#[test]
fn ec_private_debug_omits_d() {
    let jwk = ec_private("k");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("EcPrivateJwk"));
    assert!(dbg.contains("crv"));
    assert!(!dbg.contains("PRIVATE"));
}

#[test]
fn okp_private_debug_omits_d() {
    let jwk = okp_private("k");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("OkpPrivateJwk"));
    assert!(dbg.contains("crv"));
    assert!(!dbg.contains("PRIVATE"));
}

#[test]
fn oct_debug_omits_k() {
    let jwk = oct_private("k");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("OctJwk"));
    assert!(!dbg.contains("PRIVATE"));
}

// ── PrivateJwk Debug dispatches to inner ─────────────────────────

#[test]
fn private_jwk_debug_rsa_dispatches() {
    let jwk = PrivateJwk::Rsa(rsa_private("k"));
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("RsaPrivateJwk"));
}

#[test]
fn private_jwk_debug_ec_dispatches() {
    let jwk = PrivateJwk::Ec(ec_private("k"));
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("EcPrivateJwk"));
}

#[test]
fn private_jwk_debug_okp_dispatches() {
    let jwk = PrivateJwk::Okp(okp_private("k"));
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("OkpPrivateJwk"));
}

#[test]
fn private_jwk_debug_oct_dispatches() {
    let jwk = PrivateJwk::Oct(oct_private("k"));
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("OctJwk"));
}

// ── Display produces valid JSON ──────────────────────────────────

#[test]
fn public_jwk_display_is_valid_json() {
    let jwk = PublicJwk::Rsa(rsa_public("k"));
    let json = jwk.to_string();
    let v: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["kty"], "RSA");
}

#[test]
fn private_jwk_display_is_valid_json() {
    let jwk = PrivateJwk::Oct(oct_private("k"));
    let json = jwk.to_string();
    let v: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["kty"], "oct");
}

#[test]
fn any_jwk_display_is_valid_json() {
    let any = AnyJwk::from(PublicJwk::Ec(ec_public("k")));
    let json = any.to_string();
    let v: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["kty"], "EC");
}

// ── Jwks ─────────────────────────────────────────────────────────

#[test]
fn jwks_to_value_has_keys_array() {
    let jwks = Jwks {
        keys: vec![AnyJwk::Public(PublicJwk::Rsa(rsa_public("k1")))],
    };
    let v = jwks.to_value();
    assert!(v["keys"].is_array());
    assert_eq!(v["keys"].as_array().unwrap().len(), 1);
}

#[test]
fn jwks_display_is_valid_json() {
    let jwks = Jwks {
        keys: vec![AnyJwk::Public(PublicJwk::Rsa(rsa_public("k1")))],
    };
    let json = jwks.to_string();
    let v: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["keys"][0]["kid"], "k1");
}

// ── From conversions ─────────────────────────────────────────────

#[test]
fn from_public_jwk_to_any_jwk() {
    let public = PublicJwk::Okp(okp_public("from-pub"));
    let any = AnyJwk::from(public);
    assert_eq!(any.kid(), "from-pub");
    // Verify it's the Public variant by checking to_value has no "d" field
    assert!(any.to_value().get("d").is_none());
}

#[test]
fn from_private_jwk_to_any_jwk() {
    let private = PrivateJwk::Oct(oct_private("from-priv"));
    let any = AnyJwk::from(private);
    assert_eq!(any.kid(), "from-priv");
    assert!(any.to_value().get("k").is_some());
}
