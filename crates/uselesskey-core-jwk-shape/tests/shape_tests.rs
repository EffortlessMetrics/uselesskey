//! Comprehensive tests for the `uselesskey-core-jwk-shape` crate.

use serde_json::Value;
use uselesskey_core_jwk_shape::{
    AnyJwk, EcPrivateJwk, EcPublicJwk, Jwks, OctJwk, OkpPrivateJwk, OkpPublicJwk, PrivateJwk,
    PublicJwk, RsaPrivateJwk, RsaPublicJwk,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn rsa_public(kid: &str) -> RsaPublicJwk {
    RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "modulus-base64url".to_string(),
        e: "AQAB".to_string(),
    }
}

fn rsa_private(kid: &str) -> RsaPrivateJwk {
    RsaPrivateJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "n-val".to_string(),
        e: "AQAB".to_string(),
        d: "private-d".to_string(),
        p: "prime-p".to_string(),
        q: "prime-q".to_string(),
        dp: "dp-val".to_string(),
        dq: "dq-val".to_string(),
        qi: "qi-val".to_string(),
    }
}

fn ec_public(kid: &str) -> EcPublicJwk {
    EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: "x-coord".to_string(),
        y: "y-coord".to_string(),
    }
}

fn ec_private(kid: &str) -> EcPrivateJwk {
    EcPrivateJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: "x-coord".to_string(),
        y: "y-coord".to_string(),
        d: "private-d".to_string(),
    }
}

fn okp_public(kid: &str) -> OkpPublicJwk {
    OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "x-coord".to_string(),
    }
}

fn okp_private(kid: &str) -> OkpPrivateJwk {
    OkpPrivateJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "x-coord".to_string(),
        d: "private-d".to_string(),
    }
}

fn oct_jwk(kid: &str) -> OctJwk {
    OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.to_string(),
        k: "secret-key-material".to_string(),
    }
}

// ---------------------------------------------------------------------------
// 1. JWK shape construction
// ---------------------------------------------------------------------------

#[test]
fn rsa_public_jwk_construction() {
    let jwk = rsa_public("rsa-pub-1");
    assert_eq!(jwk.kty, "RSA");
    assert_eq!(jwk.use_, "sig");
    assert_eq!(jwk.alg, "RS256");
    assert_eq!(jwk.kid(), "rsa-pub-1");
    assert_eq!(jwk.n, "modulus-base64url");
    assert_eq!(jwk.e, "AQAB");
}

#[test]
fn rsa_private_jwk_construction() {
    let jwk = rsa_private("rsa-priv-1");
    assert_eq!(jwk.kty, "RSA");
    assert_eq!(jwk.kid(), "rsa-priv-1");
    assert_eq!(jwk.d, "private-d");
    assert_eq!(jwk.p, "prime-p");
    assert_eq!(jwk.q, "prime-q");
    assert_eq!(jwk.dp, "dp-val");
    assert_eq!(jwk.dq, "dq-val");
    assert_eq!(jwk.qi, "qi-val");
}

#[test]
fn ec_public_jwk_construction() {
    let jwk = ec_public("ec-pub-1");
    assert_eq!(jwk.kty, "EC");
    assert_eq!(jwk.crv, "P-256");
    assert_eq!(jwk.kid(), "ec-pub-1");
    assert_eq!(jwk.x, "x-coord");
    assert_eq!(jwk.y, "y-coord");
}

#[test]
fn ec_private_jwk_construction() {
    let jwk = ec_private("ec-priv-1");
    assert_eq!(jwk.kty, "EC");
    assert_eq!(jwk.crv, "P-256");
    assert_eq!(jwk.alg, "ES256");
    assert_eq!(jwk.kid(), "ec-priv-1");
}

#[test]
fn okp_public_jwk_construction() {
    let jwk = okp_public("okp-pub-1");
    assert_eq!(jwk.kty, "OKP");
    assert_eq!(jwk.crv, "Ed25519");
    assert_eq!(jwk.kid(), "okp-pub-1");
}

#[test]
fn okp_private_jwk_construction() {
    let jwk = okp_private("okp-priv-1");
    assert_eq!(jwk.kty, "OKP");
    assert_eq!(jwk.crv, "Ed25519");
    assert_eq!(jwk.alg, "EdDSA");
    assert_eq!(jwk.kid(), "okp-priv-1");
}

#[test]
fn oct_jwk_construction() {
    let jwk = oct_jwk("oct-1");
    assert_eq!(jwk.kty, "oct");
    assert_eq!(jwk.alg, "HS256");
    assert_eq!(jwk.kid(), "oct-1");
    assert_eq!(jwk.k, "secret-key-material");
}

// ---------------------------------------------------------------------------
// 2. JSON serialization / deserialization roundtrip
// ---------------------------------------------------------------------------

#[test]
fn rsa_public_json_roundtrip() {
    let jwk = PublicJwk::Rsa(rsa_public("rsa-rt"));
    let json = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["kty"], "RSA");
    assert_eq!(parsed["kid"], "rsa-rt");
    assert_eq!(parsed["n"], "modulus-base64url");
    assert_eq!(parsed["e"], "AQAB");

    // to_value should match the Display roundtrip
    assert_eq!(jwk.to_value(), parsed);
}

#[test]
fn rsa_private_json_roundtrip() {
    let jwk = PrivateJwk::Rsa(rsa_private("rsa-priv-rt"));
    let json = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["kty"], "RSA");
    assert_eq!(parsed["kid"], "rsa-priv-rt");
    assert_eq!(parsed["d"], "private-d");
    assert_eq!(parsed["qi"], "qi-val");

    assert_eq!(jwk.to_value(), parsed);
}

#[test]
fn ec_public_json_roundtrip() {
    let jwk = PublicJwk::Ec(ec_public("ec-rt"));
    let json = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["kty"], "EC");
    assert_eq!(parsed["crv"], "P-256");
    assert_eq!(parsed["kid"], "ec-rt");

    assert_eq!(jwk.to_value(), parsed);
}

#[test]
fn ec_private_json_roundtrip() {
    let jwk = PrivateJwk::Ec(ec_private("ec-priv-rt"));
    let json = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["kty"], "EC");
    assert_eq!(parsed["d"], "private-d");

    assert_eq!(jwk.to_value(), parsed);
}

#[test]
fn okp_public_json_roundtrip() {
    let jwk = PublicJwk::Okp(okp_public("okp-rt"));
    let json = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["kty"], "OKP");
    assert_eq!(parsed["crv"], "Ed25519");
    assert_eq!(parsed["x"], "x-coord");

    assert_eq!(jwk.to_value(), parsed);
}

#[test]
fn okp_private_json_roundtrip() {
    let jwk = PrivateJwk::Okp(okp_private("okp-priv-rt"));
    let json = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["kty"], "OKP");
    assert_eq!(parsed["d"], "private-d");

    assert_eq!(jwk.to_value(), parsed);
}

#[test]
fn oct_json_roundtrip() {
    let jwk = PrivateJwk::Oct(oct_jwk("oct-rt"));
    let json = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["kty"], "oct");
    assert_eq!(parsed["k"], "secret-key-material");

    assert_eq!(jwk.to_value(), parsed);
}

#[test]
fn any_jwk_json_roundtrip_public() {
    let any = AnyJwk::from(PublicJwk::Rsa(rsa_public("any-pub")));
    let json = any.to_string();
    let parsed: Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["kid"], "any-pub");
    assert_eq!(any.to_value(), parsed);
}

#[test]
fn any_jwk_json_roundtrip_private() {
    let any = AnyJwk::from(PrivateJwk::Oct(oct_jwk("any-priv")));
    let json = any.to_string();
    let parsed: Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["kid"], "any-priv");
    assert_eq!(any.to_value(), parsed);
}

// ---------------------------------------------------------------------------
// 3. Required fields are present (kty, use, alg, kid)
// ---------------------------------------------------------------------------

#[test]
fn rsa_public_required_fields_present() {
    let v = PublicJwk::Rsa(rsa_public("req-rsa")).to_value();
    assert!(v.get("kty").is_some(), "kty missing");
    assert!(v.get("use").is_some(), "use missing");
    assert!(v.get("alg").is_some(), "alg missing");
    assert!(v.get("kid").is_some(), "kid missing");
    assert!(v.get("n").is_some(), "n missing");
    assert!(v.get("e").is_some(), "e missing");
}

#[test]
fn rsa_private_required_fields_present() {
    let v = PrivateJwk::Rsa(rsa_private("req-rsa-priv")).to_value();
    for field in ["kty", "use", "alg", "kid", "n", "e", "d", "p", "q", "dp", "dq", "qi"] {
        assert!(v.get(field).is_some(), "field {field} missing");
    }
}

#[test]
fn ec_public_required_fields_present() {
    let v = PublicJwk::Ec(ec_public("req-ec")).to_value();
    for field in ["kty", "use", "alg", "kid", "crv", "x", "y"] {
        assert!(v.get(field).is_some(), "field {field} missing");
    }
}

#[test]
fn ec_private_required_fields_present() {
    let v = PrivateJwk::Ec(ec_private("req-ec-priv")).to_value();
    for field in ["kty", "use", "alg", "kid", "crv", "x", "y", "d"] {
        assert!(v.get(field).is_some(), "field {field} missing");
    }
}

#[test]
fn okp_public_required_fields_present() {
    let v = PublicJwk::Okp(okp_public("req-okp")).to_value();
    for field in ["kty", "use", "alg", "kid", "crv", "x"] {
        assert!(v.get(field).is_some(), "field {field} missing");
    }
}

#[test]
fn okp_private_required_fields_present() {
    let v = PrivateJwk::Okp(okp_private("req-okp-priv")).to_value();
    for field in ["kty", "use", "alg", "kid", "crv", "x", "d"] {
        assert!(v.get(field).is_some(), "field {field} missing");
    }
}

#[test]
fn oct_required_fields_present() {
    let v = PrivateJwk::Oct(oct_jwk("req-oct")).to_value();
    for field in ["kty", "use", "alg", "kid", "k"] {
        assert!(v.get(field).is_some(), "field {field} missing");
    }
}

// ---------------------------------------------------------------------------
// 4. Serde rename: `use_` serialized as `"use"`
// ---------------------------------------------------------------------------

#[test]
fn use_field_is_serialized_as_use_not_use_underscore() {
    let v = PublicJwk::Rsa(rsa_public("use-rename")).to_value();
    assert!(v.get("use").is_some(), "should serialize as 'use'");
    assert!(v.get("use_").is_none(), "should not have 'use_' key");
}

#[test]
fn qi_field_is_serialized_correctly() {
    let v = PrivateJwk::Rsa(rsa_private("qi-check")).to_value();
    assert!(v.get("qi").is_some(), "should serialize as 'qi'");
}

// ---------------------------------------------------------------------------
// 5. Different key types (kty values)
// ---------------------------------------------------------------------------

#[test]
fn kty_rsa_public() {
    let v = PublicJwk::Rsa(rsa_public("kty-rsa")).to_value();
    assert_eq!(v["kty"], "RSA");
}

#[test]
fn kty_ec_public() {
    let v = PublicJwk::Ec(ec_public("kty-ec")).to_value();
    assert_eq!(v["kty"], "EC");
}

#[test]
fn kty_okp_public() {
    let v = PublicJwk::Okp(okp_public("kty-okp")).to_value();
    assert_eq!(v["kty"], "OKP");
}

#[test]
fn kty_oct_private() {
    let v = PrivateJwk::Oct(oct_jwk("kty-oct")).to_value();
    assert_eq!(v["kty"], "oct");
}

#[test]
fn ec_p384_curve() {
    let jwk = EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES384",
        crv: "P-384",
        kid: "ec-384".to_string(),
        x: "x".to_string(),
        y: "y".to_string(),
    };
    let v = serde_json::to_value(&jwk).expect("serialize");
    assert_eq!(v["crv"], "P-384");
    assert_eq!(v["alg"], "ES384");
}

// ---------------------------------------------------------------------------
// 6. Display/Debug format doesn't leak key material
// ---------------------------------------------------------------------------

#[test]
fn debug_rsa_private_omits_key_material() {
    let jwk = rsa_private("dbg-rsa");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("RsaPrivateJwk"), "should contain type name");
    assert!(dbg.contains("dbg-rsa"), "should contain kid");
    for secret in ["private-d", "prime-p", "prime-q", "dp-val", "dq-val", "qi-val", "n-val"] {
        assert!(!dbg.contains(secret), "leaked {secret} in Debug output");
    }
}

#[test]
fn debug_ec_private_omits_key_material() {
    let jwk = ec_private("dbg-ec");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("EcPrivateJwk"));
    assert!(dbg.contains("dbg-ec"));
    assert!(!dbg.contains("private-d"), "leaked d in Debug output");
    assert!(!dbg.contains("x-coord"), "leaked x in Debug output");
}

#[test]
fn debug_okp_private_omits_key_material() {
    let jwk = okp_private("dbg-okp");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("OkpPrivateJwk"));
    assert!(dbg.contains("dbg-okp"));
    assert!(!dbg.contains("private-d"), "leaked d in Debug output");
    assert!(!dbg.contains("x-coord"), "leaked x in Debug output");
}

#[test]
fn debug_oct_omits_key_material() {
    let jwk = oct_jwk("dbg-oct");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("OctJwk"));
    assert!(dbg.contains("dbg-oct"));
    assert!(
        !dbg.contains("secret-key-material"),
        "leaked k in Debug output"
    );
}

#[test]
fn debug_private_jwk_enum_omits_all_secrets() {
    let secret = "top-secret-material";

    let rsa = PrivateJwk::Rsa(RsaPrivateJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: "enum-rsa".to_string(),
        n: secret.to_string(),
        e: secret.to_string(),
        d: secret.to_string(),
        p: secret.to_string(),
        q: secret.to_string(),
        dp: secret.to_string(),
        dq: secret.to_string(),
        qi: secret.to_string(),
    });
    assert!(!format!("{rsa:?}").contains(secret));

    let ec = PrivateJwk::Ec(EcPrivateJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: "enum-ec".to_string(),
        x: secret.to_string(),
        y: secret.to_string(),
        d: secret.to_string(),
    });
    assert!(!format!("{ec:?}").contains(secret));

    let okp = PrivateJwk::Okp(OkpPrivateJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: "enum-okp".to_string(),
        x: secret.to_string(),
        d: secret.to_string(),
    });
    assert!(!format!("{okp:?}").contains(secret));

    let oct = PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: "enum-oct".to_string(),
        k: secret.to_string(),
    });
    assert!(!format!("{oct:?}").contains(secret));
}

// ---------------------------------------------------------------------------
// 7. JWKS collection
// ---------------------------------------------------------------------------

#[test]
fn jwks_empty_serializes_to_empty_keys_array() {
    let jwks = Jwks { keys: vec![] };
    let v = jwks.to_value();
    assert_eq!(v["keys"].as_array().unwrap().len(), 0);
}

#[test]
fn jwks_to_value_and_display_agree() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::from(PublicJwk::Rsa(rsa_public("jwks-1"))),
            AnyJwk::from(PrivateJwk::Oct(oct_jwk("jwks-2"))),
        ],
    };
    let from_value = jwks.to_value();
    let from_display: Value = serde_json::from_str(&jwks.to_string()).expect("valid JSON");
    assert_eq!(from_value, from_display);
}

#[test]
fn jwks_mixed_key_types() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::from(PublicJwk::Rsa(rsa_public("mix-rsa"))),
            AnyJwk::from(PublicJwk::Ec(ec_public("mix-ec"))),
            AnyJwk::from(PublicJwk::Okp(okp_public("mix-okp"))),
            AnyJwk::from(PrivateJwk::Oct(oct_jwk("mix-oct"))),
        ],
    };
    let v = jwks.to_value();
    let keys = v["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 4);
    assert_eq!(keys[0]["kty"], "RSA");
    assert_eq!(keys[1]["kty"], "EC");
    assert_eq!(keys[2]["kty"], "OKP");
    assert_eq!(keys[3]["kty"], "oct");
}

// ---------------------------------------------------------------------------
// 8. Clone works
// ---------------------------------------------------------------------------

#[test]
fn all_types_are_cloneable() {
    let rsa_pub = rsa_public("clone-rsa");
    let cloned = rsa_pub.clone();
    assert_eq!(rsa_pub.kid(), cloned.kid());

    let any = AnyJwk::from(PublicJwk::Rsa(rsa_pub));
    let any_cloned = any.clone();
    assert_eq!(any.kid(), any_cloned.kid());

    let jwks = Jwks {
        keys: vec![any_cloned],
    };
    let jwks_cloned = jwks.clone();
    assert_eq!(jwks.keys.len(), jwks_cloned.keys.len());
}

// ---------------------------------------------------------------------------
// 9. From conversions
// ---------------------------------------------------------------------------

#[test]
fn from_public_jwk_into_any_jwk() {
    let public = PublicJwk::Ec(ec_public("from-ec"));
    let any: AnyJwk = public.into();
    assert_eq!(any.kid(), "from-ec");
}

#[test]
fn from_private_jwk_into_any_jwk() {
    let private = PrivateJwk::Okp(okp_private("from-okp"));
    let any: AnyJwk = private.into();
    assert_eq!(any.kid(), "from-okp");
}
