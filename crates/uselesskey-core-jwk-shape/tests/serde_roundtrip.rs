//! Serde serialization roundtrip tests for JWK shape types.
//!
//! These tests verify that:
//! - serialize → JSON string → parse as Value → field correctness
//! - deterministic serialization (same input → identical JSON)
//! - expected JSON structure (field names, rename attributes)
//! - malformed JSON is handled gracefully

use serde_json::Value;
use uselesskey_core_jwk_shape::{
    AnyJwk, EcPrivateJwk, EcPublicJwk, Jwks, OctJwk, OkpPrivateJwk, OkpPublicJwk, PrivateJwk,
    PublicJwk, RsaPrivateJwk, RsaPublicJwk,
};

// ── helpers ──────────────────────────────────────────────────────────

fn rsa_public(kid: &str) -> RsaPublicJwk {
    RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "test-modulus".to_string(),
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
        e: "e-value".to_string(),
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
        x: "x-public".to_string(),
    }
}

fn okp_private(kid: &str) -> OkpPrivateJwk {
    OkpPrivateJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "x-public".to_string(),
        d: "d-value".to_string(),
    }
}

fn oct_jwk(kid: &str) -> OctJwk {
    OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.to_string(),
        k: "k-secret".to_string(),
    }
}

// ── RsaPublicJwk ────────────────────────────────────────────────────

#[test]
fn rsa_public_jwk_json_structure() {
    let jwk = rsa_public("rsa-pub-1");
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "RSA");
    assert_eq!(v["use"], "sig", "`use_` field must serialize as `use`");
    assert_eq!(v["alg"], "RS256");
    assert_eq!(v["kid"], "rsa-pub-1");
    assert!(v["n"].is_string());
    assert!(v["e"].is_string());

    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 6, "RSA public JWK should have exactly 6 fields");
    assert!(
        !obj.contains_key("use_"),
        "raw field name `use_` must not appear"
    );
}

#[test]
fn rsa_public_jwk_roundtrip_via_value() {
    let jwk = rsa_public("roundtrip-1");

    let json_str = serde_json::to_string(&jwk).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();
    let direct_value = serde_json::to_value(&jwk).unwrap();

    assert_eq!(parsed, direct_value);
}

#[test]
fn rsa_public_jwk_deterministic() {
    let jwk = rsa_public("det-1");

    let json1 = serde_json::to_string(&jwk).unwrap();
    let json2 = serde_json::to_string(&jwk).unwrap();

    assert_eq!(json1, json2, "same input must produce identical JSON");
}

// ── RsaPrivateJwk ───────────────────────────────────────────────────

#[test]
fn rsa_private_jwk_json_structure() {
    let jwk = rsa_private("rsa-priv-1");
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "RSA");
    assert_eq!(v["use"], "sig");
    assert_eq!(v["alg"], "RS256");
    assert_eq!(v["kid"], "rsa-priv-1");

    // CRT parameters present
    for field in &["n", "e", "d", "p", "q", "dp", "dq", "qi"] {
        assert!(v[field].is_string(), "field `{field}` must be present");
    }

    let obj = v.as_object().unwrap();
    assert_eq!(
        obj.len(),
        12,
        "RSA private JWK should have exactly 12 fields"
    );
    assert!(
        obj.contains_key("qi"),
        "`qi` field must use serde rename from `qi`"
    );
}

#[test]
fn rsa_private_jwk_roundtrip_via_value() {
    let jwk = rsa_private("roundtrip-priv");
    let json_str = serde_json::to_string(&jwk).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();
    let direct = serde_json::to_value(&jwk).unwrap();
    assert_eq!(parsed, direct);
}

#[test]
fn rsa_private_jwk_deterministic() {
    let jwk = rsa_private("det-priv");
    let json1 = serde_json::to_string(&jwk).unwrap();
    let json2 = serde_json::to_string(&jwk).unwrap();
    assert_eq!(json1, json2);
}

// ── EcPublicJwk ─────────────────────────────────────────────────────

#[test]
fn ec_public_jwk_json_structure() {
    let jwk = ec_public("ec-pub-1");
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "EC");
    assert_eq!(v["use"], "sig");
    assert_eq!(v["alg"], "ES256");
    assert_eq!(v["crv"], "P-256");
    assert_eq!(v["kid"], "ec-pub-1");
    assert!(v["x"].is_string());
    assert!(v["y"].is_string());

    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 7);
}

#[test]
fn ec_public_jwk_roundtrip_via_value() {
    let jwk = ec_public("ec-rt");
    let json_str = serde_json::to_string(&jwk).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed, serde_json::to_value(&jwk).unwrap());
}

// ── EcPrivateJwk ────────────────────────────────────────────────────

#[test]
fn ec_private_jwk_json_structure() {
    let jwk = ec_private("ec-priv-1");
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "EC");
    assert_eq!(v["crv"], "P-256");
    assert!(v["d"].is_string(), "private key `d` must be present");

    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 8);
}

#[test]
fn ec_private_jwk_roundtrip_via_value() {
    let jwk = ec_private("ec-priv-rt");
    let json_str = serde_json::to_string(&jwk).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed, serde_json::to_value(&jwk).unwrap());
}

// ── OkpPublicJwk ────────────────────────────────────────────────────

#[test]
fn okp_public_jwk_json_structure() {
    let jwk = okp_public("okp-pub-1");
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "OKP");
    assert_eq!(v["use"], "sig");
    assert_eq!(v["alg"], "EdDSA");
    assert_eq!(v["crv"], "Ed25519");
    assert!(v["x"].is_string());

    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 6);
}

#[test]
fn okp_public_jwk_roundtrip_via_value() {
    let jwk = okp_public("okp-rt");
    let json_str = serde_json::to_string(&jwk).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed, serde_json::to_value(&jwk).unwrap());
}

// ── OkpPrivateJwk ───────────────────────────────────────────────────

#[test]
fn okp_private_jwk_json_structure() {
    let jwk = okp_private("okp-priv-1");
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "OKP");
    assert_eq!(v["crv"], "Ed25519");
    assert!(v["d"].is_string());
    assert!(v["x"].is_string());

    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 7);
}

#[test]
fn okp_private_jwk_roundtrip_via_value() {
    let jwk = okp_private("okp-priv-rt");
    let json_str = serde_json::to_string(&jwk).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed, serde_json::to_value(&jwk).unwrap());
}

// ── OctJwk ──────────────────────────────────────────────────────────

#[test]
fn oct_jwk_json_structure() {
    let jwk = oct_jwk("oct-1");
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "oct");
    assert_eq!(v["use"], "sig");
    assert_eq!(v["alg"], "HS256");
    assert!(v["k"].is_string());

    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 5);
}

#[test]
fn oct_jwk_roundtrip_via_value() {
    let jwk = oct_jwk("oct-rt");
    let json_str = serde_json::to_string(&jwk).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed, serde_json::to_value(&jwk).unwrap());
}

// ── PublicJwk (enum, untagged) ──────────────────────────────────────

#[test]
fn public_jwk_rsa_variant_untagged() {
    let jwk = PublicJwk::Rsa(rsa_public("pub-rsa"));
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "RSA");
    // Untagged: no wrapping "Rsa" key
    assert!(v.as_object().unwrap().contains_key("n"));
    assert!(!v.as_object().unwrap().contains_key("Rsa"));
}

#[test]
fn public_jwk_ec_variant_untagged() {
    let jwk = PublicJwk::Ec(ec_public("pub-ec"));
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "EC");
    assert!(v.as_object().unwrap().contains_key("x"));
    assert!(v.as_object().unwrap().contains_key("y"));
}

#[test]
fn public_jwk_okp_variant_untagged() {
    let jwk = PublicJwk::Okp(okp_public("pub-okp"));
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "OKP");
    assert_eq!(v["crv"], "Ed25519");
}

#[test]
fn public_jwk_all_variants_roundtrip_via_value() {
    let variants: Vec<PublicJwk> = vec![
        PublicJwk::Rsa(rsa_public("rsa")),
        PublicJwk::Ec(ec_public("ec")),
        PublicJwk::Okp(okp_public("okp")),
    ];

    for jwk in &variants {
        let json_str = serde_json::to_string(jwk).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        let direct = serde_json::to_value(jwk).unwrap();
        assert_eq!(parsed, direct, "roundtrip failed for kid={}", jwk.kid());
    }
}

// ── PrivateJwk (enum, untagged) ─────────────────────────────────────

#[test]
fn private_jwk_rsa_variant_untagged() {
    let jwk = PrivateJwk::Rsa(rsa_private("priv-rsa"));
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "RSA");
    assert!(v["d"].is_string());
    assert!(!v.as_object().unwrap().contains_key("Rsa"));
}

#[test]
fn private_jwk_ec_variant_untagged() {
    let jwk = PrivateJwk::Ec(ec_private("priv-ec"));
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "EC");
    assert!(v["d"].is_string());
}

#[test]
fn private_jwk_okp_variant_untagged() {
    let jwk = PrivateJwk::Okp(okp_private("priv-okp"));
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "OKP");
    assert!(v["d"].is_string());
}

#[test]
fn private_jwk_oct_variant_untagged() {
    let jwk = PrivateJwk::Oct(oct_jwk("priv-oct"));
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "oct");
    assert!(v["k"].is_string());
}

#[test]
fn private_jwk_all_variants_roundtrip_via_value() {
    let variants: Vec<PrivateJwk> = vec![
        PrivateJwk::Rsa(rsa_private("rsa")),
        PrivateJwk::Ec(ec_private("ec")),
        PrivateJwk::Okp(okp_private("okp")),
        PrivateJwk::Oct(oct_jwk("oct")),
    ];

    for jwk in &variants {
        let json_str = serde_json::to_string(jwk).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        let direct = serde_json::to_value(jwk).unwrap();
        assert_eq!(parsed, direct, "roundtrip failed for kid={}", jwk.kid());
    }
}

// ── AnyJwk (enum, untagged) ────────────────────────────────────────

#[test]
fn any_jwk_public_variant_untagged() {
    let jwk = AnyJwk::Public(PublicJwk::Rsa(rsa_public("any-pub")));
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "RSA");
    assert!(!v.as_object().unwrap().contains_key("Public"));
}

#[test]
fn any_jwk_private_variant_untagged() {
    let jwk = AnyJwk::Private(PrivateJwk::Oct(oct_jwk("any-priv")));
    let v = serde_json::to_value(&jwk).unwrap();

    assert_eq!(v["kty"], "oct");
    assert!(!v.as_object().unwrap().contains_key("Private"));
}

#[test]
fn any_jwk_all_variants_roundtrip_via_value() {
    let variants: Vec<AnyJwk> = vec![
        AnyJwk::Public(PublicJwk::Rsa(rsa_public("rsa"))),
        AnyJwk::Public(PublicJwk::Ec(ec_public("ec"))),
        AnyJwk::Public(PublicJwk::Okp(okp_public("okp"))),
        AnyJwk::Private(PrivateJwk::Rsa(rsa_private("rsa-priv"))),
        AnyJwk::Private(PrivateJwk::Ec(ec_private("ec-priv"))),
        AnyJwk::Private(PrivateJwk::Okp(okp_private("okp-priv"))),
        AnyJwk::Private(PrivateJwk::Oct(oct_jwk("oct-priv"))),
    ];

    for jwk in &variants {
        let json_str = serde_json::to_string(jwk).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        let direct = serde_json::to_value(jwk).unwrap();
        assert_eq!(parsed, direct, "roundtrip failed for kid={}", jwk.kid());
    }
}

// ── Jwks ────────────────────────────────────────────────────────────

#[test]
fn jwks_json_has_keys_array() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::Public(PublicJwk::Rsa(rsa_public("k1"))),
            AnyJwk::Private(PrivateJwk::Oct(oct_jwk("k2"))),
        ],
    };
    let v = serde_json::to_value(&jwks).unwrap();

    let keys = v["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["kid"], "k1");
    assert_eq!(keys[1]["kid"], "k2");
}

#[test]
fn jwks_empty_keys_roundtrip() {
    let jwks = Jwks { keys: vec![] };
    let v = serde_json::to_value(&jwks).unwrap();

    let keys = v["keys"].as_array().unwrap();
    assert!(keys.is_empty());
}

#[test]
fn jwks_roundtrip_via_value() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::Public(PublicJwk::Ec(ec_public("ec-1"))),
            AnyJwk::Public(PublicJwk::Okp(okp_public("okp-1"))),
            AnyJwk::Private(PrivateJwk::Rsa(rsa_private("rsa-1"))),
        ],
    };

    let json_str = serde_json::to_string(&jwks).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();
    let direct = serde_json::to_value(&jwks).unwrap();

    assert_eq!(parsed, direct);
}

#[test]
fn jwks_deterministic_serialization() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::Public(PublicJwk::Rsa(rsa_public("a"))),
            AnyJwk::Private(PrivateJwk::Oct(oct_jwk("b"))),
        ],
    };

    let json1 = serde_json::to_string(&jwks).unwrap();
    let json2 = serde_json::to_string(&jwks).unwrap();
    assert_eq!(json1, json2);
}

// ── Deterministic serialization (cross-type) ────────────────────────

#[test]
fn all_concrete_jwk_types_deterministic_serialization() {
    // Test each concrete type produces identical output on repeated serialization
    let json_pairs: Vec<(String, String)> = vec![
        (
            serde_json::to_string(&rsa_public("det")).unwrap(),
            serde_json::to_string(&rsa_public("det")).unwrap(),
        ),
        (
            serde_json::to_string(&rsa_private("det")).unwrap(),
            serde_json::to_string(&rsa_private("det")).unwrap(),
        ),
        (
            serde_json::to_string(&ec_public("det")).unwrap(),
            serde_json::to_string(&ec_public("det")).unwrap(),
        ),
        (
            serde_json::to_string(&ec_private("det")).unwrap(),
            serde_json::to_string(&ec_private("det")).unwrap(),
        ),
        (
            serde_json::to_string(&okp_public("det")).unwrap(),
            serde_json::to_string(&okp_public("det")).unwrap(),
        ),
        (
            serde_json::to_string(&okp_private("det")).unwrap(),
            serde_json::to_string(&okp_private("det")).unwrap(),
        ),
        (
            serde_json::to_string(&oct_jwk("det")).unwrap(),
            serde_json::to_string(&oct_jwk("det")).unwrap(),
        ),
    ];

    for (first, second) in &json_pairs {
        assert_eq!(first, second, "deterministic serialization failed");
    }
}

// ── Malformed JSON handling ─────────────────────────────────────────

#[test]
fn malformed_json_does_not_parse_as_value() {
    let bad_inputs = [
        "",
        "{",
        r#"{"kty":}"#,
        "not json at all",
        r#"{"kty": "RSA", "kid": }"#,
    ];

    for input in &bad_inputs {
        let result: Result<Value, _> = serde_json::from_str(input);
        assert!(result.is_err(), "expected error for input: {input:?}");
    }
}

#[test]
fn valid_json_missing_fields_still_parses_as_value() {
    // A minimal JSON object can be parsed as Value even if it doesn't match
    // any JWK struct — that's fine since we only have Serialize (not Deserialize).
    let minimal = r#"{"kty":"RSA"}"#;
    let v: Value = serde_json::from_str(minimal).unwrap();
    assert_eq!(v["kty"], "RSA");
    assert!(v["kid"].is_null(), "missing fields should be null in Value");
}

// ── Display and to_value consistency ────────────────────────────────

#[test]
fn display_and_to_value_produce_equivalent_json() {
    let jwk = PublicJwk::Rsa(rsa_public("display-test"));

    let from_display: Value = serde_json::from_str(&jwk.to_string()).unwrap();
    let from_to_value = jwk.to_value();

    assert_eq!(from_display, from_to_value);
}

#[test]
fn jwks_display_and_to_value_produce_equivalent_json() {
    let jwks = Jwks {
        keys: vec![AnyJwk::Public(PublicJwk::Okp(okp_public("display")))],
    };

    let from_display: Value = serde_json::from_str(&jwks.to_string()).unwrap();
    let from_to_value = jwks.to_value();

    assert_eq!(from_display, from_to_value);
}

// ── Serde rename attributes ─────────────────────────────────────────

#[test]
fn use_field_renamed_in_all_public_types() {
    let types_json: Vec<String> = vec![
        serde_json::to_string(&rsa_public("u")).unwrap(),
        serde_json::to_string(&ec_public("u")).unwrap(),
        serde_json::to_string(&okp_public("u")).unwrap(),
        serde_json::to_string(&oct_jwk("u")).unwrap(),
    ];

    for json in &types_json {
        assert!(json.contains(r#""use":"#), "must contain `use` key: {json}");
        assert!(
            !json.contains(r#""use_":"#),
            "must not contain `use_` key: {json}"
        );
    }
}

#[test]
fn qi_field_present_in_rsa_private_jwk() {
    let json = serde_json::to_string(&rsa_private("qi-test")).unwrap();
    assert!(json.contains(r#""qi":"#));
}
