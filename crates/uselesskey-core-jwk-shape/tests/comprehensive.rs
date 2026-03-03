//! Comprehensive tests for `uselesskey-core-jwk-shape`.
//!
//! Covers: shape construction for all key types, serialization roundtrips,
//! JWKS building, serde field renaming, Debug safety (no key leakage),
//! Display/to_value consistency, From conversions, Clone, and edge cases.

use serde_json::Value;
use uselesskey_core_jwk_shape::{
    AnyJwk, EcPrivateJwk, EcPublicJwk, Jwks, OctJwk, OkpPrivateJwk, OkpPublicJwk, PrivateJwk,
    PublicJwk, RsaPrivateJwk, RsaPublicJwk,
};

// ── Helpers ─────────────────────────────────────────────────────────────

fn rsa_public(kid: &str) -> RsaPublicJwk {
    RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: format!("n-{kid}"),
        e: "AQAB".to_string(),
    }
}

fn rsa_private(kid: &str) -> RsaPrivateJwk {
    RsaPrivateJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "modulus".to_string(),
        e: "AQAB".to_string(),
        d: "priv-d".to_string(),
        p: "prime-p".to_string(),
        q: "prime-q".to_string(),
        dp: "dp-exp".to_string(),
        dq: "dq-exp".to_string(),
        qi: "qi-coeff".to_string(),
    }
}

fn ec_public(kid: &str) -> EcPublicJwk {
    EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: format!("x-{kid}"),
        y: format!("y-{kid}"),
    }
}

fn ec_private(kid: &str) -> EcPrivateJwk {
    EcPrivateJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: "ec-x".to_string(),
        y: "ec-y".to_string(),
        d: "ec-d-secret".to_string(),
    }
}

fn okp_public(kid: &str) -> OkpPublicJwk {
    OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: format!("x-{kid}"),
    }
}

fn okp_private(kid: &str) -> OkpPrivateJwk {
    OkpPrivateJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "okp-x".to_string(),
        d: "okp-d-secret".to_string(),
    }
}

fn oct_jwk(kid: &str) -> OctJwk {
    OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.to_string(),
        k: format!("k-{kid}"),
    }
}

// ── 1. Shape construction: all key types ────────────────────────────────

#[test]
fn rsa_public_construction_and_accessors() {
    let jwk = rsa_public("rsa-1");
    assert_eq!(jwk.kty, "RSA");
    assert_eq!(jwk.use_, "sig");
    assert_eq!(jwk.alg, "RS256");
    assert_eq!(jwk.kid(), "rsa-1");
    assert_eq!(jwk.n, "n-rsa-1");
    assert_eq!(jwk.e, "AQAB");
}

#[test]
fn rsa_private_construction_and_crt_fields() {
    let jwk = rsa_private("rsa-priv-1");
    assert_eq!(jwk.kty, "RSA");
    assert_eq!(jwk.kid(), "rsa-priv-1");
    assert_eq!(jwk.d, "priv-d");
    assert_eq!(jwk.p, "prime-p");
    assert_eq!(jwk.q, "prime-q");
    assert_eq!(jwk.dp, "dp-exp");
    assert_eq!(jwk.dq, "dq-exp");
    assert_eq!(jwk.qi, "qi-coeff");
}

#[test]
fn ec_public_construction_with_curve() {
    let jwk = ec_public("ec-1");
    assert_eq!(jwk.kty, "EC");
    assert_eq!(jwk.crv, "P-256");
    assert_eq!(jwk.alg, "ES256");
    assert_eq!(jwk.kid(), "ec-1");
    assert_eq!(jwk.x, "x-ec-1");
    assert_eq!(jwk.y, "y-ec-1");
}

#[test]
fn ec_p384_construction() {
    let jwk = EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES384",
        crv: "P-384",
        kid: "ec-384".to_string(),
        x: "x384".to_string(),
        y: "y384".to_string(),
    };
    assert_eq!(jwk.crv, "P-384");
    assert_eq!(jwk.alg, "ES384");
}

#[test]
fn okp_public_construction() {
    let jwk = okp_public("okp-1");
    assert_eq!(jwk.kty, "OKP");
    assert_eq!(jwk.crv, "Ed25519");
    assert_eq!(jwk.alg, "EdDSA");
    assert_eq!(jwk.kid(), "okp-1");
}

#[test]
fn okp_private_construction() {
    let jwk = okp_private("okp-priv-1");
    assert_eq!(jwk.kty, "OKP");
    assert_eq!(jwk.crv, "Ed25519");
    assert_eq!(jwk.kid(), "okp-priv-1");
    assert_eq!(jwk.d, "okp-d-secret");
}

#[test]
fn oct_construction() {
    let jwk = oct_jwk("oct-1");
    assert_eq!(jwk.kty, "oct");
    assert_eq!(jwk.alg, "HS256");
    assert_eq!(jwk.kid(), "oct-1");
    assert_eq!(jwk.k, "k-oct-1");
}

#[test]
fn oct_hs384_construction() {
    let jwk = OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS384",
        kid: "hs384".to_string(),
        k: "secret384".to_string(),
    };
    assert_eq!(jwk.alg, "HS384");
}

#[test]
fn oct_hs512_construction() {
    let jwk = OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS512",
        kid: "hs512".to_string(),
        k: "secret512".to_string(),
    };
    assert_eq!(jwk.alg, "HS512");
}

// ── 2. PublicJwk / PrivateJwk / AnyJwk enum wrappers ────────────────────

#[test]
fn public_jwk_kid_dispatches_to_inner() {
    assert_eq!(PublicJwk::Rsa(rsa_public("r")).kid(), "r");
    assert_eq!(PublicJwk::Ec(ec_public("e")).kid(), "e");
    assert_eq!(PublicJwk::Okp(okp_public("o")).kid(), "o");
}

#[test]
fn private_jwk_kid_dispatches_to_inner() {
    assert_eq!(PrivateJwk::Rsa(rsa_private("r")).kid(), "r");
    assert_eq!(PrivateJwk::Ec(ec_private("e")).kid(), "e");
    assert_eq!(PrivateJwk::Okp(okp_private("o")).kid(), "o");
    assert_eq!(PrivateJwk::Oct(oct_jwk("h")).kid(), "h");
}

#[test]
fn any_jwk_kid_dispatches_through_public() {
    let any = AnyJwk::Public(PublicJwk::Rsa(rsa_public("pub-k")));
    assert_eq!(any.kid(), "pub-k");
}

#[test]
fn any_jwk_kid_dispatches_through_private() {
    let any = AnyJwk::Private(PrivateJwk::Oct(oct_jwk("priv-k")));
    assert_eq!(any.kid(), "priv-k");
}

// ── 3. Serialization roundtrips ─────────────────────────────────────────

#[test]
fn rsa_public_serde_roundtrip() {
    let jwk = PublicJwk::Rsa(rsa_public("rt-rsa"));
    let json = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(jwk.to_value(), parsed);
}

#[test]
fn rsa_private_serde_roundtrip() {
    let jwk = PrivateJwk::Rsa(rsa_private("rt-rsa-priv"));
    let json = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(jwk.to_value(), parsed);
}

#[test]
fn ec_public_serde_roundtrip() {
    let jwk = PublicJwk::Ec(ec_public("rt-ec"));
    let json = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(jwk.to_value(), parsed);
}

#[test]
fn ec_private_serde_roundtrip() {
    let jwk = PrivateJwk::Ec(ec_private("rt-ec-priv"));
    let json = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(jwk.to_value(), parsed);
}

#[test]
fn okp_public_serde_roundtrip() {
    let jwk = PublicJwk::Okp(okp_public("rt-okp"));
    let json = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(jwk.to_value(), parsed);
}

#[test]
fn okp_private_serde_roundtrip() {
    let jwk = PrivateJwk::Okp(okp_private("rt-okp-priv"));
    let json = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(jwk.to_value(), parsed);
}

#[test]
fn oct_serde_roundtrip() {
    let jwk = PrivateJwk::Oct(oct_jwk("rt-oct"));
    let json = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(jwk.to_value(), parsed);
}

#[test]
fn any_jwk_public_serde_roundtrip() {
    let any = AnyJwk::from(PublicJwk::Ec(ec_public("any-rt")));
    let json = any.to_string();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(any.to_value(), parsed);
}

#[test]
fn any_jwk_private_serde_roundtrip() {
    let any = AnyJwk::from(PrivateJwk::Oct(oct_jwk("any-priv-rt")));
    let json = any.to_string();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(any.to_value(), parsed);
}

#[test]
fn deterministic_serialization_all_types() {
    let items: Vec<Box<dyn Fn() -> String>> = vec![
        Box::new(|| serde_json::to_string(&rsa_public("d")).unwrap()),
        Box::new(|| serde_json::to_string(&rsa_private("d")).unwrap()),
        Box::new(|| serde_json::to_string(&ec_public("d")).unwrap()),
        Box::new(|| serde_json::to_string(&ec_private("d")).unwrap()),
        Box::new(|| serde_json::to_string(&okp_public("d")).unwrap()),
        Box::new(|| serde_json::to_string(&okp_private("d")).unwrap()),
        Box::new(|| serde_json::to_string(&oct_jwk("d")).unwrap()),
    ];

    for make_json in &items {
        assert_eq!(
            make_json(),
            make_json(),
            "deterministic serialization failed"
        );
    }
}

// ── 4. Serde rename attributes ──────────────────────────────────────────

#[test]
fn use_field_serialized_as_use_for_rsa_public() {
    let v = serde_json::to_value(rsa_public("u")).unwrap();
    assert!(v.get("use").is_some());
    assert!(v.get("use_").is_none());
}

#[test]
fn use_field_serialized_as_use_for_ec_public() {
    let v = serde_json::to_value(ec_public("u")).unwrap();
    assert!(v.get("use").is_some());
    assert!(v.get("use_").is_none());
}

#[test]
fn use_field_serialized_as_use_for_okp_public() {
    let v = serde_json::to_value(okp_public("u")).unwrap();
    assert!(v.get("use").is_some());
    assert!(v.get("use_").is_none());
}

#[test]
fn use_field_serialized_as_use_for_oct() {
    let v = serde_json::to_value(oct_jwk("u")).unwrap();
    assert!(v.get("use").is_some());
    assert!(v.get("use_").is_none());
}

#[test]
fn qi_field_serialized_correctly_in_rsa_private() {
    let v = serde_json::to_value(rsa_private("qi")).unwrap();
    assert!(v.get("qi").is_some());
}

#[test]
fn untagged_serialization_no_variant_wrapper() {
    let pub_v = serde_json::to_value(PublicJwk::Rsa(rsa_public("u"))).unwrap();
    assert!(pub_v.get("Rsa").is_none());

    let priv_v = serde_json::to_value(PrivateJwk::Oct(oct_jwk("u"))).unwrap();
    assert!(priv_v.get("Oct").is_none());

    let any_v = serde_json::to_value(AnyJwk::from(PublicJwk::Ec(ec_public("u")))).unwrap();
    assert!(any_v.get("Public").is_none());
}

// ── 5. JSON field counts (structural correctness) ───────────────────────

#[test]
fn rsa_public_has_six_fields() {
    let v = serde_json::to_value(rsa_public("fc")).unwrap();
    assert_eq!(v.as_object().unwrap().len(), 6);
}

#[test]
fn rsa_private_has_twelve_fields() {
    let v = serde_json::to_value(rsa_private("fc")).unwrap();
    assert_eq!(v.as_object().unwrap().len(), 12);
}

#[test]
fn ec_public_has_seven_fields() {
    let v = serde_json::to_value(ec_public("fc")).unwrap();
    assert_eq!(v.as_object().unwrap().len(), 7);
}

#[test]
fn ec_private_has_eight_fields() {
    let v = serde_json::to_value(ec_private("fc")).unwrap();
    assert_eq!(v.as_object().unwrap().len(), 8);
}

#[test]
fn okp_public_has_six_fields() {
    let v = serde_json::to_value(okp_public("fc")).unwrap();
    assert_eq!(v.as_object().unwrap().len(), 6);
}

#[test]
fn okp_private_has_seven_fields() {
    let v = serde_json::to_value(okp_private("fc")).unwrap();
    assert_eq!(v.as_object().unwrap().len(), 7);
}

#[test]
fn oct_has_five_fields() {
    let v = serde_json::to_value(oct_jwk("fc")).unwrap();
    assert_eq!(v.as_object().unwrap().len(), 5);
}

// ── 6. Debug safety: no key material leakage ────────────────────────────

#[test]
fn rsa_private_debug_omits_all_secrets() {
    let jwk = rsa_private("dbg-rsa");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("RsaPrivateJwk"));
    assert!(dbg.contains("dbg-rsa"));
    for secret in [
        "priv-d", "prime-p", "prime-q", "dp-exp", "dq-exp", "qi-coeff",
    ] {
        assert!(!dbg.contains(secret), "leaked {secret}");
    }
}

#[test]
fn ec_private_debug_omits_d() {
    let jwk = ec_private("dbg-ec");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("EcPrivateJwk"));
    assert!(!dbg.contains("ec-d-secret"));
}

#[test]
fn okp_private_debug_omits_d() {
    let jwk = okp_private("dbg-okp");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("OkpPrivateJwk"));
    assert!(!dbg.contains("okp-d-secret"));
}

#[test]
fn oct_debug_omits_k() {
    let jwk = oct_jwk("dbg-oct");
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("OctJwk"));
    assert!(!dbg.contains("k-dbg-oct"));
}

#[test]
fn private_jwk_enum_debug_delegates_to_inner() {
    let rsa = PrivateJwk::Rsa(rsa_private("d-rsa"));
    assert!(format!("{rsa:?}").contains("RsaPrivateJwk"));

    let ec = PrivateJwk::Ec(ec_private("d-ec"));
    assert!(format!("{ec:?}").contains("EcPrivateJwk"));

    let okp = PrivateJwk::Okp(okp_private("d-okp"));
    assert!(format!("{okp:?}").contains("OkpPrivateJwk"));

    let oct = PrivateJwk::Oct(oct_jwk("d-oct"));
    assert!(format!("{oct:?}").contains("OctJwk"));
}

#[test]
fn debug_uses_finish_non_exhaustive() {
    // finish_non_exhaustive produces `..` in output
    let dbg = format!("{:?}", rsa_private("ne"));
    assert!(dbg.contains(".."), "expected finish_non_exhaustive marker");
}

// ── 7. Display produces valid JSON ──────────────────────────────────────

#[test]
fn public_jwk_display_all_variants_valid_json() {
    let variants: Vec<PublicJwk> = vec![
        PublicJwk::Rsa(rsa_public("d1")),
        PublicJwk::Ec(ec_public("d2")),
        PublicJwk::Okp(okp_public("d3")),
    ];
    for jwk in &variants {
        let json = jwk.to_string();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["kid"], jwk.kid());
    }
}

#[test]
fn private_jwk_display_all_variants_valid_json() {
    let variants: Vec<PrivateJwk> = vec![
        PrivateJwk::Rsa(rsa_private("d1")),
        PrivateJwk::Ec(ec_private("d2")),
        PrivateJwk::Okp(okp_private("d3")),
        PrivateJwk::Oct(oct_jwk("d4")),
    ];
    for jwk in &variants {
        let json = jwk.to_string();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["kid"], jwk.kid());
    }
}

#[test]
fn any_jwk_display_valid_json() {
    let any_pub = AnyJwk::from(PublicJwk::Rsa(rsa_public("dp")));
    let parsed: Value = serde_json::from_str(&any_pub.to_string()).unwrap();
    assert_eq!(parsed["kid"], "dp");

    let any_priv = AnyJwk::from(PrivateJwk::Oct(oct_jwk("dpr")));
    let parsed: Value = serde_json::from_str(&any_priv.to_string()).unwrap();
    assert_eq!(parsed["kid"], "dpr");
}

// ── 8. Display and to_value consistency ─────────────────────────────────

#[test]
fn display_and_to_value_agree_for_public_jwk() {
    let jwk = PublicJwk::Okp(okp_public("agree"));
    let from_display: Value = serde_json::from_str(&jwk.to_string()).unwrap();
    assert_eq!(from_display, jwk.to_value());
}

#[test]
fn display_and_to_value_agree_for_private_jwk() {
    let jwk = PrivateJwk::Ec(ec_private("agree"));
    let from_display: Value = serde_json::from_str(&jwk.to_string()).unwrap();
    assert_eq!(from_display, jwk.to_value());
}

#[test]
fn display_and_to_value_agree_for_any_jwk() {
    let any = AnyJwk::from(PublicJwk::Rsa(rsa_public("agree")));
    let from_display: Value = serde_json::from_str(&any.to_string()).unwrap();
    assert_eq!(from_display, any.to_value());
}

// ── 9. JWKS collection ──────────────────────────────────────────────────

#[test]
fn jwks_empty_collection() {
    let jwks = Jwks { keys: vec![] };
    let v = jwks.to_value();
    assert!(v["keys"].as_array().unwrap().is_empty());
}

#[test]
fn jwks_single_public_key() {
    let jwks = Jwks {
        keys: vec![AnyJwk::from(PublicJwk::Rsa(rsa_public("single")))],
    };
    let v = jwks.to_value();
    assert_eq!(v["keys"].as_array().unwrap().len(), 1);
    assert_eq!(v["keys"][0]["kid"], "single");
}

#[test]
fn jwks_single_private_key() {
    let jwks = Jwks {
        keys: vec![AnyJwk::from(PrivateJwk::Oct(oct_jwk("single-priv")))],
    };
    let v = jwks.to_value();
    assert_eq!(v["keys"].as_array().unwrap().len(), 1);
    assert_eq!(v["keys"][0]["kty"], "oct");
}

#[test]
fn jwks_mixed_public_and_private_keys() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::from(PublicJwk::Rsa(rsa_public("pub-rsa"))),
            AnyJwk::from(PublicJwk::Ec(ec_public("pub-ec"))),
            AnyJwk::from(PublicJwk::Okp(okp_public("pub-okp"))),
            AnyJwk::from(PrivateJwk::Rsa(rsa_private("priv-rsa"))),
            AnyJwk::from(PrivateJwk::Ec(ec_private("priv-ec"))),
            AnyJwk::from(PrivateJwk::Okp(okp_private("priv-okp"))),
            AnyJwk::from(PrivateJwk::Oct(oct_jwk("priv-oct"))),
        ],
    };
    let v = jwks.to_value();
    assert_eq!(v["keys"].as_array().unwrap().len(), 7);
}

#[test]
fn jwks_display_is_valid_json() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::from(PublicJwk::Rsa(rsa_public("j1"))),
            AnyJwk::from(PrivateJwk::Oct(oct_jwk("j2"))),
        ],
    };
    let json = jwks.to_string();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["keys"].is_array());
    assert_eq!(parsed["keys"].as_array().unwrap().len(), 2);
}

#[test]
fn jwks_display_and_to_value_agree() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::from(PublicJwk::Ec(ec_public("ag1"))),
            AnyJwk::from(PublicJwk::Okp(okp_public("ag2"))),
        ],
    };
    let from_display: Value = serde_json::from_str(&jwks.to_string()).unwrap();
    assert_eq!(from_display, jwks.to_value());
}

#[test]
fn jwks_serde_roundtrip() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::from(PublicJwk::Rsa(rsa_public("sr1"))),
            AnyJwk::from(PrivateJwk::Ec(ec_private("sr2"))),
            AnyJwk::from(PublicJwk::Okp(okp_public("sr3"))),
        ],
    };
    let json_str = serde_json::to_string(&jwks).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();
    let direct = jwks.to_value();
    assert_eq!(parsed, direct);
}

#[test]
fn jwks_deterministic_serialization() {
    let build = || Jwks {
        keys: vec![
            AnyJwk::from(PublicJwk::Rsa(rsa_public("det-1"))),
            AnyJwk::from(PrivateJwk::Oct(oct_jwk("det-2"))),
        ],
    };
    assert_eq!(
        serde_json::to_string(&build()).unwrap(),
        serde_json::to_string(&build()).unwrap(),
    );
}

#[test]
fn jwks_duplicate_kids_serialized_as_separate_entries() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::from(PublicJwk::Rsa(rsa_public("dup"))),
            AnyJwk::from(PublicJwk::Ec(ec_public("dup"))),
        ],
    };
    let v = jwks.to_value();
    let keys = v["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["kid"], "dup");
    assert_eq!(keys[1]["kid"], "dup");
    // Distinct kty values prove they are different keys
    assert_ne!(keys[0]["kty"], keys[1]["kty"]);
}

// ── 10. From conversions ────────────────────────────────────────────────

#[test]
fn from_public_to_any_preserves_value() {
    let public = PublicJwk::Rsa(rsa_public("from-rsa"));
    let original_value = public.to_value();
    let any = AnyJwk::from(public);
    assert_eq!(any.to_value(), original_value);
}

#[test]
fn from_private_to_any_preserves_value() {
    let private = PrivateJwk::Oct(oct_jwk("from-oct"));
    let original_value = private.to_value();
    let any = AnyJwk::from(private);
    assert_eq!(any.to_value(), original_value);
}

#[test]
fn into_any_jwk_from_public() {
    let public = PublicJwk::Ec(ec_public("into-ec"));
    let any: AnyJwk = public.into();
    assert_eq!(any.kid(), "into-ec");
}

#[test]
fn into_any_jwk_from_private() {
    let private = PrivateJwk::Okp(okp_private("into-okp"));
    let any: AnyJwk = private.into();
    assert_eq!(any.kid(), "into-okp");
}

// ── 11. Clone ───────────────────────────────────────────────────────────

#[test]
fn rsa_public_clone_is_equal() {
    let jwk = rsa_public("clone");
    let cloned = jwk.clone();
    assert_eq!(jwk.kid(), cloned.kid());
    assert_eq!(
        serde_json::to_value(jwk).unwrap(),
        serde_json::to_value(cloned).unwrap(),
    );
}

#[test]
fn public_jwk_enum_clone_preserves_value() {
    let jwk = PublicJwk::Ec(ec_public("clone-ec"));
    let cloned = jwk.clone();
    assert_eq!(jwk.to_value(), cloned.to_value());
}

#[test]
fn private_jwk_enum_clone_preserves_value() {
    let jwk = PrivateJwk::Oct(oct_jwk("clone-oct"));
    let cloned = jwk.clone();
    assert_eq!(jwk.to_value(), cloned.to_value());
}

#[test]
fn any_jwk_clone_preserves_value() {
    let any = AnyJwk::from(PublicJwk::Okp(okp_public("clone-any")));
    let cloned = any.clone();
    assert_eq!(any.to_value(), cloned.to_value());
}

#[test]
fn jwks_clone_preserves_keys() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::from(PublicJwk::Rsa(rsa_public("c1"))),
            AnyJwk::from(PrivateJwk::Oct(oct_jwk("c2"))),
        ],
    };
    let cloned = jwks.clone();
    assert_eq!(jwks.keys.len(), cloned.keys.len());
    assert_eq!(
        serde_json::to_string(&jwks).unwrap(),
        serde_json::to_string(&cloned).unwrap(),
    );
}

// ── 12. Edge cases ──────────────────────────────────────────────────────

#[test]
fn kid_with_unicode_characters() {
    let jwk = PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: "キー-1".to_string(),
        n: "n".to_string(),
        e: "AQAB".to_string(),
    });
    assert_eq!(jwk.kid(), "キー-1");
    let v = jwk.to_value();
    assert_eq!(v["kid"], "キー-1");
}

#[test]
fn kid_with_empty_string() {
    let jwk = PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: String::new(),
        n: "n".to_string(),
        e: "AQAB".to_string(),
    });
    assert_eq!(jwk.kid(), "");
    let v = jwk.to_value();
    assert_eq!(v["kid"], "");
}

#[test]
fn large_jwks_with_many_keys() {
    let keys: Vec<AnyJwk> = (0..100)
        .map(|i| AnyJwk::from(PublicJwk::Rsa(rsa_public(&format!("key-{i:03}")))))
        .collect();
    let jwks = Jwks { keys };

    let v = jwks.to_value();
    assert_eq!(v["keys"].as_array().unwrap().len(), 100);

    // Verify roundtrip
    let json = jwks.to_string();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["keys"].as_array().unwrap().len(), 100);
}

#[test]
fn jwks_json_structure_has_only_keys_field() {
    let jwks = Jwks {
        keys: vec![AnyJwk::from(PublicJwk::Rsa(rsa_public("s")))],
    };
    let v = jwks.to_value();
    let obj = v.as_object().unwrap();
    assert_eq!(obj.len(), 1, "JWKS should only have 'keys' field");
    assert!(obj.contains_key("keys"));
}

#[test]
fn to_value_returns_object_for_all_jwk_types() {
    let vals: Vec<Value> = vec![
        PublicJwk::Rsa(rsa_public("v")).to_value(),
        PublicJwk::Ec(ec_public("v")).to_value(),
        PublicJwk::Okp(okp_public("v")).to_value(),
        PrivateJwk::Rsa(rsa_private("v")).to_value(),
        PrivateJwk::Ec(ec_private("v")).to_value(),
        PrivateJwk::Okp(okp_private("v")).to_value(),
        PrivateJwk::Oct(oct_jwk("v")).to_value(),
        AnyJwk::from(PublicJwk::Rsa(rsa_public("v"))).to_value(),
        AnyJwk::from(PrivateJwk::Oct(oct_jwk("v"))).to_value(),
    ];
    for v in &vals {
        assert!(v.is_object(), "to_value must return a JSON object");
    }
}
