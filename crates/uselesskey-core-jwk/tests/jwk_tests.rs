//! Comprehensive tests for the `uselesskey-core-jwk` facade crate.
//!
//! Covers JwksBuilder ordering, serialization round-trips, type traits,
//! and property-based invariants.

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

fn rsa_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Rsa(RsaPrivateJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "test-n".to_string(),
        e: "AQAB".to_string(),
        d: "test-d".to_string(),
        p: "test-p".to_string(),
        q: "test-q".to_string(),
        dp: "test-dp".to_string(),
        dq: "test-dq".to_string(),
        qi: "test-qi".to_string(),
    })
}

fn ec_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Ec(EcPrivateJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: "test-x".to_string(),
        y: "test-y".to_string(),
        d: "test-d".to_string(),
    })
}

fn okp_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Okp(OkpPrivateJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "test-x".to_string(),
        d: "test-d".to_string(),
    })
}

fn oct_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.to_string(),
        k: "test-k".to_string(),
    })
}

// ── JwksBuilder tests ────────────────────────────────────────────────

#[test]
fn builder_empty_produces_empty_jwks() {
    let jwks = JwksBuilder::new().build();
    assert!(jwks.keys.is_empty());
}

#[test]
fn builder_single_public_entry() {
    let jwks = JwksBuilder::new().add_public(rsa_public("only")).build();
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].kid(), "only");
}

#[test]
fn builder_single_private_entry() {
    let jwks = JwksBuilder::new()
        .add_private(oct_private("single"))
        .build();
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].kid(), "single");
}

#[test]
fn builder_orders_by_kid_ascending() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("charlie"))
        .add_public(ec_public("alpha"))
        .add_public(okp_public("bravo"))
        .build();

    let kids: Vec<&str> = jwks.keys.iter().map(|k| k.kid()).collect();
    assert_eq!(kids, vec!["alpha", "bravo", "charlie"]);
}

#[test]
fn builder_mixed_public_private_ordered_by_kid() {
    let jwks = JwksBuilder::new()
        .add_private(oct_private("zulu"))
        .add_public(rsa_public("alpha"))
        .add_private(rsa_private("mike"))
        .add_public(ec_public("delta"))
        .build();

    let kids: Vec<&str> = jwks.keys.iter().map(|k| k.kid()).collect();
    assert_eq!(kids, vec!["alpha", "delta", "mike", "zulu"]);
}

#[test]
fn builder_duplicate_kids_preserve_insertion_order() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("dup"))
        .add_public(ec_public("dup"))
        .add_public(okp_public("dup"))
        .build();

    assert_eq!(jwks.keys.len(), 3);
    // All have the same kid
    for key in &jwks.keys {
        assert_eq!(key.kid(), "dup");
    }
    // Insertion order preserved: RSA first, EC second, OKP third
    assert_eq!(jwks.keys[0].to_value()["kty"], "RSA");
    assert_eq!(jwks.keys[1].to_value()["kty"], "EC");
    assert_eq!(jwks.keys[2].to_value()["kty"], "OKP");
}

#[test]
fn builder_add_any_works() {
    let any = AnyJwk::from(rsa_public("via-any"));
    let jwks = JwksBuilder::new().add_any(any).build();
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].kid(), "via-any");
}

#[test]
fn builder_push_methods_return_self_for_chaining() {
    let mut builder = JwksBuilder::new();
    builder
        .push_public(rsa_public("b"))
        .push_private(oct_private("a"))
        .push_any(AnyJwk::from(ec_public("c")));

    let jwks = builder.build();
    let kids: Vec<&str> = jwks.keys.iter().map(|k| k.kid()).collect();
    assert_eq!(kids, vec!["a", "b", "c"]);
}

#[test]
fn builder_all_key_types_together() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("rsa-pub"))
        .add_public(ec_public("ec-pub"))
        .add_public(okp_public("okp-pub"))
        .add_private(rsa_private("rsa-priv"))
        .add_private(ec_private("ec-priv"))
        .add_private(okp_private("okp-priv"))
        .add_private(oct_private("oct-priv"))
        .build();

    assert_eq!(jwks.keys.len(), 7);
    // Verify all keys sorted by kid
    let kids: Vec<&str> = jwks.keys.iter().map(|k| k.kid()).collect();
    let mut sorted_kids = kids.clone();
    sorted_kids.sort();
    assert_eq!(kids, sorted_kids);
}

// ── Serialization tests ──────────────────────────────────────────────

#[test]
fn jwk_serializes_to_valid_json() {
    let jwk = rsa_public("ser-test");
    let json_str = jwk.to_string();
    let parsed: Value = serde_json::from_str(&json_str).expect("valid JSON");

    assert_eq!(parsed["kty"], "RSA");
    assert_eq!(parsed["kid"], "ser-test");
    assert_eq!(parsed["use"], "sig");
    assert_eq!(parsed["alg"], "RS256");
}

#[test]
fn jwks_serializes_with_keys_array() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("k1"))
        .add_public(ec_public("k2"))
        .build();

    let json_str = jwks.to_string();
    let parsed: Value = serde_json::from_str(&json_str).expect("valid JSON");

    assert!(parsed["keys"].is_array());
    assert_eq!(parsed["keys"].as_array().unwrap().len(), 2);
}

#[test]
fn jwks_to_value_matches_to_string() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("k1"))
        .add_private(oct_private("k2"))
        .build();

    let from_value = jwks.to_value();
    let from_string: Value = serde_json::from_str(&jwks.to_string()).expect("valid JSON");
    assert_eq!(from_value, from_string);
}

#[test]
fn to_value_roundtrip_preserves_public_fields() {
    let jwk = ec_public("ec-rt");
    let val = jwk.to_value();

    assert_eq!(val["kty"], "EC");
    assert_eq!(val["kid"], "ec-rt");
    assert_eq!(val["alg"], "ES256");
    assert_eq!(val["crv"], "P-256");
    assert_eq!(val["use"], "sig");
    assert_eq!(val["x"], "test-x");
    assert_eq!(val["y"], "test-y");
}

#[test]
fn to_value_roundtrip_preserves_private_fields() {
    let jwk = rsa_private("rsa-rt");
    let val = jwk.to_value();

    assert_eq!(val["kty"], "RSA");
    assert_eq!(val["kid"], "rsa-rt");
    assert_eq!(val["alg"], "RS256");
    assert_eq!(val["n"], "test-n");
    assert_eq!(val["e"], "AQAB");
    assert_eq!(val["d"], "test-d");
    assert_eq!(val["p"], "test-p");
    assert_eq!(val["q"], "test-q");
    assert_eq!(val["dp"], "test-dp");
    assert_eq!(val["dq"], "test-dq");
    assert_eq!(val["qi"], "test-qi");
}

#[test]
fn okp_public_serialization() {
    let jwk = okp_public("okp-ser");
    let val = jwk.to_value();

    assert_eq!(val["kty"], "OKP");
    assert_eq!(val["crv"], "Ed25519");
    assert_eq!(val["kid"], "okp-ser");
    assert_eq!(val["alg"], "EdDSA");
}

#[test]
fn oct_serialization_includes_k_field() {
    let jwk = oct_private("oct-ser");
    let val = jwk.to_value();

    assert_eq!(val["kty"], "oct");
    assert_eq!(val["kid"], "oct-ser");
    assert_eq!(val["k"], "test-k");
    assert_eq!(val["alg"], "HS256");
}

#[test]
fn empty_jwks_serializes_to_empty_keys_array() {
    let jwks = JwksBuilder::new().build();
    let val = jwks.to_value();
    assert_eq!(val["keys"].as_array().unwrap().len(), 0);
}

// ── Snapshot tests ───────────────────────────────────────────────────

#[test]
fn snapshot_rsa_public_jwk() {
    let jwk = rsa_public("snap-rsa");
    let val = jwk.to_value();
    insta::assert_yaml_snapshot!("rsa_public_jwk", val, {
        ".n" => "[REDACTED]",
        ".e" => "[REDACTED]",
    });
}

#[test]
fn snapshot_ec_public_jwk() {
    let jwk = ec_public("snap-ec");
    let val = jwk.to_value();
    insta::assert_yaml_snapshot!("ec_public_jwk", val, {
        ".x" => "[REDACTED]",
        ".y" => "[REDACTED]",
    });
}

#[test]
fn snapshot_okp_public_jwk() {
    let jwk = okp_public("snap-okp");
    let val = jwk.to_value();
    insta::assert_yaml_snapshot!("okp_public_jwk", val, {
        ".x" => "[REDACTED]",
    });
}

#[test]
fn snapshot_jwks_multi_key() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("key-b"))
        .add_public(ec_public("key-a"))
        .add_private(oct_private("key-c"))
        .build();
    let val = jwks.to_value();
    insta::assert_yaml_snapshot!("jwks_multi_key", val, {
        ".keys[].n" => "[REDACTED]",
        ".keys[].e" => "[REDACTED]",
        ".keys[].x" => "[REDACTED]",
        ".keys[].y" => "[REDACTED]",
        ".keys[].k" => "[REDACTED]",
    });
}

// ── Type trait tests ─────────────────────────────────────────────────

#[test]
fn clone_produces_independent_copy() {
    let original = rsa_public("clone-test");
    let cloned = original.clone();
    assert_eq!(original.kid(), cloned.kid());
    assert_eq!(original.to_value(), cloned.to_value());
}

#[test]
fn clone_jwks_is_independent() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("a"))
        .add_public(ec_public("b"))
        .build();
    let cloned = jwks.clone();
    assert_eq!(jwks.keys.len(), cloned.keys.len());
    assert_eq!(jwks.to_value(), cloned.to_value());
}

#[test]
fn debug_rsa_private_omits_key_material() {
    let jwk = RsaPrivateJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: "debug-test".to_string(),
        n: "secret-n".to_string(),
        e: "secret-e".to_string(),
        d: "secret-d".to_string(),
        p: "secret-p".to_string(),
        q: "secret-q".to_string(),
        dp: "secret-dp".to_string(),
        dq: "secret-dq".to_string(),
        qi: "secret-qi".to_string(),
    };
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("RsaPrivateJwk"));
    assert!(dbg.contains("debug-test"));
    assert!(!dbg.contains("secret-n"));
    assert!(!dbg.contains("secret-d"));
    assert!(!dbg.contains("secret-p"));
}

#[test]
fn debug_ec_private_omits_key_material() {
    let jwk = EcPrivateJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: "ec-debug".to_string(),
        x: "secret-x".to_string(),
        y: "secret-y".to_string(),
        d: "secret-d".to_string(),
    };
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("EcPrivateJwk"));
    assert!(!dbg.contains("secret-x"));
    assert!(!dbg.contains("secret-d"));
}

#[test]
fn debug_okp_private_omits_key_material() {
    let jwk = OkpPrivateJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: "okp-debug".to_string(),
        x: "secret-x".to_string(),
        d: "secret-d".to_string(),
    };
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("OkpPrivateJwk"));
    assert!(!dbg.contains("secret-x"));
    assert!(!dbg.contains("secret-d"));
}

#[test]
fn debug_oct_omits_key_material() {
    let jwk = OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: "oct-debug".to_string(),
        k: "secret-k".to_string(),
    };
    let dbg = format!("{jwk:?}");
    assert!(dbg.contains("OctJwk"));
    assert!(!dbg.contains("secret-k"));
}

#[test]
fn debug_private_jwk_enum_delegates_to_inner() {
    let rsa = rsa_private("dbg-rsa");
    let ec = ec_private("dbg-ec");
    let okp = okp_private("dbg-okp");
    let oct = oct_private("dbg-oct");

    assert!(format!("{rsa:?}").contains("RsaPrivateJwk"));
    assert!(format!("{ec:?}").contains("EcPrivateJwk"));
    assert!(format!("{okp:?}").contains("OkpPrivateJwk"));
    assert!(format!("{oct:?}").contains("OctJwk"));
}

#[test]
fn different_jwks_serialize_differently() {
    let a = rsa_public("kid-a").to_value();
    let b = rsa_public("kid-b").to_value();
    assert_ne!(a, b);
}

#[test]
fn different_key_types_same_kid_serialize_differently() {
    let rsa = rsa_public("same-kid").to_value();
    let ec = ec_public("same-kid").to_value();
    assert_ne!(rsa, ec);
}

// ── From conversion tests ────────────────────────────────────────────

#[test]
fn any_jwk_from_public_preserves_kid() {
    let pub_jwk = rsa_public("from-pub");
    let any = AnyJwk::from(pub_jwk);
    assert_eq!(any.kid(), "from-pub");
}

#[test]
fn any_jwk_from_private_preserves_kid() {
    let priv_jwk = oct_private("from-priv");
    let any = AnyJwk::from(priv_jwk);
    assert_eq!(any.kid(), "from-priv");
}

#[test]
fn any_jwk_from_conversions_preserve_all_fields() {
    let pub_jwk = ec_public("conv-ec");
    let any = AnyJwk::from(pub_jwk);
    let val = any.to_value();
    assert_eq!(val["kty"], "EC");
    assert_eq!(val["crv"], "P-256");
    assert_eq!(val["kid"], "conv-ec");
}

// ── kid accessor tests ───────────────────────────────────────────────

#[test]
fn kid_accessors_all_variants() {
    assert_eq!(rsa_public("r").kid(), "r");
    assert_eq!(ec_public("e").kid(), "e");
    assert_eq!(okp_public("o").kid(), "o");
    assert_eq!(rsa_private("rp").kid(), "rp");
    assert_eq!(ec_private("ep").kid(), "ep");
    assert_eq!(okp_private("op").kid(), "op");
    assert_eq!(oct_private("oc").kid(), "oc");
}

#[test]
fn any_jwk_kid_delegates_correctly() {
    let pub_any = AnyJwk::from(rsa_public("any-pub"));
    let priv_any = AnyJwk::from(ec_private("any-priv"));
    assert_eq!(pub_any.kid(), "any-pub");
    assert_eq!(priv_any.kid(), "any-priv");
}

// ── Display tests ────────────────────────────────────────────────────

#[test]
fn display_public_jwk_produces_valid_json() {
    let jwk = ec_public("disp-ec");
    let json_str = format!("{jwk}");
    let parsed: Value = serde_json::from_str(&json_str).expect("valid JSON from Display");
    assert_eq!(parsed["kid"], "disp-ec");
}

#[test]
fn display_private_jwk_produces_valid_json() {
    let jwk = okp_private("disp-okp");
    let json_str = format!("{jwk}");
    let parsed: Value = serde_json::from_str(&json_str).expect("valid JSON from Display");
    assert_eq!(parsed["kid"], "disp-okp");
}

#[test]
fn display_any_jwk_produces_valid_json() {
    let any = AnyJwk::from(rsa_public("disp-any"));
    let json_str = format!("{any}");
    let parsed: Value = serde_json::from_str(&json_str).expect("valid JSON from Display");
    assert_eq!(parsed["kid"], "disp-any");
}

#[test]
fn display_jwks_produces_valid_json_with_keys() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_public("d1"))
        .add_private(oct_private("d2"))
        .build();
    let json_str = format!("{jwks}");
    let parsed: Value = serde_json::from_str(&json_str).expect("valid JSON from Display");
    assert!(parsed["keys"].is_array());
}

// ── Jwks direct construction ─────────────────────────────────────────

#[test]
fn jwks_direct_construction_works() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::from(rsa_public("direct-1")),
            AnyJwk::from(oct_private("direct-2")),
        ],
    };
    assert_eq!(jwks.keys.len(), 2);
    let val = jwks.to_value();
    assert_eq!(val["keys"].as_array().unwrap().len(), 2);
}

// ── Property tests ───────────────────────────────────────────────────

proptest::proptest! {
    #[test]
    fn builder_always_sorts_by_kid(
        kids in proptest::collection::vec("[a-z]{1,8}", 1..20),
    ) {
        let mut builder = JwksBuilder::new();
        for kid in &kids {
            builder.push_public(rsa_public(kid));
        }
        let jwks = builder.build();

        let result_kids: Vec<&str> = jwks.keys.iter().map(|k| k.kid()).collect();
        let mut expected = result_kids.clone();
        expected.sort();
        proptest::prop_assert_eq!(result_kids, expected);
    }

    #[test]
    fn serialization_roundtrip_preserves_kid(
        kid in "[a-zA-Z0-9._-]{1,24}",
    ) {
        let jwk = rsa_public(&kid);
        let json_str = jwk.to_string();
        let parsed: Value = serde_json::from_str(&json_str).expect("valid JSON");
        proptest::prop_assert_eq!(parsed["kid"].as_str().unwrap(), kid.as_str());
    }

    #[test]
    fn to_value_and_to_string_agree(
        kid in "[a-zA-Z0-9._-]{1,24}",
    ) {
        let jwk = ec_public(&kid);
        let from_value = jwk.to_value();
        let from_string: Value = serde_json::from_str(&jwk.to_string()).expect("valid JSON");
        proptest::prop_assert_eq!(from_value, from_string);
    }

    #[test]
    fn jwks_serialization_roundtrip(
        kids in proptest::collection::vec("[a-z]{1,8}", 0..10),
    ) {
        let mut builder = JwksBuilder::new();
        for kid in &kids {
            builder.push_public(rsa_public(kid));
        }
        let jwks = builder.build();

        let json_str = jwks.to_string();
        let parsed: Value = serde_json::from_str(&json_str).expect("valid JSON");
        let keys = parsed["keys"].as_array().expect("keys array");
        proptest::prop_assert_eq!(keys.len(), kids.len());
    }

    #[test]
    fn builder_preserves_insertion_order_for_same_kid(
        n in 2..10usize,
    ) {
        let mut builder = JwksBuilder::new();
        for i in 0..n {
            builder.push_public(PublicJwk::Rsa(RsaPublicJwk {
                kty: "RSA",
                use_: "sig",
                alg: "RS256",
                kid: "same".to_string(),
                n: format!("n-{i}"),
                e: "AQAB".to_string(),
            }));
        }
        let jwks = builder.build();

        for (i, key) in jwks.keys.iter().enumerate() {
            let val = key.to_value();
            proptest::prop_assert_eq!(val["n"].as_str().unwrap(), format!("n-{i}"));
        }
    }
}
