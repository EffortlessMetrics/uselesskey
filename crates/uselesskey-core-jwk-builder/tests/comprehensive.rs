//! Comprehensive tests for `uselesskey-core-jwk-builder`.
//!
//! Covers: fluent API chaining, JWKS building with multiple keys,
//! kid-sorted ordering, insertion-order for duplicates, serde roundtrips,
//! and edge cases (empty JWKS, duplicate kids, single-key sets, large sets).

use serde_json::Value;
use uselesskey_core_jwk_builder::JwksBuilder;
use uselesskey_core_jwk_shape::{
    AnyJwk, EcPrivateJwk, EcPublicJwk, Jwks, OctJwk, OkpPrivateJwk, OkpPublicJwk, PrivateJwk,
    PublicJwk, RsaPrivateJwk, RsaPublicJwk,
};

// ── Helpers ─────────────────────────────────────────────────────────────

fn rsa_pub(kid: &str) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: format!("n-{kid}"),
        e: "AQAB".to_string(),
    })
}

fn ec_pub(kid: &str) -> PublicJwk {
    PublicJwk::Ec(EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: format!("x-{kid}"),
        y: format!("y-{kid}"),
    })
}

fn okp_pub(kid: &str) -> PublicJwk {
    PublicJwk::Okp(OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: format!("x-{kid}"),
    })
}

fn rsa_priv(kid: &str) -> PrivateJwk {
    PrivateJwk::Rsa(RsaPrivateJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "n".to_string(),
        e: "e".to_string(),
        d: "d".to_string(),
        p: "p".to_string(),
        q: "q".to_string(),
        dp: "dp".to_string(),
        dq: "dq".to_string(),
        qi: "qi".to_string(),
    })
}

fn ec_priv(kid: &str) -> PrivateJwk {
    PrivateJwk::Ec(EcPrivateJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: "x".to_string(),
        y: "y".to_string(),
        d: "d".to_string(),
    })
}

fn okp_priv(kid: &str) -> PrivateJwk {
    PrivateJwk::Okp(OkpPrivateJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "x".to_string(),
        d: "d".to_string(),
    })
}

fn oct_priv(kid: &str) -> PrivateJwk {
    PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.to_string(),
        k: format!("k-{kid}"),
    })
}

// ── 1. Fluent API chaining ──────────────────────────────────────────────

#[test]
fn fluent_add_public_returns_builder() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("a"))
        .add_public(ec_pub("b"))
        .add_public(okp_pub("c"))
        .build();
    assert_eq!(jwks.keys.len(), 3);
}

#[test]
fn fluent_add_private_returns_builder() {
    let jwks = JwksBuilder::new()
        .add_private(rsa_priv("a"))
        .add_private(ec_priv("b"))
        .add_private(okp_priv("c"))
        .add_private(oct_priv("d"))
        .build();
    assert_eq!(jwks.keys.len(), 4);
}

#[test]
fn fluent_add_any_returns_builder() {
    let jwks = JwksBuilder::new()
        .add_any(AnyJwk::from(rsa_pub("a")))
        .add_any(AnyJwk::from(oct_priv("b")))
        .build();
    assert_eq!(jwks.keys.len(), 2);
}

#[test]
fn fluent_mixed_add_methods_chain() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("pub-1"))
        .add_private(oct_priv("priv-1"))
        .add_any(AnyJwk::from(ec_pub("any-1")))
        .add_public(okp_pub("pub-2"))
        .add_private(ec_priv("priv-2"))
        .build();
    assert_eq!(jwks.keys.len(), 5);
}

#[test]
fn push_methods_return_mutable_self() {
    let mut builder = JwksBuilder::new();
    builder
        .push_public(rsa_pub("a"))
        .push_private(oct_priv("b"))
        .push_any(AnyJwk::from(ec_pub("c")));
    let jwks = builder.build();
    assert_eq!(jwks.keys.len(), 3);
}

// ── 2. Key ordering (kid-sorted) ────────────────────────────────────────

#[test]
fn keys_sorted_lexicographically_by_kid() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("zebra"))
        .add_public(ec_pub("apple"))
        .add_public(okp_pub("mango"))
        .build();

    let kids: Vec<&str> = jwks.keys.iter().map(AnyJwk::kid).collect();
    assert_eq!(kids, ["apple", "mango", "zebra"]);
}

#[test]
fn numeric_kids_sorted_lexicographically() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("10"))
        .add_public(rsa_pub("2"))
        .add_public(rsa_pub("1"))
        .build();

    let kids: Vec<&str> = jwks.keys.iter().map(AnyJwk::kid).collect();
    // Lexicographic: "1" < "10" < "2"
    assert_eq!(kids, ["1", "10", "2"]);
}

#[test]
fn mixed_case_kids_sorted_case_sensitive() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("Bravo"))
        .add_public(rsa_pub("alpha"))
        .add_public(rsa_pub("Charlie"))
        .build();

    let kids: Vec<&str> = jwks.keys.iter().map(AnyJwk::kid).collect();
    // ASCII: uppercase < lowercase
    assert_eq!(kids, ["Bravo", "Charlie", "alpha"]);
}

#[test]
fn single_key_preserved() {
    let jwks = JwksBuilder::new().add_public(rsa_pub("only")).build();
    assert_eq!(jwks.keys.len(), 1);
    assert_eq!(jwks.keys[0].kid(), "only");
}

// ── 3. Duplicate kid insertion-order preservation ───────────────────────

#[test]
fn duplicate_kids_preserve_insertion_order() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("same"))
        .add_public(ec_pub("same"))
        .add_public(okp_pub("same"))
        .build();

    assert_eq!(jwks.keys.len(), 3);
    // All have same kid
    for key in &jwks.keys {
        assert_eq!(key.kid(), "same");
    }
    // Insertion order preserved: RSA first, then EC, then OKP
    assert_eq!(jwks.keys[0].to_value()["kty"], "RSA");
    assert_eq!(jwks.keys[1].to_value()["kty"], "EC");
    assert_eq!(jwks.keys[2].to_value()["kty"], "OKP");
}

#[test]
fn duplicate_kids_interleaved_with_unique_kids() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("dup"))
        .add_public(ec_pub("alpha"))
        .add_public(okp_pub("dup"))
        .add_private(oct_priv("zulu"))
        .build();

    let kids: Vec<&str> = jwks.keys.iter().map(AnyJwk::kid).collect();
    assert_eq!(kids, ["alpha", "dup", "dup", "zulu"]);

    // Within the "dup" group, RSA came first in insertion order
    let dup_keys: Vec<&AnyJwk> = jwks.keys.iter().filter(|k| k.kid() == "dup").collect();
    assert_eq!(dup_keys[0].to_value()["kty"], "RSA");
    assert_eq!(dup_keys[1].to_value()["kty"], "OKP");
}

#[test]
fn many_duplicates_all_preserved() {
    let mut builder = JwksBuilder::new();
    for i in 0..10 {
        builder.push_public(PublicJwk::Rsa(RsaPublicJwk {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: "repeat".to_string(),
            n: format!("n-{i}"),
            e: "AQAB".to_string(),
        }));
    }
    let jwks = builder.build();
    assert_eq!(jwks.keys.len(), 10);

    // Verify insertion order via the n field
    for (i, key) in jwks.keys.iter().enumerate() {
        let v = key.to_value();
        assert_eq!(v["n"], format!("n-{i}"));
    }
}

// ── 4. JWKS building with multiple key types ────────────────────────────

#[test]
fn all_key_types_in_single_jwks() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("k-rsa-pub"))
        .add_public(ec_pub("k-ec-pub"))
        .add_public(okp_pub("k-okp-pub"))
        .add_private(rsa_priv("k-rsa-priv"))
        .add_private(ec_priv("k-ec-priv"))
        .add_private(okp_priv("k-okp-priv"))
        .add_private(oct_priv("k-oct"))
        .build();

    assert_eq!(jwks.keys.len(), 7);

    // Verify sorted order
    let kids: Vec<&str> = jwks.keys.iter().map(AnyJwk::kid).collect();
    let mut sorted_kids = kids.clone();
    sorted_kids.sort();
    assert_eq!(kids, sorted_kids);
}

#[test]
fn large_jwks_correctly_sorted() {
    let mut builder = JwksBuilder::new();
    let labels: Vec<String> = (0..50).rev().map(|i| format!("key-{i:03}")).collect();
    for label in &labels {
        builder.push_public(rsa_pub(label));
    }
    let jwks = builder.build();

    assert_eq!(jwks.keys.len(), 50);

    let kids: Vec<&str> = jwks.keys.iter().map(AnyJwk::kid).collect();
    let mut sorted = kids.clone();
    sorted.sort();
    assert_eq!(kids, sorted);
}

// ── 5. Serialization roundtrips ─────────────────────────────────────────

#[test]
fn builder_output_to_value_roundtrip() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("rt-1"))
        .add_private(oct_priv("rt-2"))
        .build();

    let v = jwks.to_value();
    let json_str = serde_json::to_string(&jwks).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(v, parsed);
}

#[test]
fn builder_output_display_roundtrip() {
    let jwks = JwksBuilder::new()
        .add_public(ec_pub("disp-1"))
        .add_public(okp_pub("disp-2"))
        .build();

    let display_str = jwks.to_string();
    let parsed: Value = serde_json::from_str(&display_str).unwrap();
    let to_value = jwks.to_value();

    assert_eq!(parsed, to_value);
}

#[test]
fn builder_deterministic_across_builds() {
    let build_jwks = || {
        JwksBuilder::new()
            .add_public(rsa_pub("c"))
            .add_public(ec_pub("a"))
            .add_private(oct_priv("b"))
            .build()
    };

    let json1 = serde_json::to_string(&build_jwks()).unwrap();
    let json2 = serde_json::to_string(&build_jwks()).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn jwks_json_contains_keys_array_key() {
    let jwks = JwksBuilder::new().add_public(rsa_pub("k")).build();
    let v = jwks.to_value();

    assert!(v.is_object());
    assert!(v.as_object().unwrap().contains_key("keys"));
    assert!(v["keys"].is_array());
}

#[test]
fn each_key_in_jwks_json_has_kty_and_kid() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("k1"))
        .add_public(ec_pub("k2"))
        .add_public(okp_pub("k3"))
        .add_private(oct_priv("k4"))
        .build();

    let v = jwks.to_value();
    let keys = v["keys"].as_array().unwrap();
    for key in keys {
        assert!(key["kty"].is_string(), "kty must be present");
        assert!(key["kid"].is_string(), "kid must be present");
    }
}

#[test]
fn serialized_kty_values_match_key_types() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("rsa"))
        .add_public(ec_pub("ec"))
        .add_public(okp_pub("okp"))
        .add_private(oct_priv("oct"))
        .build();

    let v = jwks.to_value();
    let keys = v["keys"].as_array().unwrap();
    let ktys: Vec<&str> = keys.iter().map(|k| k["kty"].as_str().unwrap()).collect();

    assert!(ktys.contains(&"RSA"));
    assert!(ktys.contains(&"EC"));
    assert!(ktys.contains(&"OKP"));
    assert!(ktys.contains(&"oct"));
}

// ── 6. Edge cases ───────────────────────────────────────────────────────

#[test]
fn empty_builder_produces_empty_jwks() {
    let jwks = JwksBuilder::new().build();
    assert!(jwks.keys.is_empty());
}

#[test]
fn empty_jwks_serializes_to_empty_keys_array() {
    let jwks = JwksBuilder::new().build();
    let v = jwks.to_value();
    assert_eq!(v["keys"].as_array().unwrap().len(), 0);
}

#[test]
fn empty_jwks_display_is_valid_json() {
    let jwks = JwksBuilder::new().build();
    let json = jwks.to_string();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["keys"].as_array().unwrap().is_empty());
}

#[test]
fn builder_default_is_equivalent_to_new() {
    let from_new = JwksBuilder::new().build();
    let from_default = JwksBuilder::default().build();
    assert_eq!(from_new.keys.len(), from_default.keys.len());
    assert!(from_new.keys.is_empty());
}

#[test]
fn single_public_key_jwks() {
    let jwks = JwksBuilder::new().add_public(rsa_pub("solo")).build();
    let v = jwks.to_value();
    let keys = v["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kid"], "solo");
}

#[test]
fn single_private_key_jwks() {
    let jwks = JwksBuilder::new().add_private(oct_priv("solo")).build();
    let v = jwks.to_value();
    let keys = v["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kid"], "solo");
    assert_eq!(keys[0]["kty"], "oct");
}

#[test]
fn kid_with_special_characters() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("key/with/slashes"))
        .add_public(rsa_pub("key.with.dots"))
        .add_public(rsa_pub("key-with-dashes"))
        .add_public(rsa_pub("key_with_underscores"))
        .build();

    assert_eq!(jwks.keys.len(), 4);
    let v = jwks.to_value();
    let keys = v["keys"].as_array().unwrap();
    for key in keys {
        assert!(key["kid"].is_string());
    }
}

#[test]
fn kid_with_empty_string() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub(""))
        .add_public(rsa_pub("a"))
        .build();

    // Empty string sorts before "a"
    assert_eq!(jwks.keys[0].kid(), "");
    assert_eq!(jwks.keys[1].kid(), "a");
}

#[test]
fn builder_clone_produces_independent_copy() {
    let builder = JwksBuilder::new()
        .add_public(rsa_pub("a"))
        .add_public(ec_pub("b"));

    let clone = builder.clone();
    let jwks1 = builder.build();
    let jwks2 = clone.build();

    assert_eq!(jwks1.keys.len(), jwks2.keys.len());
    assert_eq!(
        serde_json::to_string(&jwks1).unwrap(),
        serde_json::to_string(&jwks2).unwrap(),
    );
}

// ── 7. JWKS Display matches to_value for complex sets ───────────────────

#[test]
fn complex_jwks_display_matches_to_value() {
    let jwks = JwksBuilder::new()
        .add_public(rsa_pub("z-rsa"))
        .add_public(ec_pub("a-ec"))
        .add_private(okp_priv("m-okp"))
        .add_private(oct_priv("b-oct"))
        .add_public(okp_pub("c-okp"))
        .build();

    let from_display: Value = serde_json::from_str(&jwks.to_string()).unwrap();
    let from_to_value = jwks.to_value();
    assert_eq!(from_display, from_to_value);
}

// ── 8. Private key data preserved in serialization ──────────────────────

#[test]
fn rsa_private_key_fields_present_in_jwks() {
    let jwks = JwksBuilder::new().add_private(rsa_priv("rsa-k")).build();
    let v = jwks.to_value();
    let key = &v["keys"][0];

    for field in [
        "kty", "use", "alg", "kid", "n", "e", "d", "p", "q", "dp", "dq", "qi",
    ] {
        assert!(key.get(field).is_some(), "missing field: {field}");
    }
}

#[test]
fn ec_private_key_d_field_present_in_jwks() {
    let jwks = JwksBuilder::new().add_private(ec_priv("ec-k")).build();
    let v = jwks.to_value();
    let key = &v["keys"][0];
    assert!(key["d"].is_string());
    assert!(key["x"].is_string());
    assert!(key["y"].is_string());
}

#[test]
fn okp_private_key_d_field_present_in_jwks() {
    let jwks = JwksBuilder::new().add_private(okp_priv("okp-k")).build();
    let v = jwks.to_value();
    let key = &v["keys"][0];
    assert!(key["d"].is_string());
    assert!(key["x"].is_string());
}

#[test]
fn oct_private_key_k_field_present_in_jwks() {
    let jwks = JwksBuilder::new().add_private(oct_priv("oct-k")).build();
    let v = jwks.to_value();
    let key = &v["keys"][0];
    assert!(key["k"].is_string());
}

// ── 9. Jwks struct direct construction vs builder ───────────────────────

#[test]
fn builder_output_type_is_jwks() {
    let jwks: Jwks = JwksBuilder::new().add_public(rsa_pub("t")).build();
    // Verify the Jwks struct is usable
    assert_eq!(jwks.keys.len(), 1);
    let _ = jwks.to_value();
    let _ = jwks.to_string();
}
