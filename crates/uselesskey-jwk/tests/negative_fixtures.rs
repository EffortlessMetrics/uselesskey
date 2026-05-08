use serde_json::Value;
use uselesskey_jwk::{
    AnyJwk, EcPublicJwk, Jwks, NegativeJwk, NegativeJwks, OctJwk, PrivateJwk, PublicJwk,
    RsaPrivateJwk, RsaPublicJwk,
};

fn rsa_public(kid: &str) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "modulus".to_string(),
        e: "AQAB".to_string(),
    })
}

fn rsa_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Rsa(RsaPrivateJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "modulus".to_string(),
        e: "AQAB".to_string(),
        d: "private-exponent".to_string(),
        p: "p".to_string(),
        q: "q".to_string(),
        dp: "dp".to_string(),
        dq: "dq".to_string(),
        qi: "qi".to_string(),
    })
}

fn ec_public(kid: &str) -> PublicJwk {
    PublicJwk::Ec(EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: "x-coordinate".to_string(),
        y: "y-coordinate".to_string(),
    })
}

fn oct_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.to_string(),
        k: "symmetric-key".to_string(),
    })
}

fn keys(value: &Value) -> &[Value] {
    value["keys"].as_array().expect("keys array").as_slice()
}

#[test]
fn negative_jwk_missing_kid_removes_only_kid() {
    let value = rsa_public("missing-kid").negative_value(NegativeJwk::MissingKid);

    assert!(value.get("kid").is_none());
    assert_eq!(value["kty"], "RSA");
    assert_eq!(value["alg"], "RS256");
    assert_eq!(value["n"], "modulus");
}

#[test]
fn negative_jwk_malformed_field_is_scanner_safe_invalid_material() {
    let value = rsa_public("bad-field").negative_value(NegativeJwk::MalformedField);

    assert_eq!(value["kid"], "bad-field");
    assert_eq!(value["kty"], "RSA");
    assert_eq!(value["n"], "not_base64url!*");
    assert_ne!(value["n"], "modulus");
}

#[test]
fn negative_jwk_wrong_kty_preserves_metadata_and_material() {
    let value = ec_public("wrong-kty").negative_value(NegativeJwk::WrongKty);

    assert_eq!(value["kid"], "wrong-kty");
    assert_eq!(value["alg"], "ES256");
    assert_eq!(value["kty"], "RSA");
    assert_eq!(value["crv"], "P-256");
    assert_eq!(value["x"], "x-coordinate");
}

#[test]
fn negative_jwk_wrong_kty_changes_rsa_to_ec() {
    let value = rsa_public("wrong-rsa-kty").negative_value(NegativeJwk::WrongKty);

    assert_eq!(value["kid"], "wrong-rsa-kty");
    assert_eq!(value["alg"], "RS256");
    assert_eq!(value["kty"], "EC");
    assert_eq!(value["n"], "modulus");
}

#[test]
fn negative_jwk_unsupported_alg_preserves_key_shape() {
    let value = oct_private("unsupported-alg").negative_value(NegativeJwk::UnsupportedAlg);

    assert_eq!(value["kid"], "unsupported-alg");
    assert_eq!(value["kty"], "oct");
    assert_eq!(value["alg"], "UK-UNSUPPORTED");
    assert_eq!(value["k"], "symmetric-key");
}

#[test]
fn negative_jwk_mismatched_parameters_changes_material_not_identity() {
    let value = rsa_private("mismatch").negative_value(NegativeJwk::MismatchedParameters);

    assert_eq!(value["kid"], "mismatch");
    assert_eq!(value["kty"], "RSA");
    assert_eq!(value["alg"], "RS256");
    assert_eq!(value["n"], "modulus");
    assert_eq!(value["d"], "AAAA");
    assert_ne!(value["d"], "private-exponent");
}

#[test]
fn negative_any_jwk_delegates_to_inner_shape() {
    let jwk = AnyJwk::from(rsa_public("any-negative"));

    let value = jwk.negative_value(NegativeJwk::UnsupportedAlg);

    assert_eq!(value["kid"], "any-negative");
    assert_eq!(value["kty"], "RSA");
    assert_eq!(value["alg"], "UK-UNSUPPORTED");
}

#[test]
fn negative_jwks_empty_keys_emits_empty_key_set() {
    let jwks = Jwks {
        keys: vec![AnyJwk::from(rsa_public("ignored"))],
    };

    let value = jwks.negative_value(NegativeJwks::EmptyKeys);

    assert_eq!(keys(&value).len(), 0);
}

#[test]
fn negative_jwks_missing_kid_removes_kid_from_key() {
    let jwks = Jwks {
        keys: vec![AnyJwk::from(rsa_public("missing"))],
    };

    let value = jwks.negative_value(NegativeJwks::MissingKid);
    let keys = keys(&value);

    assert_eq!(keys.len(), 1);
    assert!(keys[0].get("kid").is_none());
    assert_eq!(keys[0]["kty"], "RSA");
}

#[test]
fn negative_jwks_duplicate_kid_uses_distinct_scanner_safe_material() {
    let jwks = Jwks {
        keys: vec![AnyJwk::from(rsa_public("dup"))],
    };

    let value = jwks.negative_value(NegativeJwks::DuplicateKid);
    let keys = keys(&value);

    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["kid"], "duplicate-kid");
    assert_eq!(keys[1]["kid"], "duplicate-kid");
    assert_eq!(keys[0]["kty"], keys[1]["kty"]);
    assert_ne!(keys[0]["n"], keys[1]["n"]);
    assert_eq!(keys[1]["n"], "AAAA");
}

#[test]
fn negative_jwks_duplicate_key_repeats_exact_key() {
    let jwks = Jwks {
        keys: vec![AnyJwk::from(rsa_public("dup-key"))],
    };

    let value = jwks.negative_value(NegativeJwks::DuplicateKey);
    let keys = keys(&value);

    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1]);
    assert_eq!(keys[0]["kid"], "dup-key");
}

#[test]
fn negative_jwks_empty_input_still_emits_shape_realistic_key_for_duplicate_cases() {
    let jwks = Jwks { keys: vec![] };

    let value = jwks.negative_value(NegativeJwks::DuplicateKey);
    let keys = keys(&value);

    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["kid"], "duplicate-key");
    assert_eq!(keys[0]["n"], "AAAA");
    assert_eq!(keys[0], keys[1]);
}
