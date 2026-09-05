#![cfg(feature = "json")]

//! Duplicate IDs and duplicate keys are different negative-fixture contracts.

use serde_json::{Value, json};
use uselesskey_jwk::{
    AnyJwk, EcPrivateJwk, EcPublicJwk, Jwks, NegativeJwks, OctJwk, OkpPrivateJwk,
    OkpPublicJwk, PrivateJwk, PublicJwk, RsaPrivateJwk, RsaPublicJwk,
};
use uselesskey_test_support::{TestResult, ensure, ensure_eq, require_some};

// All material here is deliberately synthetic, not cryptographic test vectors.
fn shapes(material: &str) -> [(&'static str, AnyJwk); 7] {
    [
        (
            "n",
            PublicJwk::Rsa(RsaPublicJwk {
                kty: "RSA",
                use_: "sig",
                alg: "RS256",
                kid: "source-rsa".into(),
                n: material.into(),
                e: "AQAB".into(),
            })
            .into(),
        ),
        (
            "n",
            PrivateJwk::Rsa(RsaPrivateJwk {
                kty: "RSA",
                use_: "sig",
                alg: "RS256",
                kid: "source-rsa-private".into(),
                n: material.into(),
                e: "AQAB".into(),
                d: "AAAC".into(),
                p: "AAAC".into(),
                q: "AAAC".into(),
                dp: "AAAC".into(),
                dq: "AAAC".into(),
                qi: "AAAC".into(),
            })
            .into(),
        ),
        (
            "x",
            PublicJwk::Ec(EcPublicJwk {
                kty: "EC",
                use_: "sig",
                alg: "ES256",
                crv: "P-256",
                kid: "source-ec".into(),
                x: material.into(),
                y: "AAAC".into(),
            })
            .into(),
        ),
        (
            "x",
            PrivateJwk::Ec(EcPrivateJwk {
                kty: "EC",
                use_: "sig",
                alg: "ES256",
                crv: "P-256",
                kid: "source-ec-private".into(),
                x: material.into(),
                y: "AAAC".into(),
                d: "AAAC".into(),
            })
            .into(),
        ),
        (
            "x",
            PublicJwk::Okp(OkpPublicJwk {
                kty: "OKP",
                use_: "sig",
                alg: "EdDSA",
                crv: "Ed25519",
                kid: "source-okp".into(),
                x: material.into(),
            })
            .into(),
        ),
        (
            "x",
            PrivateJwk::Okp(OkpPrivateJwk {
                kty: "OKP",
                use_: "sig",
                alg: "EdDSA",
                crv: "Ed25519",
                kid: "source-okp-private".into(),
                x: material.into(),
                d: "AAAC".into(),
            })
            .into(),
        ),
        (
            "k",
            PrivateJwk::Oct(OctJwk {
                kty: "oct",
                use_: "sig",
                alg: "HS256",
                kid: "source-oct".into(),
                k: material.into(),
            })
            .into(),
        ),
    ]
}

fn pair(value: &Value) -> TestResult<(&Value, &Value)> {
    let keys = require_some(
        value.get("keys").and_then(Value::as_array),
        "negative JWKS must contain a keys array",
    )?;
    ensure_eq!(keys.len(), 2);
    let first = require_some(keys.first(), "first key is missing")?;
    let second = require_some(keys.get(1), "second key is missing")?;
    Ok((first, second))
}

fn check_duplicate_kid(
    source: AnyJwk,
    field: &str,
    replacement: &str,
) -> TestResult<()> {
    let jwks = Jwks { keys: vec![source] };
    let original = jwks.to_value();
    let first_source = require_some(jwks.keys.first(), "source key is missing")?;
    let mut expected_first = first_source.to_value();
    require_some(expected_first.as_object_mut(), "source is not an object")?
        .insert("kid".into(), json!("duplicate-kid"));
    let mut expected_second = expected_first.clone();
    require_some(expected_second.as_object_mut(), "expected key is not an object")?
        .insert(field.into(), json!(replacement));

    let result = jwks.negative_value(NegativeJwks::DuplicateKid);
    let (first, second) = pair(&result)?;
    ensure!(first != second, "DuplicateKid must not become DuplicateKey");
    ensure_eq!(first, &expected_first);
    ensure_eq!(second, &expected_second);
    ensure_eq!(result, jwks.negative_value(NegativeJwks::DuplicateKid));
    ensure_eq!(original, jwks.to_value());
    Ok(())
}

#[test]
fn duplicate_kid_empty_input_has_distinct_material() -> TestResult<()> {
    let jwks = Jwks { keys: vec![] };
    let result = jwks.negative_value(NegativeJwks::DuplicateKid);
    let (first, second) = pair(&result)?;
    ensure!(first != second, "fallback keys must have distinct material");
    ensure_eq!(
        first,
        &json!({
            "kty": "RSA", "use": "sig", "alg": "RS256",
            "kid": "duplicate-kid", "n": "AAAA", "e": "AQAB"
        })
    );
    ensure_eq!(
        second,
        &json!({
            "kty": "RSA", "use": "sig", "alg": "RS256",
            "kid": "duplicate-kid", "n": "AAAB", "e": "AQAB"
        })
    );
    ensure_eq!(result, jwks.negative_value(NegativeJwks::DuplicateKid));
    ensure!(jwks.keys.is_empty());
    Ok(())
}

#[test]
fn duplicate_kid_sentinel_collision_is_distinct_for_every_shape() -> TestResult<()> {
    for (field, source) in shapes("AAAA") {
        check_duplicate_kid(source, field, "AAAB")?;
    }
    Ok(())
}

#[test]
fn duplicate_kid_preserves_existing_noncolliding_outputs() -> TestResult<()> {
    // The alternate sentinel must also remain a noncolliding input.
    for material in ["AQAB", "AAAB"] {
        for (field, source) in shapes(material) {
            check_duplicate_kid(source, field, "AAAA")?;
        }
    }
    Ok(())
}

#[test]
fn duplicate_key_still_repeats_exact_keys() -> TestResult<()> {
    let empty = Jwks { keys: vec![] }.negative_value(NegativeJwks::DuplicateKey);
    let (first, second) = pair(&empty)?;
    ensure_eq!(first, second);
    for (_, source) in shapes("AAAA") {
        let expected = source.to_value();
        let result = Jwks { keys: vec![source] }.negative_value(NegativeJwks::DuplicateKey);
        let (first, second) = pair(&result)?;
        ensure_eq!(first, &expected);
        ensure_eq!(first, second);
    }
    Ok(())
}
