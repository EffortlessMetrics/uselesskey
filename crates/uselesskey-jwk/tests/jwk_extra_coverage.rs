//! Extra coverage for uselesskey-jwk:
//! - `Jwks::to_value()` direct path (not via Display).
//! - `JwksBuilder::default()` equivalence to `new()`.
//! - `KidSorted` `new`/`default` and many-duplicate stability.
//! - `negative_value()` across concrete `PrivateJwk`/`PublicJwk` variants
//!   (RSA, EC, OKP, Oct) with branch-focused coverage for representative
//!   `NegativeJwk` variants and field lookup orders.
//! - `NegativeJwks::DuplicateKey` on a populated set (the no-empty-source path).
//! - Taxonomy stable IDs and mixed valid/invalid JWKS shape.

use serde_json::Value;
use uselesskey_jwk::srp::ordering::{HasKid, KidSorted};
use uselesskey_jwk::{
    AnyJwk, EcPrivateJwk, EcPublicJwk, Jwks, JwksBuilder, NegativeJwk, NegativeJwks, OctJwk,
    OkpPrivateJwk, OkpPublicJwk, PrivateJwk, PublicJwk, RsaPrivateJwk, RsaPublicJwk,
};
use uselesskey_test_support::{TestResult, require_ok, require_some};

fn rsa_public(kid: &str) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: "n-value".to_string(),
        e: "AQAB".to_string(),
    })
}

fn rsa_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Rsa(RsaPrivateJwk {
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
    })
}

fn ec_public(kid: &str) -> PublicJwk {
    PublicJwk::Ec(EcPublicJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: "x-value".to_string(),
        y: "y-value".to_string(),
    })
}

fn ec_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Ec(EcPrivateJwk {
        kty: "EC",
        use_: "sig",
        alg: "ES256",
        crv: "P-256",
        kid: kid.to_string(),
        x: "x-value".to_string(),
        y: "y-value".to_string(),
        d: "d-value".to_string(),
    })
}

fn okp_public(kid: &str) -> PublicJwk {
    PublicJwk::Okp(OkpPublicJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "x-value".to_string(),
    })
}

fn okp_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Okp(OkpPrivateJwk {
        kty: "OKP",
        use_: "sig",
        alg: "EdDSA",
        crv: "Ed25519",
        kid: kid.to_string(),
        x: "x-value".to_string(),
        d: "d-value".to_string(),
    })
}

fn oct_private(kid: &str) -> PrivateJwk {
    PrivateJwk::Oct(OctJwk {
        kty: "oct",
        use_: "sig",
        alg: "HS256",
        kid: kid.to_string(),
        k: "k-value".to_string(),
    })
}

// =========================================================================
// Jwks::to_value() direct round-trip
// =========================================================================

#[test]
fn jwks_to_value_returns_json_object_with_keys_array() -> TestResult<()> {
    let jwks = Jwks {
        keys: vec![AnyJwk::from(rsa_public("a"))],
    };

    let value = jwks.to_value();
    assert!(value.is_object());
    let keys = require_some(value["keys"].as_array(), "keys array")?;
    assert_eq!(keys.len(), 1);
    assert_eq!(value["keys"][0]["kid"], "a");
    Ok(())
}

#[test]
fn jwks_to_value_matches_display_output_shape() -> TestResult<()> {
    let jwks = Jwks {
        keys: vec![AnyJwk::from(rsa_public("a")), AnyJwk::from(ec_public("b"))],
    };

    let from_value = jwks.to_value();
    let from_display: Value = require_ok(serde_json::from_str(&jwks.to_string()), "parse JWKS")?;
    assert_eq!(from_value, from_display);
    Ok(())
}

// =========================================================================
// JwksBuilder::default()
// =========================================================================

#[test]
fn jwks_builder_default_equivalent_to_new() {
    let from_default: JwksBuilder = JwksBuilder::default();
    let from_new = JwksBuilder::new();

    assert_eq!(from_default.build().keys.len(), 0);
    assert_eq!(from_new.build().keys.len(), 0);
}

// =========================================================================
// KidSorted::new() and default()
// =========================================================================

#[derive(Debug, Clone)]
struct Item {
    kid: String,
}
impl HasKid for Item {
    fn kid(&self) -> &str {
        &self.kid
    }
}

#[test]
fn kid_sorted_new_starts_empty() {
    let sorter: KidSorted<Item> = KidSorted::new();
    assert!(sorter.build().is_empty());
}

#[test]
fn kid_sorted_default_starts_empty() {
    let sorter: KidSorted<Item> = KidSorted::default();
    assert!(sorter.build().is_empty());
}

#[test]
fn kid_sorted_preserves_insertion_for_many_equal_kids() {
    let mut sorter = KidSorted::new();
    for n in 0..10 {
        sorter.push(Item {
            kid: "same".to_string(),
        });
        // Use n to keep variables distinct for the linter
        let _ = n;
    }
    let result = sorter.build();
    assert_eq!(result.len(), 10);
    assert!(result.iter().all(|item| item.kid == "same"));
}

// =========================================================================
// negative_value() for every shape × every NegativeJwk variant
//
// These tests exercise the dispatch path PublicJwk::negative_value /
// PrivateJwk::negative_value for each enum arm. The inline tests cover a few
// shape combinations; here we exhaustively pair shape × variant so each arm
// of the inner `match` is hit at least once with a representative shape.
// =========================================================================

const SCANNER_INVALID: &str = "not_base64url!*";
const SCANNER_MISMATCHED: &str = "AAAA";

fn assert_kid_present(v: &Value, expected: &str) {
    assert_eq!(v["kid"], expected);
}

#[test]
fn public_ec_negative_variants_all_supported() {
    let mk = || ec_public("ec-pub");

    let m = mk().negative_value(NegativeJwk::MissingKid);
    assert!(m.get("kid").is_none());
    assert_eq!(m["kty"], "EC");

    let bad = mk().negative_value(NegativeJwk::MalformedField);
    assert_kid_present(&bad, "ec-pub");
    assert_eq!(bad["x"], SCANNER_INVALID);

    let bad_named = mk().negative_value(NegativeJwk::MalformedBase64url);
    assert_eq!(bad_named, bad);

    let wrong = mk().negative_value(NegativeJwk::WrongKty);
    assert_kid_present(&wrong, "ec-pub");
    assert_eq!(wrong["kty"], "RSA");

    let alg = mk().negative_value(NegativeJwk::UnsupportedAlg);
    assert_eq!(alg["alg"], "UK-UNSUPPORTED");
    assert_eq!(alg["kty"], "EC");

    let mismatch = mk().negative_value(NegativeJwk::MismatchedParameters);
    assert_eq!(mismatch["x"], SCANNER_MISMATCHED);
    assert_eq!(mismatch["kty"], "EC");
}

#[test]
fn public_okp_negative_variants_all_supported() {
    let mk = || okp_public("okp-pub");

    let m = mk().negative_value(NegativeJwk::MissingKid);
    assert!(m.get("kid").is_none());

    let bad = mk().negative_value(NegativeJwk::MalformedField);
    assert_eq!(bad["x"], SCANNER_INVALID);

    let wrong = mk().negative_value(NegativeJwk::WrongKty);
    // OKP is not RSA, so the else arm of `wrong_kty` switches to RSA.
    assert_eq!(wrong["kty"], "RSA");

    let alg = mk().negative_value(NegativeJwk::UnsupportedAlg);
    assert_eq!(alg["alg"], "UK-UNSUPPORTED");

    let mismatch = mk().negative_value(NegativeJwk::MismatchedParameters);
    assert_eq!(mismatch["x"], SCANNER_MISMATCHED);
}

#[test]
fn private_rsa_negative_variants_all_supported() {
    let mk = || rsa_private("rsa-priv");

    let m = mk().negative_value(NegativeJwk::MissingKid);
    assert!(m.get("kid").is_none());
    assert_eq!(m["kty"], "RSA");

    let bad = mk().negative_value(NegativeJwk::MalformedField);
    assert_eq!(bad["n"], SCANNER_INVALID);

    let wrong = mk().negative_value(NegativeJwk::WrongKty);
    assert_eq!(wrong["kty"], "EC");

    let alg = mk().negative_value(NegativeJwk::UnsupportedAlg);
    assert_eq!(alg["alg"], "UK-UNSUPPORTED");

    let mismatch = mk().negative_value(NegativeJwk::MismatchedParameters);
    assert_eq!(mismatch["d"], SCANNER_MISMATCHED);
    assert_ne!(mismatch["n"], SCANNER_MISMATCHED);
}

#[test]
fn private_ec_negative_variants_all_supported() {
    let mk = || ec_private("ec-priv");

    let m = mk().negative_value(NegativeJwk::MissingKid);
    assert!(m.get("kid").is_none());

    let bad = mk().negative_value(NegativeJwk::MalformedField);
    assert_eq!(bad["x"], SCANNER_INVALID);

    let wrong = mk().negative_value(NegativeJwk::WrongKty);
    assert_eq!(wrong["kty"], "RSA");

    let alg = mk().negative_value(NegativeJwk::UnsupportedAlg);
    assert_eq!(alg["alg"], "UK-UNSUPPORTED");

    let mismatch = mk().negative_value(NegativeJwk::MismatchedParameters);
    assert_eq!(mismatch["d"], SCANNER_MISMATCHED);
}

#[test]
fn private_okp_negative_variants_all_supported() {
    let mk = || okp_private("okp-priv");

    let m = mk().negative_value(NegativeJwk::MissingKid);
    assert!(m.get("kid").is_none());

    let bad = mk().negative_value(NegativeJwk::MalformedField);
    assert_eq!(bad["x"], SCANNER_INVALID);

    let wrong = mk().negative_value(NegativeJwk::WrongKty);
    assert_eq!(wrong["kty"], "RSA");

    let alg = mk().negative_value(NegativeJwk::UnsupportedAlg);
    assert_eq!(alg["alg"], "UK-UNSUPPORTED");

    let mismatch = mk().negative_value(NegativeJwk::MismatchedParameters);
    assert_eq!(mismatch["d"], SCANNER_MISMATCHED);
}

#[test]
fn private_oct_negative_unsupported_alg_and_wrong_kty() {
    // Oct is not RSA so WrongKty must switch to RSA.
    let wrong = oct_private("oct-priv").negative_value(NegativeJwk::WrongKty);
    assert_eq!(wrong["kty"], "RSA");
    assert_eq!(wrong["k"], "k-value");

    let alg = oct_private("oct-priv").negative_value(NegativeJwk::UnsupportedAlg);
    assert_eq!(alg["alg"], "UK-UNSUPPORTED");
    assert_eq!(alg["kty"], "oct");
}

// =========================================================================
// NegativeJwks::DuplicateKey on a populated set — exercises the
// "first.clone(), first" arm with a real input key, not just the
// scanner-safe fallback that the existing empty-set test covers.
// =========================================================================

#[test]
fn negative_jwks_duplicate_key_on_populated_set_repeats_first_entry() -> TestResult<()> {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::from(rsa_public("primary")),
            AnyJwk::from(ec_public("secondary")),
        ],
    };

    let value = jwks.negative_value(NegativeJwks::DuplicateKey);
    let keys = require_some(value["keys"].as_array(), "keys array")?;

    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1]);
    // The duplicate uses the first key in the set, not the second.
    assert_eq!(keys[0]["kid"], "primary");
    Ok(())
}

#[test]
fn negative_jwks_mixed_valid_invalid_keeps_one_valid_and_one_malformed_key() -> TestResult<()> {
    let jwks = Jwks {
        keys: vec![AnyJwk::from(rsa_public("valid-key"))],
    };

    let value = jwks.negative_value(NegativeJwks::MixedValidInvalid);
    let keys = require_some(value["keys"].as_array(), "keys array")?;

    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["kid"], "valid-key");
    assert_eq!(keys[0]["n"], "n-value");
    assert_eq!(keys[1]["kid"], "mixed-invalid");
    assert_eq!(keys[1]["n"], SCANNER_INVALID);
    assert_ne!(keys[0], keys[1]);
    Ok(())
}

#[test]
fn taxonomy_stable_ids_match_spec_0016() {
    assert_eq!(NegativeJwk::MissingKid.stable_id(), "jwk_missing_kid");
    assert_eq!(
        NegativeJwk::MalformedField.stable_id(),
        "jwk_malformed_base64url"
    );
    assert_eq!(
        NegativeJwk::MalformedBase64url.stable_id(),
        "jwk_malformed_base64url"
    );
    assert_eq!(NegativeJwk::WrongKty.stable_id(), "jwk_wrong_kty");
    assert_eq!(
        NegativeJwk::UnsupportedAlg.stable_id(),
        "jwk_unsupported_alg"
    );
    assert_eq!(
        NegativeJwk::MismatchedParameters.stable_id(),
        "jwk_mismatched_parameters"
    );

    assert_eq!(NegativeJwks::EmptyKeys.stable_id(), "jwks_empty_keys");
    assert_eq!(NegativeJwks::MissingKid.stable_id(), "jwks_missing_kid");
    assert_eq!(
        NegativeJwks::DuplicateKid.stable_id(),
        "jwks_duplicate_kid"
    );
    assert_eq!(
        NegativeJwks::DuplicateKey.stable_id(),
        "jwks_duplicate_key"
    );
    assert_eq!(
        NegativeJwks::MixedValidInvalid.stable_id(),
        "jwks_mixed_valid_invalid"
    );
}
