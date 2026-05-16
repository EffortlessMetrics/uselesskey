//! Integration coverage for `TokenFixture::negative_value` variants.
//!
//! `negative_fixtures.rs` exercises 5 of the 12 `NegativeToken` variants at the
//! public `TokenFixture` layer. The remaining JWT-shaped variants
//! (`MalformedJwtSegmentCount`, `BadBase64UrlSegment`, `InvalidJwtHeaderShape`,
//! `MissingAlg`, `AlgNone`, `MismatchedKid`, `NotYetValidClaims`) are only
//! covered by inline tests against the internal `generate_negative_token`
//! function. These tests close that gap and additionally verify:
//!
//! - per-variant cross-factory determinism via `negative_value`
//! - the positive token value is never perturbed by negative generation
//! - `negative_value` output is not surfaced through `Debug`
//! - distinct `NegativeToken` variants yield distinct strings
//!
//! Tests avoid `.unwrap()` / `.expect()` and use
//! `uselesskey_test_support::{ensure, ensure_eq, TestResult}` plus explicit
//! `match` so no new no-panic-family debt is introduced.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};
use uselesskey_core::Factory;
use uselesskey_test_support::{TestResult, ensure, ensure_eq, require_ok, require_some};
use uselesskey_token::{NegativeToken, TokenFactoryExt, TokenSpec};

const SCANNER_SAFE_INVALID_TOKEN_SEGMENT: &str = "not_base64url!*";

fn split_segments(value: &str) -> Vec<&str> {
    value.split('.').collect()
}

fn decode_object(segment: &str) -> TestResult<Map<String, Value>> {
    let bytes = require_ok(URL_SAFE_NO_PAD.decode(segment), "decode jwt segment")?;
    let value: Value = require_ok(
        serde_json::from_slice::<Value>(&bytes),
        "parse jwt segment json",
    )?;
    let map = require_some(value.as_object().cloned(), "jwt segment was not an object")?;
    Ok(map)
}

#[test]
fn malformed_jwt_segment_count_emits_two_segments_only() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("token-neg-segment-count");
    let token = fx.token("issuer", TokenSpec::oauth_access_token());

    let value = token.negative_value(NegativeToken::MalformedJwtSegmentCount);
    let parts = split_segments(&value);

    ensure_eq!(parts.len(), 2, "MalformedJwtSegmentCount must drop one dot");
    let header = decode_object(parts[0])?;
    ensure_eq!(header.get("alg"), Some(&Value::String("RS256".into())));
    let payload = decode_object(parts[1])?;
    ensure_eq!(payload.get("sub"), Some(&Value::String("issuer".into())));
    ensure!(value != token.value(), "negative value must differ");
    Ok(())
}

#[test]
fn bad_base64url_segment_replaces_payload_with_scanner_safe_text() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("token-neg-bad-base64url");
    let token = fx.token("issuer", TokenSpec::oauth_access_token());

    let value = token.negative_value(NegativeToken::BadBase64UrlSegment);
    let parts = split_segments(&value);

    ensure_eq!(parts.len(), 3);
    ensure_eq!(parts[1], SCANNER_SAFE_INVALID_TOKEN_SEGMENT);
    ensure!(
        URL_SAFE_NO_PAD.decode(parts[1]).is_err(),
        "scanner-safe segment must not decode as base64url"
    );
    Ok(())
}

#[test]
fn invalid_jwt_header_shape_decodes_to_a_json_array() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("token-neg-bad-header-shape");
    let token = fx.token("issuer", TokenSpec::oauth_access_token());

    let value = token.negative_value(NegativeToken::InvalidJwtHeaderShape);
    let parts = split_segments(&value);

    ensure_eq!(parts.len(), 3);
    let header_bytes = require_ok(URL_SAFE_NO_PAD.decode(parts[0]), "decode header")?;
    let header_json: Value = require_ok(
        serde_json::from_slice::<Value>(&header_bytes),
        "parse header json",
    )?;
    ensure!(
        header_json.is_array(),
        "invalid-header-shape variant must decode to a JSON array"
    );
    Ok(())
}

#[test]
fn missing_alg_keeps_typ_and_drops_alg() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("token-neg-missing-alg");
    let token = fx.token("issuer", TokenSpec::oauth_access_token());

    let value = token.negative_value(NegativeToken::MissingAlg);
    let parts = split_segments(&value);
    let header = decode_object(parts[0])?;

    ensure!(!header.contains_key("alg"), "alg must be removed");
    ensure_eq!(header.get("typ"), Some(&Value::String("JWT".into())));
    Ok(())
}

#[test]
fn alg_none_only_changes_alg_field() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("token-neg-alg-none");
    let token = fx.token("issuer", TokenSpec::oauth_access_token());

    let value = token.negative_value(NegativeToken::AlgNone);
    let parts = split_segments(&value);
    let header = decode_object(parts[0])?;

    ensure_eq!(header.get("alg"), Some(&Value::String("none".into())));
    ensure_eq!(header.get("typ"), Some(&Value::String("JWT".into())));
    Ok(())
}

#[test]
fn mismatched_kid_puts_different_kid_in_header_and_payload() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("token-neg-mismatched-kid");
    let token = fx.token("issuer", TokenSpec::oauth_access_token());

    let value = token.negative_value(NegativeToken::MismatchedKid);
    let parts = split_segments(&value);

    let header = decode_object(parts[0])?;
    let payload = decode_object(parts[1])?;
    let header_kid = require_some(header.get("kid").cloned(), "header kid missing")?;
    let payload_kid = require_some(payload.get("kid").cloned(), "payload kid missing")?;
    ensure!(
        header_kid != payload_kid,
        "header and payload kid must differ"
    );
    Ok(())
}

#[test]
fn not_yet_valid_claims_sets_future_nbf_and_exp() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("token-neg-not-yet-valid");
    let token = fx.token("issuer", TokenSpec::oauth_access_token());

    let value = token.negative_value(NegativeToken::NotYetValidClaims);
    let parts = split_segments(&value);
    let payload = decode_object(parts[1])?;

    let nbf = require_some(
        payload.get("nbf").and_then(Value::as_u64),
        "nbf must be a u64",
    )?;
    let exp = require_some(
        payload.get("exp").and_then(Value::as_u64),
        "exp must be a u64",
    )?;
    ensure!(nbf > 1_900_000_000, "nbf must be in the far future");
    ensure!(exp > nbf, "exp must follow nbf");
    Ok(())
}

#[test]
fn negative_value_is_deterministic_across_factories_for_all_variants() -> TestResult<()> {
    let variants = [
        NegativeToken::MalformedJwtSegmentCount,
        NegativeToken::BadBase64UrlSegment,
        NegativeToken::InvalidJwtHeaderShape,
        NegativeToken::MissingAlg,
        NegativeToken::AlgNone,
        NegativeToken::MismatchedKid,
        NegativeToken::NotYetValidClaims,
    ];

    for variant in variants {
        let fx1 = Factory::deterministic_from_str("token-neg-cross-factory");
        let fx2 = Factory::deterministic_from_str("token-neg-cross-factory");
        let t1 = fx1.token("issuer", TokenSpec::oauth_access_token());
        let t2 = fx2.token("issuer", TokenSpec::oauth_access_token());

        let v1 = t1.negative_value(variant);
        let v2 = t2.negative_value(variant);
        ensure_eq!(v1, v2, "negative_value not deterministic for {variant:?}");
    }
    Ok(())
}

#[test]
fn negative_value_does_not_perturb_positive_token_value() -> TestResult<()> {
    let variants = [
        NegativeToken::MalformedJwtSegmentCount,
        NegativeToken::BadBase64UrlSegment,
        NegativeToken::InvalidJwtHeaderShape,
        NegativeToken::MissingAlg,
        NegativeToken::AlgNone,
        NegativeToken::MismatchedKid,
        NegativeToken::NotYetValidClaims,
    ];

    // baseline: positive value with no negative ever asked for
    let baseline_fx = Factory::deterministic_from_str("token-neg-isolation");
    let baseline = baseline_fx
        .token("issuer", TokenSpec::oauth_access_token())
        .value()
        .to_string();

    for variant in variants {
        let fx = Factory::deterministic_from_str("token-neg-isolation");
        let token = fx.token("issuer", TokenSpec::oauth_access_token());
        // Generate negative first, then sample positive.
        let _ = token.negative_value(variant);
        let positive_after = token.value().to_string();
        ensure_eq!(
            baseline,
            positive_after,
            "positive token must be stable after {variant:?}"
        );
    }
    Ok(())
}

#[test]
fn negative_value_does_not_leak_through_debug() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("token-neg-debug");
    let token = fx.token("issuer", TokenSpec::oauth_access_token());

    // Materialise the negative value to seed the cache.
    let negative = token.negative_value(NegativeToken::AlgNone);
    let dbg = format!("{token:?}");

    ensure!(
        !dbg.contains(token.value()),
        "Debug must not leak positive value"
    );
    ensure!(
        !dbg.contains(&negative),
        "Debug must not leak negative value"
    );
    Ok(())
}

#[test]
fn distinct_negative_variants_yield_distinct_outputs() -> TestResult<()> {
    let fx = Factory::deterministic_from_str("token-neg-distinct");
    let token = fx.token("issuer", TokenSpec::oauth_access_token());

    let variants = [
        NegativeToken::MalformedJwtSegmentCount,
        NegativeToken::BadBase64UrlSegment,
        NegativeToken::InvalidJwtHeaderShape,
        NegativeToken::MissingAlg,
        NegativeToken::AlgNone,
        NegativeToken::MismatchedKid,
        NegativeToken::NotYetValidClaims,
    ];

    let values: Vec<String> = variants.iter().map(|v| token.negative_value(*v)).collect();

    for (i, vi) in values.iter().enumerate() {
        ensure!(
            vi != token.value(),
            "{:?} should differ from positive",
            variants[i]
        );
        for (j, vj) in values.iter().enumerate().skip(i + 1) {
            ensure!(
                vi != vj,
                "{:?} and {:?} must produce distinct outputs",
                variants[i],
                variants[j]
            );
        }
    }
    Ok(())
}
