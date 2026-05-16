//! Header propagation and `Validation` configuration coverage.
//!
//! Pins adapter behaviour for paths the existing tests do not exercise:
//! - `Header::kid`/`typ`/`alg` round-tripping through `encode` →
//!   `decode_header` → `decode`, for each supported `JwtKeyExt` impl
//! - `Validation::set_issuer` accept and reject branches
//! - `Validation::validate_nbf` rejecting not-yet-valid tokens
//! - `Validation::set_required_spec_claims` rejecting missing claims
//! - `Validation::leeway` extending the acceptable `exp` window
//!
//! All assertions use `uselesskey_test_support` so the file adds no new
//! panic-family debt.

mod testutil;

use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
    errors::{Error, ErrorKind, Result as JwtResult},
};
use serde::{Deserialize, Serialize};
use testutil::fx;
use uselesskey_jsonwebtoken::JwtKeyExt;
use uselesskey_test_support::{TestError, TestResult, ensure, ensure_eq, require_ok};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Claims {
    sub: String,
    exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<usize>,
}

fn base_claims() -> Claims {
    Claims {
        sub: "header-validation-user".into(),
        exp: 2_000_000_000,
        iss: None,
        nbf: None,
    }
}

fn expect_err<T: std::fmt::Debug>(result: JwtResult<T>, ctx: &str) -> TestResult<Error> {
    match result {
        Ok(value) => Err(TestError(format!(
            "{ctx}: expected decode error, got Ok({value:?})"
        ))),
        Err(err) => Ok(err),
    }
}

/// Shared body for the per-algorithm KID round-trip tests below.
///
/// Exercises the full triplet: `encode` with `Header.kid = Some(kid)`,
/// then `decode_header` (which must surface kid + alg + typ without
/// touching the signature), and finally `decode` (which must preserve
/// the same fields on the returned `TokenData`).
#[allow(dead_code)] // false positive when no features are enabled
fn assert_kid_round_trip(
    alg: Algorithm,
    kid: &str,
    enc: &EncodingKey,
    dec: &DecodingKey,
) -> TestResult<()> {
    let mut header = Header::new(alg);
    header.kid = Some(kid.to_string());

    let token = require_ok(
        encode(&header, &base_claims(), enc),
        "encode token with kid",
    )?;

    let parsed = require_ok(decode_header(&token), "decode_header")?;
    ensure_eq!(parsed.kid, Some(kid.to_string()));
    ensure_eq!(parsed.alg, alg);
    ensure_eq!(parsed.typ, Some("JWT".to_string()));

    let decoded = require_ok(
        decode::<Claims>(&token, dec, &Validation::new(alg)),
        "decode token with kid",
    )?;
    ensure_eq!(decoded.header.kid, Some(kid.to_string()));
    ensure_eq!(decoded.header.alg, alg);
    Ok(())
}

// =========================================================================
// Header.kid round-trips for every supported adapter impl
// =========================================================================

#[cfg(feature = "rsa")]
#[test]
fn rsa_header_kid_round_trips_through_decode() -> TestResult<()> {
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    let kp = fx().rsa("hdr-kid-rsa", RsaSpec::rs256());
    assert_kid_round_trip(
        Algorithm::RS256,
        "rsa-test-kid-1",
        &kp.encoding_key(),
        &kp.decoding_key(),
    )
}

#[cfg(feature = "ecdsa")]
#[test]
fn ecdsa_header_kid_round_trips_through_decode() -> TestResult<()> {
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    let kp = fx().ecdsa("hdr-kid-ec", EcdsaSpec::es256());
    assert_kid_round_trip(
        Algorithm::ES256,
        "ec-test-kid-1",
        &kp.encoding_key(),
        &kp.decoding_key(),
    )
}

#[cfg(feature = "ed25519")]
#[test]
fn ed25519_header_kid_round_trips_through_decode() -> TestResult<()> {
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    let kp = fx().ed25519("hdr-kid-ed", Ed25519Spec::new());
    assert_kid_round_trip(
        Algorithm::EdDSA,
        "ed-test-kid-1",
        &kp.encoding_key(),
        &kp.decoding_key(),
    )
}

#[cfg(feature = "hmac")]
#[test]
fn hmac_header_kid_round_trips_through_decode() -> TestResult<()> {
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    let s = fx().hmac("hdr-kid-hmac", HmacSpec::hs256());
    assert_kid_round_trip(
        Algorithm::HS256,
        "hmac-test-kid-1",
        &s.encoding_key(),
        &s.decoding_key(),
    )
}

// =========================================================================
// Validation knobs (HMAC keeps test runtime tiny — keygen is free).
// =========================================================================

#[cfg(feature = "hmac")]
#[test]
fn issuer_validation_accepts_matching_iss() -> TestResult<()> {
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    let secret = fx().hmac("val-iss-ok", HmacSpec::hs256());
    let mut claims = base_claims();
    claims.iss = Some("trusted-issuer".into());

    let token = require_ok(
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &secret.encoding_key(),
        ),
        "encode HS256 with iss claim",
    )?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&["trusted-issuer"]);
    let decoded = require_ok(
        decode::<Claims>(&token, &secret.decoding_key(), &validation),
        "decode with matching issuer",
    )?;
    ensure_eq!(decoded.claims.iss, Some("trusted-issuer".to_string()));
    Ok(())
}

#[cfg(feature = "hmac")]
#[test]
fn issuer_validation_rejects_mismatched_iss() -> TestResult<()> {
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    let secret = fx().hmac("val-iss-bad", HmacSpec::hs256());
    let mut claims = base_claims();
    claims.iss = Some("other-issuer".into());

    let token = require_ok(
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &secret.encoding_key(),
        ),
        "encode HS256 with iss claim",
    )?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&["trusted-issuer"]);
    let err = expect_err(
        decode::<Claims>(&token, &secret.decoding_key(), &validation),
        "issuer-mismatch decode",
    )?;
    ensure!(
        matches!(err.kind(), ErrorKind::InvalidIssuer),
        "expected InvalidIssuer, got {:?}",
        err.kind(),
    );
    Ok(())
}

#[cfg(feature = "hmac")]
#[test]
fn nbf_validation_rejects_token_not_yet_valid() -> TestResult<()> {
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    let secret = fx().hmac("val-nbf", HmacSpec::hs256());
    let mut claims = base_claims();
    // nbf far in the future — token is not yet valid.
    claims.nbf = Some(2_000_000_000);

    let token = require_ok(
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &secret.encoding_key(),
        ),
        "encode HS256 with nbf claim",
    )?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_nbf = true;
    let err = expect_err(
        decode::<Claims>(&token, &secret.decoding_key(), &validation),
        "nbf-not-yet-valid decode",
    )?;
    ensure!(
        matches!(err.kind(), ErrorKind::ImmatureSignature),
        "expected ImmatureSignature, got {:?}",
        err.kind(),
    );
    Ok(())
}

#[cfg(feature = "hmac")]
#[test]
fn required_spec_claims_rejects_missing_iss() -> TestResult<()> {
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    let secret = fx().hmac("val-required", HmacSpec::hs256());
    // base_claims() leaves iss unset; the decoder demands it.
    let token = require_ok(
        encode(
            &Header::new(Algorithm::HS256),
            &base_claims(),
            &secret.encoding_key(),
        ),
        "encode HS256 without iss",
    )?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["exp", "iss"]);
    let err = expect_err(
        decode::<Claims>(&token, &secret.decoding_key(), &validation),
        "missing-required-iss decode",
    )?;
    ensure!(
        matches!(err.kind(), ErrorKind::MissingRequiredClaim(_)),
        "expected MissingRequiredClaim, got {:?}",
        err.kind(),
    );
    Ok(())
}

#[cfg(feature = "hmac")]
#[test]
fn leeway_admits_slightly_expired_token() -> TestResult<()> {
    use std::time::{SystemTime, UNIX_EPOCH};
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

    let secret = fx().hmac("val-leeway", HmacSpec::hs256());
    let now =
        require_ok(SystemTime::now().duration_since(UNIX_EPOCH), "system time")?.as_secs() as usize;

    // exp 5 minutes in the past — outside jsonwebtoken's default 60s
    // leeway so `leeway = 0` rejects it and `leeway = 600` accepts it.
    let mut claims = base_claims();
    claims.exp = now - 300;

    let token = require_ok(
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &secret.encoding_key(),
        ),
        "encode HS256 expired token",
    )?;

    let mut strict = Validation::new(Algorithm::HS256);
    strict.leeway = 0;
    let err = expect_err(
        decode::<Claims>(&token, &secret.decoding_key(), &strict),
        "strict expiration",
    )?;
    ensure!(
        matches!(err.kind(), ErrorKind::ExpiredSignature),
        "expected ExpiredSignature under strict validation, got {:?}",
        err.kind(),
    );

    let mut lenient = Validation::new(Algorithm::HS256);
    lenient.leeway = 600;
    let decoded = require_ok(
        decode::<Claims>(&token, &secret.decoding_key(), &lenient),
        "decode with leeway",
    )?;
    ensure_eq!(decoded.claims.exp, claims.exp);
    Ok(())
}
