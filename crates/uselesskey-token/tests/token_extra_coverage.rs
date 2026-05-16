//! Extra coverage for `uselesskey-token`:
//!
//! - Pin `DOMAIN_TOKEN_FIXTURE` so accidental renames flip a test rather than
//!   silently re-key every cached and deterministic token fixture downstream.
//! - Pin `TokenFixture::spec()` / `label()` accessors which are otherwise only
//!   exercised by doctests.
//! - Pin `authorization_header()` shape for every supported spec.
//! - Pin negative-fixture cache identity by variant (different `NegativeToken`
//!   variants must produce distinct cached values from the same base token).
//! - Pin `Clone` semantics: cloning preserves label/spec/value.
//!
//! Follows the established `<crate>_extra_coverage.rs` pattern used by
//! `uselesskey-hmac`, `uselesskey-ed25519`, `uselesskey-entropy`, and
//! `uselesskey-jwk`.

use uselesskey_core::{Factory, Seed};
use uselesskey_test_support::{TestResult, ensure, ensure_eq, require_ok};
use uselesskey_token::{DOMAIN_TOKEN_FIXTURE, NegativeToken, TokenFactoryExt, TokenSpec};

fn det_fx(seed_label: &str) -> TestResult<Factory> {
    Ok(Factory::deterministic(require_ok(
        Seed::from_env_value(seed_label),
        "valid deterministic seed",
    )?))
}

#[test]
fn domain_constant_is_stable() {
    assert_eq!(DOMAIN_TOKEN_FIXTURE, "uselesskey:token:fixture");
}

#[test]
fn spec_accessor_returns_construction_spec() -> TestResult<()> {
    let fx = det_fx("token-spec-accessor")?;
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let tok = fx.token("svc", spec);
        ensure_eq!(tok.spec(), spec);
    }
    Ok(())
}

#[test]
fn label_accessor_returns_construction_label() -> TestResult<()> {
    let fx = det_fx("token-label-accessor")?;
    let tok = fx.token("my-service", TokenSpec::api_key());
    ensure_eq!(tok.label(), "my-service");
    Ok(())
}

#[test]
fn authorization_header_uses_api_key_scheme_for_api_key_spec() -> TestResult<()> {
    let fx = det_fx("token-auth-header-api")?;
    let tok = fx.token("svc", TokenSpec::api_key());
    let header = tok.authorization_header();
    ensure!(header.starts_with("ApiKey "));
    ensure!(header.ends_with(tok.value()));
    Ok(())
}

#[test]
fn authorization_header_uses_bearer_scheme_for_oauth_spec() -> TestResult<()> {
    let fx = det_fx("token-auth-header-oauth")?;
    let tok = fx.token("svc", TokenSpec::oauth_access_token());
    let header = tok.authorization_header();
    ensure!(header.starts_with("Bearer "));
    ensure!(header.ends_with(tok.value()));
    Ok(())
}

#[test]
fn negative_variants_have_distinct_cached_values() -> TestResult<()> {
    let fx = det_fx("token-negative-distinct")?;
    let tok = fx.token("svc", TokenSpec::oauth_access_token());

    let expired = tok.negative_value(NegativeToken::ExpiredClaims);
    let bad_issuer = tok.negative_value(NegativeToken::BadIssuer);
    let bad_aud = tok.negative_value(NegativeToken::BadAudience);
    let alg_none = tok.negative_value(NegativeToken::AlgNone);

    // Each variant must reach its own cache bucket.
    ensure!(expired != bad_issuer);
    ensure!(expired != bad_aud);
    ensure!(expired != alg_none);
    ensure!(bad_issuer != bad_aud);
    ensure!(bad_issuer != alg_none);
    ensure!(bad_aud != alg_none);

    // And none of them should equal the positive fixture.
    let good = tok.value();
    ensure!(expired != good);
    ensure!(bad_issuer != good);
    ensure!(bad_aud != good);
    ensure!(alg_none != good);

    Ok(())
}

#[test]
fn negative_variant_value_is_cached_within_token_fixture() -> TestResult<()> {
    let fx = det_fx("token-negative-cache")?;
    let tok = fx.token("svc", TokenSpec::oauth_access_token());

    let first = tok.negative_value(NegativeToken::BadIssuer);
    let second = tok.negative_value(NegativeToken::BadIssuer);
    ensure_eq!(first, second);
    Ok(())
}

#[test]
fn clone_preserves_label_spec_and_value() -> TestResult<()> {
    let fx = det_fx("token-clone")?;
    let original = fx.token("clone-svc", TokenSpec::bearer());
    let cloned = original.clone();

    ensure_eq!(original.label(), cloned.label());
    ensure_eq!(original.spec(), cloned.spec());
    ensure_eq!(original.value(), cloned.value());
    Ok(())
}
