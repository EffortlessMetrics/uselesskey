//! Tests for HTTP-level branches that the spec-accessor tests don't cover:
//!
//! - `serve_discovery = false` / `serve_jwks = false` return `404 Not Found`.
//! - `CachePolicySpec` with `max_age_seconds == 0` emits `Cache-Control: no-store`.
//! - `CachePolicySpec` with `emit_etag = false` only sets `Cache-Control`, never `ETag`.
//! - The discovery endpoint emits a body-derived `ETag` when caching is enabled
//!   (the response has no phase, exercising the `unwrap_or_else` fallback in
//!   `cached_json_response`).

use uselesskey_core::{Factory, Seed};
use uselesskey_rsa::RsaSpec;
use uselesskey_test_server::{
    CachePolicySpec, IssuerUrlMode, JwksRotation, JwksSpec, OidcServerSpec, OidcTestServer,
};
use uselesskey_test_support::{TestResult, ensure, ensure_eq, require_ok};

fn deterministic_factory(label: &str) -> TestResult<Factory> {
    let seed = require_ok(
        Seed::from_env_value(label),
        format!("{label} must parse as a deterministic seed"),
    )?;
    Ok(Factory::deterministic(seed))
}

fn http_client() -> TestResult<reqwest::Client> {
    require_ok(
        reqwest::Client::builder().no_proxy().build(),
        "build http client",
    )
}

fn static_jwks_spec_with(serve_discovery: bool, serve_jwks: bool) -> OidcServerSpec {
    OidcServerSpec {
        issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
        jwks_rotation: JwksRotation::Static(JwksSpec::single_rsa("serve-flag", RsaSpec::rs256())),
        cache_headers: None,
        serve_discovery,
        serve_jwks,
    }
}

#[tokio::test]
async fn discovery_endpoint_returns_404_when_serve_discovery_is_false() -> TestResult<()> {
    let spec = static_jwks_spec_with(false, true);
    let server = require_ok(
        OidcTestServer::start(deterministic_factory("serve-flag-discovery-off")?, spec).await,
        "start server",
    )?;

    let response = require_ok(
        http_client()?.get(server.discovery_url()).send().await,
        "discovery response",
    )?;
    ensure_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "disabled discovery endpoint must 404"
    );

    // The JWKS endpoint must still respond when only discovery is disabled.
    let jwks_response = require_ok(
        http_client()?.get(server.jwks_url()).send().await,
        "jwks response",
    )?;
    ensure_eq!(jwks_response.status(), reqwest::StatusCode::OK);

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn jwks_endpoint_returns_404_when_serve_jwks_is_false() -> TestResult<()> {
    let spec = static_jwks_spec_with(true, false);
    let server = require_ok(
        OidcTestServer::start(deterministic_factory("serve-flag-jwks-off")?, spec).await,
        "start server",
    )?;

    let response = require_ok(
        http_client()?.get(server.jwks_url()).send().await,
        "jwks response",
    )?;
    ensure_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "disabled jwks endpoint must 404"
    );

    // The discovery endpoint must still respond when only JWKS is disabled.
    let discovery_response = require_ok(
        http_client()?.get(server.discovery_url()).send().await,
        "discovery response",
    )?;
    ensure_eq!(discovery_response.status(), reqwest::StatusCode::OK);

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn both_endpoints_return_404_when_both_flags_are_false() -> TestResult<()> {
    let spec = static_jwks_spec_with(false, false);
    let server = require_ok(
        OidcTestServer::start(deterministic_factory("serve-flag-both-off")?, spec).await,
        "start server",
    )?;

    let discovery = require_ok(
        http_client()?.get(server.discovery_url()).send().await,
        "discovery response",
    )?;
    let jwks = require_ok(
        http_client()?.get(server.jwks_url()).send().await,
        "jwks response",
    )?;
    ensure_eq!(discovery.status(), reqwest::StatusCode::NOT_FOUND);
    ensure_eq!(jwks.status(), reqwest::StatusCode::NOT_FOUND);

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn cache_control_no_store_is_sent_when_max_age_is_zero() -> TestResult<()> {
    let spec = OidcServerSpec {
        issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
        jwks_rotation: JwksRotation::Static(JwksSpec::single_rsa("no-store", RsaSpec::rs256())),
        cache_headers: Some(CachePolicySpec::no_store()),
        serve_discovery: true,
        serve_jwks: true,
    };
    let server = require_ok(
        OidcTestServer::start(deterministic_factory("cache-no-store")?, spec).await,
        "start server",
    )?;

    let response = require_ok(
        http_client()?.get(server.jwks_url()).send().await,
        "jwks response",
    )?;
    ensure_eq!(response.status(), reqwest::StatusCode::OK);

    let header_value = require_ok(
        response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .ok_or("missing cache-control")
            .and_then(|value| value.to_str().map_err(|_| "non-ascii cache-control")),
        "cache-control header",
    )?
    .to_string();
    ensure_eq!(header_value, "no-store");

    // `no_store` keeps `emit_etag = false`, so no ETag header should be emitted.
    ensure!(
        !response.headers().contains_key(reqwest::header::ETAG),
        "no_store policy must not emit an ETag header"
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn cache_control_sent_without_etag_when_emit_etag_is_false() -> TestResult<()> {
    let spec = OidcServerSpec {
        issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
        jwks_rotation: JwksRotation::Static(JwksSpec::single_rsa("cc-only", RsaSpec::rs256())),
        cache_headers: Some(CachePolicySpec {
            max_age_seconds: 60,
            emit_etag: false,
        }),
        serve_discovery: true,
        serve_jwks: true,
    };
    let server = require_ok(
        OidcTestServer::start(deterministic_factory("cache-control-only")?, spec).await,
        "start server",
    )?;

    let response = require_ok(
        http_client()?.get(server.jwks_url()).send().await,
        "jwks response",
    )?;
    ensure_eq!(response.status(), reqwest::StatusCode::OK);

    let cc = require_ok(
        response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .ok_or("missing cache-control")
            .and_then(|value| value.to_str().map_err(|_| "non-ascii cache-control")),
        "cache-control header",
    )?;
    ensure_eq!(cc, "public, max-age=60");
    ensure!(
        !response.headers().contains_key(reqwest::header::ETAG),
        "emit_etag=false must not emit an ETag header"
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn discovery_endpoint_emits_body_derived_etag_when_caching_is_enabled() -> TestResult<()> {
    // The discovery endpoint runs through `cached_json_response` without a
    // `PhaseMaterial`, so the etag fallback (`unwrap_or_else`) computes a
    // body-hashed quoted etag string.
    let spec = OidcServerSpec {
        issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
        jwks_rotation: JwksRotation::Static(JwksSpec::single_rsa(
            "discovery-etag",
            RsaSpec::rs256(),
        )),
        cache_headers: Some(CachePolicySpec {
            max_age_seconds: 30,
            emit_etag: true,
        }),
        serve_discovery: true,
        serve_jwks: true,
    };
    let server = require_ok(
        OidcTestServer::start(deterministic_factory("discovery-etag")?, spec).await,
        "start server",
    )?;

    let response = require_ok(
        http_client()?.get(server.discovery_url()).send().await,
        "discovery response",
    )?;
    ensure_eq!(response.status(), reqwest::StatusCode::OK);

    let etag = require_ok(
        response
            .headers()
            .get(reqwest::header::ETAG)
            .ok_or("missing etag")
            .and_then(|value| value.to_str().map_err(|_| "non-ascii etag")),
        "etag header",
    )?
    .to_string();

    ensure!(
        etag.starts_with('"') && etag.ends_with('"') && etag.len() > 2,
        "discovery etag must be a non-empty quoted string, got {etag}"
    );

    // Discovery does not currently revalidate via If-None-Match (only the
    // phase-bearing JWKS endpoint does), so a request with the same etag
    // returns OK with the same etag — confirming the body-derived etag is
    // stable across repeated requests.
    let revalidate = require_ok(
        http_client()?
            .get(server.discovery_url())
            .header(reqwest::header::IF_NONE_MATCH, etag.clone())
            .send()
            .await,
        "second discovery response",
    )?;
    ensure_eq!(revalidate.status(), reqwest::StatusCode::OK);
    let second_etag = require_ok(
        revalidate
            .headers()
            .get(reqwest::header::ETAG)
            .ok_or("missing etag on revalidate")
            .and_then(|value| value.to_str().map_err(|_| "non-ascii etag")),
        "etag header on revalidate",
    )?;
    ensure_eq!(second_etag, etag);

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn revalidation_with_non_matching_etag_returns_full_body() -> TestResult<()> {
    // Exercises the JWKS endpoint's `If-None-Match` mismatch path: a tag that
    // does not equal the active phase's etag should produce a 200 with body,
    // not 304.
    let spec = OidcServerSpec {
        issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
        jwks_rotation: JwksRotation::Static(JwksSpec::single_rsa(
            "mismatched-etag",
            RsaSpec::rs256(),
        )),
        cache_headers: Some(CachePolicySpec {
            max_age_seconds: 60,
            emit_etag: true,
        }),
        serve_discovery: true,
        serve_jwks: true,
    };
    let server = require_ok(
        OidcTestServer::start(deterministic_factory("mismatched-etag")?, spec).await,
        "start server",
    )?;

    let response = require_ok(
        http_client()?
            .get(server.jwks_url())
            .header(reqwest::header::IF_NONE_MATCH, "\"not-the-actual-etag\"")
            .send()
            .await,
        "jwks response",
    )?;
    ensure_eq!(response.status(), reqwest::StatusCode::OK);
    ensure!(
        response.headers().contains_key(reqwest::header::ETAG),
        "mismatched revalidation must emit the fresh ETag header"
    );

    server.shutdown().await;
    Ok(())
}
