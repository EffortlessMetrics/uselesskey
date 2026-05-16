//! Coverage for fallback branches in the `uselesskey-axum` verifier and the
//! `TestAuthContext` extractor's missing-context rejection.
//!
//! These tests exercise paths that the happy-path integration tests do not:
//! - Tokens that omit `sub`, `iss`, or `aud` claims and rely on the
//!   `unwrap_or(...)` / `unwrap_or_default()` fallbacks in
//!   `verify_bearer_token`.
//! - `TestAuthContext::from_request_parts` returning `401 UNAUTHORIZED` when
//!   no context has been injected into request extensions.
//!
//! Tests are panic-free and follow the same `TestResult<()>` pattern used by
//! `accessors.rs`.
//!
//! Note: a token that omits `exp` cannot reach the extractor through the
//! public middleware because `jsonwebtoken`'s default validation lists `exp`
//! in `required_spec_claims` and rejects the token at verification time. The
//! `exp.unwrap_or_default()` branch in `verify_bearer_token` is therefore
//! defensive code that is unreachable via the public API; the corresponding
//! test is intentionally omitted.

use axum::body::Body;
use axum::http::{Request, StatusCode, header::AUTHORIZATION};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uselesskey_axum::{
    DeterministicJwksPhase, MockJwtVerifierState, RotationPhase, TestAuthContext,
    mock_jwt_verifier_layer,
};
use uselesskey_core::{Factory, Seed};
use uselesskey_rsa::{RsaFactoryExt, RsaKeyPair, RsaSpec};
use uselesskey_test_support::{TestResult, ensure_eq, require_ok};

const SEED_LABEL: &str = "uselesskey-axum-fallbacks-v1";
const ISSUER: &str = "https://issuer.example.test";
const AUDIENCE: &str = "api://example-aud";

fn phase() -> TestResult<DeterministicJwksPhase> {
    let seed = require_ok(
        Seed::from_env_value(SEED_LABEL),
        "fallbacks seed must parse as a deterministic seed",
    )?;
    Ok(DeterministicJwksPhase::new(
        seed,
        "auth-suite",
        RotationPhase::Primary,
        ISSUER,
        AUDIENCE,
    ))
}

fn verifier_state() -> TestResult<MockJwtVerifierState> {
    Ok(MockJwtVerifierState::new(phase()?))
}

/// Recreate the same deterministic RSA keypair the verifier expects, so we
/// can hand-craft tokens with arbitrary claim shapes (including omitted
/// `sub`/`iss`/`aud`) that still verify against the JWKS the middleware
/// uses.
fn signing_keypair() -> TestResult<RsaKeyPair> {
    let seed = require_ok(
        Seed::from_env_value(SEED_LABEL),
        "fallbacks seed must parse as a deterministic seed",
    )?;
    let fx = Factory::deterministic(seed);
    Ok(fx.rsa("auth-suite:primary", RsaSpec::rs256()))
}

fn sign_token(key: &RsaKeyPair, kid: &str, claims: &Value) -> TestResult<String> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    let encoding_key = require_ok(
        EncodingKey::from_rsa_pem(key.private_key_pkcs8_pem().as_bytes()),
        "deterministic fixture key must produce a valid RSA encoding key",
    )?;
    require_ok(
        encode(&header, claims, &encoding_key),
        "deterministic fixture key must produce a valid JWT",
    )
}

fn current_unix_seconds() -> TestResult<u64> {
    let duration = require_ok(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH),
        "system clock must be at or after the unix epoch",
    )?;
    Ok(duration.as_secs())
}

/// Build an app that echoes the extracted `TestAuthContext` into the response
/// body so tests can assert on the post-fallback values.
fn echoing_app(state: MockJwtVerifierState) -> Router {
    mock_jwt_verifier_layer(
        Router::new().route(
            "/me",
            get(|auth: TestAuthContext| async move {
                Json(json!({
                    "sub": auth.sub,
                    "iss": auth.iss,
                    "aud": auth.aud,
                    "kid": auth.kid,
                    "exp": auth.exp,
                }))
                .into_response()
            }),
        ),
        state,
    )
}

async fn read_json_body(response: axum::response::Response) -> TestResult<Value> {
    let body = require_ok(
        axum::body::to_bytes(response.into_body(), usize::MAX).await,
        "read response body",
    )?;
    require_ok(serde_json::from_slice(&body), "parse response body as json")
}

#[tokio::test]
async fn missing_sub_claim_falls_back_to_unknown_sentinel() -> TestResult<()> {
    let state = verifier_state()?;
    let key = signing_keypair()?;
    let kid = state.expectations().kid.clone();
    let now = current_unix_seconds()?;

    // Token deliberately omits `sub` while preserving the iss/aud/exp values
    // the middleware verifies, so verification succeeds and extraction must
    // fall back to the `unwrap_or("unknown")` sentinel.
    let claims = json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 300,
        "iat": now,
    });
    let token = sign_token(&key, &kid, &claims)?;

    let request = require_ok(
        Request::builder()
            .uri("/me")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty()),
        "request builder",
    )?;

    let response = require_ok(
        echoing_app(state).oneshot(request).await,
        "echoing app oneshot",
    )?;
    ensure_eq!(response.status(), StatusCode::OK);

    let value = read_json_body(response).await?;
    ensure_eq!(value["sub"], json!("unknown"));
    ensure_eq!(value["iss"], json!(ISSUER));
    ensure_eq!(value["aud"], json!(AUDIENCE));
    Ok(())
}

#[tokio::test]
async fn missing_iss_claim_falls_back_to_empty_string() -> TestResult<()> {
    let state = verifier_state()?;
    let key = signing_keypair()?;
    let kid = state.expectations().kid.clone();
    let now = current_unix_seconds()?;

    // jsonwebtoken only validates `iss` when present in the token, so omitting
    // it lets verification succeed and forces the `unwrap_or_default()`
    // fallback on the `iss` claim extraction.
    let claims = json!({
        "sub": "alice",
        "aud": AUDIENCE,
        "exp": now + 300,
        "iat": now,
    });
    let token = sign_token(&key, &kid, &claims)?;

    let request = require_ok(
        Request::builder()
            .uri("/me")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty()),
        "request builder",
    )?;

    let response = require_ok(
        echoing_app(state).oneshot(request).await,
        "echoing app oneshot",
    )?;
    ensure_eq!(response.status(), StatusCode::OK);

    let value = read_json_body(response).await?;
    ensure_eq!(value["sub"], json!("alice"));
    ensure_eq!(value["iss"], json!(""));
    ensure_eq!(value["aud"], json!(AUDIENCE));
    Ok(())
}

#[tokio::test]
async fn missing_aud_claim_falls_back_to_empty_string() -> TestResult<()> {
    let state = verifier_state()?;
    let key = signing_keypair()?;
    let kid = state.expectations().kid.clone();
    let now = current_unix_seconds()?;

    // jsonwebtoken only validates `aud` when present in the token, so omitting
    // it lets verification succeed and forces the `unwrap_or_default()`
    // fallback on the `aud` claim extraction.
    let claims = json!({
        "sub": "alice",
        "iss": ISSUER,
        "exp": now + 300,
        "iat": now,
    });
    let token = sign_token(&key, &kid, &claims)?;

    let request = require_ok(
        Request::builder()
            .uri("/me")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty()),
        "request builder",
    )?;

    let response = require_ok(
        echoing_app(state).oneshot(request).await,
        "echoing app oneshot",
    )?;
    ensure_eq!(response.status(), StatusCode::OK);

    let value = read_json_body(response).await?;
    ensure_eq!(value["sub"], json!("alice"));
    ensure_eq!(value["iss"], json!(ISSUER));
    ensure_eq!(value["aud"], json!(""));
    Ok(())
}

#[tokio::test]
async fn test_auth_context_extractor_rejects_when_not_injected() -> TestResult<()> {
    // No middleware layer inserts `TestAuthContext`, so the extractor's
    // `FromRequestParts` impl must return `(401, "missing auth context")`.
    let app = Router::new().route(
        "/me",
        get(|auth: TestAuthContext| async move { Json(json!({"sub": auth.sub})).into_response() }),
    );

    let request = require_ok(
        Request::builder().uri("/me").body(Body::empty()),
        "request builder",
    )?;

    let response = require_ok(app.oneshot(request).await, "uninjected app oneshot")?;
    ensure_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = require_ok(
        axum::body::to_bytes(response.into_body(), usize::MAX).await,
        "read response body",
    )?;
    ensure_eq!(&body[..], b"missing auth context");
    Ok(())
}
