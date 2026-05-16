//! Coverage tests for `uselesskey-axum` builder methods, rotation phases,
//! and middleware reject paths.
//!
//! These tests are intentionally panic-free per the workspace no-panic-family
//! policy: assertions go through `uselesskey-test-support` helpers and tests
//! return `TestResult<()>` so failures surface as errors rather than panics.

use axum::body::Body;
use axum::http::{Request, StatusCode, header::AUTHORIZATION};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use tower::ServiceExt;
use uselesskey_axum::{
    AuthExpectations, DeterministicJwksPhase, MockJwtVerifierState, RotationPhase, TestAuthContext,
    inject_auth_context_layer, jwks_router, mock_jwt_verifier_layer, oidc_router,
};
use uselesskey_core::Seed;
use uselesskey_test_support::{TestResult, ensure, ensure_eq, require_ok};

const SEED_LABEL: &str = "uselesskey-axum-coverage-v1";
const ISSUER: &str = "https://issuer.example.test";
const AUDIENCE: &str = "api://example-aud";

fn phase(rotation: RotationPhase) -> TestResult<DeterministicJwksPhase> {
    let seed = require_ok(
        Seed::from_env_value(SEED_LABEL),
        "coverage seed must parse as a deterministic seed",
    )?;
    Ok(DeterministicJwksPhase::new(
        seed,
        "auth-suite",
        rotation,
        ISSUER,
        AUDIENCE,
    ))
}

fn verifier_state(rotation: RotationPhase) -> TestResult<MockJwtVerifierState> {
    Ok(MockJwtVerifierState::new(phase(rotation)?))
}

async fn run_protected(
    state: MockJwtVerifierState,
    request: Request<Body>,
) -> TestResult<Response> {
    let app =
        mock_jwt_verifier_layer(
            Router::new().route(
                "/me",
                get(|auth: TestAuthContext| async move {
                    Json(json!({"sub": auth.sub})).into_response()
                }),
            ),
            state,
        );
    require_ok(
        app.oneshot(request).await,
        "oneshot through verifier middleware should resolve",
    )
}

// `Response` re-exported here so the local helper signature does not need to
// pull `axum::response::Response` directly into every test scope.
type Response = axum::response::Response;

#[tokio::test]
async fn auth_expectations_with_issuer_replaces_only_issuer() -> TestResult<()> {
    let original = AuthExpectations::new("orig-iss", "orig-aud", "orig-kid");
    let updated = original.clone().with_issuer("new-iss");

    ensure_eq!(updated.issuer, "new-iss");
    ensure_eq!(updated.audience, "orig-aud");
    ensure_eq!(updated.kid, "orig-kid");
    ensure_eq!(original.issuer, "orig-iss");
    Ok(())
}

#[tokio::test]
async fn auth_expectations_with_audience_replaces_only_audience() -> TestResult<()> {
    let original = AuthExpectations::new("orig-iss", "orig-aud", "orig-kid");
    let updated = original.clone().with_audience("new-aud");

    ensure_eq!(updated.audience, "new-aud");
    ensure_eq!(updated.issuer, "orig-iss");
    ensure_eq!(updated.kid, "orig-kid");
    ensure_eq!(original.audience, "orig-aud");
    Ok(())
}

#[tokio::test]
async fn auth_expectations_with_kid_replaces_only_kid() -> TestResult<()> {
    let original = AuthExpectations::new("orig-iss", "orig-aud", "orig-kid");
    let updated = original.clone().with_kid("new-kid");

    ensure_eq!(updated.kid, "new-kid");
    ensure_eq!(updated.issuer, "orig-iss");
    ensure_eq!(updated.audience, "orig-aud");
    ensure_eq!(original.kid, "orig-kid");
    Ok(())
}

#[tokio::test]
async fn auth_expectations_builders_chain_independently() -> TestResult<()> {
    let chained = AuthExpectations::new("a", "b", "c")
        .with_issuer("iss-1")
        .with_audience("aud-1")
        .with_kid("kid-1");

    ensure_eq!(chained, AuthExpectations::new("iss-1", "aud-1", "kid-1"));
    Ok(())
}

#[tokio::test]
async fn auth_expectations_clone_round_trips_via_partial_eq() -> TestResult<()> {
    let original = AuthExpectations::new("iss", "aud", "kid");
    let cloned = original.clone();

    ensure_eq!(original, cloned);
    // PartialEq is sensitive to any field, so a single mutation breaks equality.
    ensure!(original != cloned.clone().with_kid("other-kid"));
    Ok(())
}

#[tokio::test]
async fn rotation_phase_next_produces_different_kid_than_primary() -> TestResult<()> {
    let primary = phase(RotationPhase::Primary)?;
    let next = phase(RotationPhase::Next)?;

    ensure!(
        primary.expectations().kid != next.expectations().kid,
        "Primary and Next rotation phases must derive distinct kids"
    );
    // Issuer/audience are configured directly, so they should match across phases.
    ensure_eq!(primary.expectations().issuer, next.expectations().issuer);
    ensure_eq!(
        primary.expectations().audience,
        next.expectations().audience
    );
    Ok(())
}

#[tokio::test]
async fn rotation_phase_is_deterministic_per_phase() -> TestResult<()> {
    let a = phase(RotationPhase::Next)?;
    let b = phase(RotationPhase::Next)?;
    ensure_eq!(a.expectations().kid, b.expectations().kid);
    Ok(())
}

#[tokio::test]
async fn middleware_rejects_missing_authorization_header() -> TestResult<()> {
    let state = verifier_state(RotationPhase::Primary)?;
    let request = require_ok(
        Request::builder().uri("/me").body(Body::empty()),
        "request builder",
    )?;

    let response = run_protected(state, request).await?;
    ensure_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = require_ok(
        axum::body::to_bytes(response.into_body(), usize::MAX).await,
        "read response body",
    )?;
    ensure_eq!(&body[..], b"missing authorization header");
    Ok(())
}

#[tokio::test]
async fn middleware_rejects_non_bearer_scheme() -> TestResult<()> {
    let state = verifier_state(RotationPhase::Primary)?;
    let request = require_ok(
        Request::builder()
            .uri("/me")
            .header(AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .body(Body::empty()),
        "request builder",
    )?;

    let response = run_protected(state, request).await?;
    ensure_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = require_ok(
        axum::body::to_bytes(response.into_body(), usize::MAX).await,
        "read response body",
    )?;
    ensure_eq!(&body[..], b"invalid authorization scheme");
    Ok(())
}

#[tokio::test]
async fn middleware_rejects_empty_bearer_token() -> TestResult<()> {
    let state = verifier_state(RotationPhase::Primary)?;
    let request = require_ok(
        Request::builder()
            .uri("/me")
            .header(AUTHORIZATION, "Bearer ")
            .body(Body::empty()),
        "request builder",
    )?;

    let response = run_protected(state, request).await?;
    ensure_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = require_ok(
        axum::body::to_bytes(response.into_body(), usize::MAX).await,
        "read response body",
    )?;
    ensure_eq!(&body[..], b"empty bearer token");
    Ok(())
}

#[tokio::test]
async fn middleware_rejects_malformed_jwt_with_invalid_header_message() -> TestResult<()> {
    let state = verifier_state(RotationPhase::Primary)?;
    let request = require_ok(
        Request::builder()
            .uri("/me")
            .header(AUTHORIZATION, "Bearer not.a.jwt")
            .body(Body::empty()),
        "request builder",
    )?;

    let response = run_protected(state, request).await?;
    ensure_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = require_ok(
        axum::body::to_bytes(response.into_body(), usize::MAX).await,
        "read response body",
    )?;
    ensure_eq!(&body[..], b"invalid jwt header");
    Ok(())
}

#[tokio::test]
async fn middleware_rejects_unexpected_kid() -> TestResult<()> {
    // Token signed by `Next`-phase key but verifier expects `Primary` key.
    let primary_state = verifier_state(RotationPhase::Primary)?;
    let next_phase = phase(RotationPhase::Next)?;
    let next_state = MockJwtVerifierState::new(next_phase);
    let token = next_state.issue_token(json!({"sub": "alice"}), 300);

    let request = require_ok(
        Request::builder()
            .uri("/me")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty()),
        "request builder",
    )?;

    let response = run_protected(primary_state, request).await?;
    ensure_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = require_ok(
        axum::body::to_bytes(response.into_body(), usize::MAX).await,
        "read response body",
    )?;
    ensure_eq!(&body[..], b"unexpected kid");
    Ok(())
}

#[tokio::test]
async fn oidc_json_is_identical_with_or_without_trailing_slash() -> TestResult<()> {
    let state = verifier_state(RotationPhase::Primary)?;
    let without = state.oidc_json("https://issuer.example.test");
    let with = state.oidc_json("https://issuer.example.test/");

    ensure_eq!(without, with);
    // jwks_uri must use a single slash between base and well-known path.
    ensure_eq!(
        without["jwks_uri"],
        json!("https://issuer.example.test/.well-known/jwks.json")
    );
    Ok(())
}

#[tokio::test]
async fn oidc_json_strips_only_trailing_slash_not_other_path_segments() -> TestResult<()> {
    let state = verifier_state(RotationPhase::Primary)?;
    let with_path = state.oidc_json("https://issuer.example.test/tenant");
    ensure_eq!(
        with_path["jwks_uri"],
        json!("https://issuer.example.test/tenant/.well-known/jwks.json")
    );
    Ok(())
}

#[tokio::test]
async fn oidc_router_serves_trimmed_base_url() -> TestResult<()> {
    let state = verifier_state(RotationPhase::Primary)?;
    let app = oidc_router(state.clone(), "https://issuer.example.test/");

    let request = require_ok(
        Request::builder()
            .uri("/.well-known/openid-configuration")
            .body(Body::empty()),
        "request builder",
    )?;
    let response = require_ok(app.oneshot(request).await, "oidc router oneshot")?;
    ensure_eq!(response.status(), StatusCode::OK);

    let body = require_ok(
        axum::body::to_bytes(response.into_body(), usize::MAX).await,
        "read response body",
    )?;
    let value: serde_json::Value =
        require_ok(serde_json::from_slice(&body), "parse oidc body json")?;
    ensure_eq!(
        value["jwks_uri"],
        json!("https://issuer.example.test/.well-known/jwks.json")
    );
    Ok(())
}

#[tokio::test]
async fn jwks_router_serves_state_jwks_payload() -> TestResult<()> {
    let state = verifier_state(RotationPhase::Primary)?;
    let app = jwks_router(state.clone());

    let request = require_ok(
        Request::builder()
            .uri("/.well-known/jwks.json")
            .body(Body::empty()),
        "request builder",
    )?;
    let response = require_ok(app.oneshot(request).await, "jwks router oneshot")?;
    ensure_eq!(response.status(), StatusCode::OK);

    let body = require_ok(
        axum::body::to_bytes(response.into_body(), usize::MAX).await,
        "read response body",
    )?;
    let value: serde_json::Value =
        require_ok(serde_json::from_slice(&body), "parse jwks body json")?;
    ensure_eq!(value, state.jwks_json());
    Ok(())
}

#[tokio::test]
async fn inject_auth_context_layer_makes_context_extractable() -> TestResult<()> {
    let context = TestAuthContext {
        sub: "test-user".into(),
        iss: "iss".into(),
        aud: "aud".into(),
        kid: "kid-1".into(),
        exp: 42,
    };
    let app = inject_auth_context_layer(
        Router::new().route(
            "/me",
            get(|auth: TestAuthContext| async move {
                Json(json!({"sub": auth.sub, "exp": auth.exp})).into_response()
            }),
        ),
        context.clone(),
    );

    let request = require_ok(
        Request::builder().uri("/me").body(Body::empty()),
        "request builder",
    )?;
    let response = require_ok(app.oneshot(request).await, "inject layer oneshot")?;
    ensure_eq!(response.status(), StatusCode::OK);

    let body = require_ok(
        axum::body::to_bytes(response.into_body(), usize::MAX).await,
        "read response body",
    )?;
    let value: serde_json::Value =
        require_ok(serde_json::from_slice(&body), "parse injected body json")?;
    ensure_eq!(value["sub"], json!(context.sub));
    ensure_eq!(value["exp"], json!(context.exp));
    Ok(())
}
