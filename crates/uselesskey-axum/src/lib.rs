#![forbid(unsafe_code)]

//! `axum` auth-test helpers built on deterministic `uselesskey` fixtures.
//!
//! This crate is intentionally test-focused and scoped to common drop-in needs:
//! - JWKS and OIDC discovery routers
//! - Bearer token verification middleware for tests
//! - Typed deterministic auth context extraction/injection

use axum::extract::{FromRequestParts, State};
use axum::http::{Request, StatusCode, header::AUTHORIZATION, request::Parts};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use uselesskey_core::{Factory, Seed};
use uselesskey_rsa::{RsaFactoryExt, RsaKeyPair, RsaSpec};

const DEFAULT_JWKS_PATH: &str = "/.well-known/jwks.json";
const DEFAULT_OIDC_PATH: &str = "/.well-known/openid-configuration";

/// Expected JWT shape for test verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthExpectations {
    /// Expected `iss` claim.
    pub issuer: String,
    /// Expected `aud` claim.
    pub audience: String,
    /// Expected key id from JWT header.
    pub kid: String,
}

impl AuthExpectations {
    /// Build expected issuer/audience/kid values.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        kid: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            kid: kid.into(),
        }
    }

    /// Replace expected issuer.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    /// Replace expected audience.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Replace expected kid.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = kid.into();
        self
    }
}

/// Deterministic JWT rotation phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationPhase {
    /// Primary signing key.
    Primary,
    /// Next key in deterministic rotation sequence.
    Next,
}

impl RotationPhase {
    fn suffix(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Next => "next",
        }
    }
}

/// Deterministic signer + JWKS test fixture for one rotation phase.
#[derive(Clone)]
pub struct DeterministicJwksPhase {
    keypair: RsaKeyPair,
    expectations: AuthExpectations,
}

impl DeterministicJwksPhase {
    /// Build deterministic material for a rotation phase.
    pub fn new(
        seed: Seed,
        label: impl AsRef<str>,
        phase: RotationPhase,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        let fx = Factory::deterministic(seed);
        let keypair = fx.rsa(
            format!("{}:{}", label.as_ref(), phase.suffix()),
            RsaSpec::rs256(),
        );
        let kid = keypair.kid();
        Self {
            keypair,
            expectations: AuthExpectations::new(issuer, audience, kid),
        }
    }

    /// Public JWKS payload for this phase.
    pub fn jwks_json(&self) -> Value {
        self.keypair.public_jwks_json()
    }

    /// Expected issuer/audience/kid values.
    pub fn expectations(&self) -> &AuthExpectations {
        &self.expectations
    }

    /// Create RS256 bearer token for test claims.
    pub fn issue_token(&self, mut claims: Value, ttl_seconds: u64) -> String {
        let now = current_unix_seconds();
        if claims.get("iss").is_none() {
            claims["iss"] = Value::String(self.expectations.issuer.clone());
        }
        if claims.get("aud").is_none() {
            claims["aud"] = Value::String(self.expectations.audience.clone());
        }
        if claims.get("iat").is_none() {
            claims["iat"] = Value::Number((now as u64).into());
        }
        if claims.get("exp").is_none() {
            claims["exp"] = Value::Number((now as u64 + ttl_seconds).into());
        }

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.expectations.kid.clone());

        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(self.keypair.private_key_pkcs8_pem().as_bytes())
                .expect("deterministic fixture key should produce valid RSA encoding key"),
        )
        .expect("deterministic fixture key should produce valid JWT")
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_rsa_pem(self.keypair.public_key_spki_pem().as_bytes())
            .expect("deterministic fixture key should produce valid RSA decoding key")
    }
}

/// Typed auth context inserted by helpers and extracted in handlers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestAuthContext {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub kid: String,
    pub exp: u64,
}

impl<S> FromRequestParts<S> for TestAuthContext
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "missing auth context"))
    }
}

/// Middleware verification state.
#[derive(Clone)]
pub struct MockJwtVerifierState {
    signer: DeterministicJwksPhase,
}

impl MockJwtVerifierState {
    /// Build middleware state from a deterministic phase.
    pub fn new(signer: DeterministicJwksPhase) -> Self {
        Self { signer }
    }

    /// Produce JWKS JSON served by [`jwks_router`].
    pub fn jwks_json(&self) -> Value {
        self.signer.jwks_json()
    }

    /// Produce OIDC discovery JSON served by [`oidc_router`].
    pub fn oidc_json(&self, base_url: impl AsRef<str>) -> Value {
        let base = base_url.as_ref().trim_end_matches('/');
        json!({
            "issuer": self.signer.expectations().issuer,
            "jwks_uri": format!("{base}{DEFAULT_JWKS_PATH}"),
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "response_types_supported": ["token"],
            "subject_types_supported": ["public"],
        })
    }

    /// Generate a valid bearer token for this state.
    pub fn issue_token(&self, claims: Value, ttl_seconds: u64) -> String {
        self.signer.issue_token(claims, ttl_seconds)
    }

    /// Clone expected claims checks.
    pub fn expectations(&self) -> AuthExpectations {
        self.signer.expectations().clone()
    }
}

/// Build a JWKS router mounted at `/.well-known/jwks.json`.
pub fn jwks_router(state: MockJwtVerifierState) -> Router {
    Router::new()
        .route(DEFAULT_JWKS_PATH, get(jwks_handler))
        .with_state(state)
}

/// Build an OIDC discovery router mounted at `/.well-known/openid-configuration`.
pub fn oidc_router(state: MockJwtVerifierState, base_url: impl Into<String>) -> Router {
    let state = OidcState {
        verifier: state,
        base_url: base_url.into(),
    };
    Router::new()
        .route(DEFAULT_OIDC_PATH, get(oidc_handler))
        .with_state(state)
}

/// Attach a middleware layer that verifies bearer tokens and inserts [`TestAuthContext`].
pub fn mock_jwt_verifier_layer(router: Router, state: MockJwtVerifierState) -> Router {
    let state = Arc::new(state);
    router.layer(axum::middleware::from_fn(move |request, next| {
        let state = Arc::clone(&state);
        async move { verify_bearer_token(state.as_ref().clone(), request, next).await }
    }))
}

/// Attach a middleware layer that injects a deterministic auth context without JWT parsing.
pub fn inject_auth_context_layer(router: Router, context: TestAuthContext) -> Router {
    let context = Arc::new(context);
    router.layer(axum::middleware::from_fn(move |request, next| {
        let context = Arc::clone(&context);
        async move { inject_auth_context(context.as_ref().clone(), request, next).await }
    }))
}

#[derive(Clone)]
struct OidcState {
    verifier: MockJwtVerifierState,
    base_url: String,
}

async fn jwks_handler(State(state): State<MockJwtVerifierState>) -> Json<Value> {
    Json(state.jwks_json())
}

async fn oidc_handler(State(state): State<OidcState>) -> Json<Value> {
    Json(state.verifier.oidc_json(&state.base_url))
}

async fn inject_auth_context(
    context: TestAuthContext,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    request.extensions_mut().insert(context);
    next.run(request).await
}

async fn verify_bearer_token(
    state: MockJwtVerifierState,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let bearer = match extract_bearer(request.headers()) {
        Ok(token) => token,
        Err((code, msg)) => return (code, msg).into_response(),
    };

    let header = match decode_header(bearer) {
        Ok(header) => header,
        Err(_) => return (StatusCode::UNAUTHORIZED, "invalid jwt header").into_response(),
    };

    let expected = state.expectations();
    if header.kid.as_deref() != Some(expected.kid.as_str()) {
        return (StatusCode::UNAUTHORIZED, "unexpected kid").into_response();
    }

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[expected.issuer.clone()]);
    validation.set_audience(&[expected.audience.clone()]);
    validation.leeway = 0;

    let token = match decode::<Value>(bearer, &state.signer.decoding_key(), &validation) {
        Ok(token) => token,
        Err(_) => return (StatusCode::UNAUTHORIZED, "token verification failed").into_response(),
    };

    let sub = token
        .claims
        .get("sub")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let iss = token
        .claims
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let aud = token
        .claims
        .get("aud")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let exp = token
        .claims
        .get("exp")
        .and_then(Value::as_u64)
        .unwrap_or_default();

    request.extensions_mut().insert(TestAuthContext {
        sub,
        iss,
        aud,
        kid: expected.kid,
        exp,
    });

    next.run(request).await
}

fn extract_bearer(headers: &axum::http::HeaderMap) -> Result<&str, (StatusCode, &'static str)> {
    let header = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "missing authorization header"))?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or((StatusCode::UNAUTHORIZED, "invalid authorization scheme"))?;
    if token.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "empty bearer token"));
    }
    Ok(token)
}

fn current_unix_seconds() -> usize {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("current time should be >= unix epoch")
        .as_secs() as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use tower::ServiceExt;

    fn phase(phase: RotationPhase) -> DeterministicJwksPhase {
        let seed = Seed::from_env_value("uselesskey-axum-tests").expect("seed parse");
        DeterministicJwksPhase::new(
            seed,
            "auth-suite",
            phase,
            "https://issuer.example.test",
            "api://example-aud",
        )
    }

    #[tokio::test]
    async fn jwks_and_oidc_routes_respond() {
        let state = MockJwtVerifierState::new(phase(RotationPhase::Primary));
        let app = jwks_router(state.clone()).merge(oidc_router(state, "http://localhost:3000"));

        let jwks_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(DEFAULT_JWKS_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(jwks_res.status(), StatusCode::OK);

        let oidc_res = app
            .oneshot(
                Request::builder()
                    .uri(DEFAULT_OIDC_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(oidc_res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rotation_phase_produces_distinct_kids() {
        let primary = phase(RotationPhase::Primary);
        let next = phase(RotationPhase::Next);
        assert_ne!(primary.expectations().kid, next.expectations().kid);
    }

    #[tokio::test]
    async fn verifier_rejects_wrong_audience() {
        let state = MockJwtVerifierState::new(phase(RotationPhase::Primary));
        let token = state.issue_token(json!({"sub":"alice", "aud":"api://wrong-aud"}), 300);

        let app = mock_jwt_verifier_layer(
            Router::new().route(
                "/me",
                get(|auth: TestAuthContext| async move {
                    Json(json!({"sub": auth.sub})).into_response()
                }),
            ),
            state,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/me")
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn verifier_rejects_expired_token() {
        let state = MockJwtVerifierState::new(phase(RotationPhase::Primary));
        let now = current_unix_seconds() as u64;
        let token = state.issue_token(
            json!({"sub":"alice", "exp": now.saturating_sub(5), "iat": now.saturating_sub(10)}),
            300,
        );

        let app = mock_jwt_verifier_layer(
            Router::new().route("/me", get(|| async { StatusCode::OK })),
            state,
        );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/me")
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn deterministic_auth_context_injection_works() {
        let app = inject_auth_context_layer(
            Router::new().route(
                "/me",
                get(|auth: TestAuthContext| async move {
                    Json(json!({"sub": auth.sub, "kid": auth.kid})).into_response()
                }),
            ),
            TestAuthContext {
                sub: "test-user".into(),
                iss: "iss".into(),
                aud: "aud".into(),
                kid: "kid-1".into(),
                exp: 42,
            },
        );

        let response = app
            .oneshot(Request::builder().uri("/me").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
