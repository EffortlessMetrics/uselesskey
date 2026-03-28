#![forbid(unsafe_code)]

//! Axum auth test helpers for deterministic JWT/JWKS/OIDC fixtures.
//!
//! This crate is test-oriented and intentionally not production middleware.

use axum::{
    Json, Router,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::get,
};
use futures_util::future::BoxFuture;
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tower::{Layer, Service};
use uselesskey_core::Factory;
use uselesskey_jose_openid::JoseOpenIdKeyExt;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

/// Expected JWT metadata for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedAuthValues {
    pub issuer: String,
    pub audience: String,
    pub kid: String,
}

impl ExpectedAuthValues {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>, kid: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            kid: kid.into(),
        }
    }
}

/// Deterministic auth server config for JWKS/OIDC routes.
#[derive(Debug, Clone)]
pub struct AuthServerConfig {
    pub seed: String,
    pub label: String,
    pub issuer: String,
    pub jwks_path: String,
    pub oidc_path: String,
    pub phases: Vec<String>,
}

impl Default for AuthServerConfig {
    fn default() -> Self {
        Self {
            seed: "uselesskey-axum-default-seed-v1".to_string(),
            label: "auth".to_string(),
            issuer: "https://issuer.test".to_string(),
            jwks_path: "/.well-known/jwks.json".to_string(),
            oidc_path: "/.well-known/openid-configuration".to_string(),
            phases: vec!["phase0".to_string()],
        }
    }
}

/// Test verifier config for bearer middleware.
#[derive(Debug, Clone)]
pub struct JwtVerifierConfig {
    pub seed: String,
    pub label: String,
    pub expected: ExpectedAuthValues,
    pub algorithm: Algorithm,
}

impl JwtVerifierConfig {
    pub fn deterministic(seed: impl Into<String>, label: impl Into<String>, issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        let seed = seed.into();
        let label = label.into();
        let keypair = Factory::deterministic_from_str(&seed).rsa(&label, RsaSpec::rs256());
        Self {
            seed,
            label,
            expected: ExpectedAuthValues::new(issuer, audience, keypair.kid()),
            algorithm: Algorithm::RS256,
        }
    }

    pub fn with_expected_values(mut self, expected: ExpectedAuthValues) -> Self {
        self.expected = expected;
        self
    }
}

/// Claims/context inserted into request extensions by [`mock_jwt_verifier_layer`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestAuthContext {
    pub token: String,
    pub claims: Value,
    pub issuer: Option<String>,
    pub audiences: Vec<String>,
    pub subject: Option<String>,
    pub kid: Option<String>,
}

impl<S> FromRequestParts<S> for TestAuthContext
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<TestAuthContext>()
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "missing auth context"))
    }
}

#[derive(Debug, Clone, Serialize)]
struct OidcDiscoveryDoc {
    issuer: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct PhaseQuery {
    phase: Option<String>,
}

/// Build a JWKS router at `config.jwks_path`.
pub fn jwks_router(config: AuthServerConfig) -> Router {
    Router::new().route(
        &config.jwks_path,
        get(
            move |query: axum::extract::Query<PhaseQuery>| async move {
                Json(jwks_for_phase(
                    &config.seed,
                    &config.label,
                    &config.phases,
                    query.phase.as_deref(),
                ))
            },
        ),
    )
}

/// Build an OIDC discovery router at `config.oidc_path`.
pub fn oidc_router(config: AuthServerConfig) -> Router {
    let jwks_path = config.jwks_path.clone();
    Router::new().route(
        &config.oidc_path,
        get(move || async move {
            Json(OidcDiscoveryDoc {
                issuer: config.issuer.clone(),
                jwks_uri: format!("{}{}", config.issuer, jwks_path),
            })
        }),
    )
}

/// Build test middleware that validates bearer JWTs and injects [`TestAuthContext`].
pub fn mock_jwt_verifier_layer(config: JwtVerifierConfig) -> MockJwtVerifierLayer {
    MockJwtVerifierLayer { config }
}

/// Layer that validates bearer tokens for tests.
#[derive(Debug, Clone)]
pub struct MockJwtVerifierLayer {
    config: JwtVerifierConfig,
}

impl MockJwtVerifierLayer {
    pub fn with_expected_values(mut self, expected: ExpectedAuthValues) -> Self {
        self.config = self.config.with_expected_values(expected);
        self
    }
}

impl<S> Layer<S> for MockJwtVerifierLayer
where
    S: Clone,
{
    type Service = MockJwtVerifierService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MockJwtVerifierService {
            inner,
            config: self.config.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MockJwtVerifierService<S> {
    inner: S,
    config: JwtVerifierConfig,
}

impl<S, B> Service<http::Request<B>> for MockJwtVerifierService<S>
where
    S: Service<http::Request<B>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        let mut inner = self.inner.clone();
        let config = self.config.clone();

        Box::pin(async move {
            let Some(token) = bearer_token(req.headers().get(http::header::AUTHORIZATION)) else {
                return Ok((StatusCode::UNAUTHORIZED, "missing bearer token").into_response());
            };

            let keypair = Factory::deterministic_from_str(&config.seed).rsa(&config.label, RsaSpec::rs256());

            let header = match decode_header(&token) {
                Ok(header) => header,
                Err(_) => return Ok((StatusCode::UNAUTHORIZED, "invalid token header").into_response()),
            };

            if header.kid.as_deref() != Some(config.expected.kid.as_str()) {
                return Ok((StatusCode::UNAUTHORIZED, "unexpected kid").into_response());
            }

            let mut validation = Validation::new(config.algorithm);
            validation.validate_exp = true;
            validation.set_issuer(&[config.expected.issuer.clone()]);
            validation.set_audience(&[config.expected.audience.clone()]);

            let decoded = match decode::<Value>(&token, &keypair.decoding_key(), &validation) {
                Ok(decoded) => decoded,
                Err(_) => return Ok((StatusCode::UNAUTHORIZED, "token verification failed").into_response()),
            };

            let claims = decoded.claims;
            let ctx = TestAuthContext {
                token,
                issuer: claims.get("iss").and_then(Value::as_str).map(ToOwned::to_owned),
                audiences: audience_values(&claims),
                subject: claims.get("sub").and_then(Value::as_str).map(ToOwned::to_owned),
                kid: header.kid,
                claims,
            };

            req.extensions_mut().insert(ctx);
            inner.call(req).await
        })
    }
}

fn bearer_token(value: Option<&http::HeaderValue>) -> Option<String> {
    let value = value?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(ToOwned::to_owned)
}

fn audience_values(claims: &Value) -> Vec<String> {
    match claims.get("aud") {
        Some(Value::String(aud)) => vec![aud.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

fn jwks_for_phase(seed: &str, label: &str, phases: &[String], requested_phase: Option<&str>) -> Value {
    let phase = requested_phase
        .filter(|candidate| phases.iter().any(|phase| phase == *candidate))
        .unwrap_or_else(|| phases.first().map(String::as_str).unwrap_or("phase0"));

    let keypair = Factory::deterministic_from_str(seed).rsa(&format!("{label}:{phase}"), RsaSpec::rs256());
    keypair.public_jwks_json()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwks_phase_changes_kid() {
        let config = AuthServerConfig {
            phases: vec!["phase0".into(), "phase1".into()],
            ..Default::default()
        };

        let phase0 = jwks_for_phase(&config.seed, &config.label, &config.phases, Some("phase0"));
        let phase1 = jwks_for_phase(&config.seed, &config.label, &config.phases, Some("phase1"));

        let kid0 = phase0["keys"][0]["kid"].as_str().unwrap();
        let kid1 = phase1["keys"][0]["kid"].as_str().unwrap();

        assert_ne!(kid0, kid1);
    }
}
