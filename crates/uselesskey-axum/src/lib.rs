#![forbid(unsafe_code)]

//! Axum auth-test helpers for deterministic JWT/JWKS/OIDC fixture flows.
//!
//! This crate is intentionally test-scoped.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    extract::{FromRequestParts, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use http::request::Parts;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use tower_layer::Layer;
use tower_service::Service;

const DEFAULT_JWKS_PATH: &str = "/.well-known/jwks.json";
const DEFAULT_OIDC_PATH: &str = "/.well-known/openid-configuration";

/// Expected identity values for deterministic auth tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedAuthValues {
    issuer: String,
    audience: String,
    kid: Option<String>,
}

impl ExpectedAuthValues {
    /// Create required issuer + audience expectations.
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            kid: None,
        }
    }

    /// Optionally require a specific JWT `kid` header value.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

/// Per-request deterministic auth context inserted by [`mock_jwt_verifier_layer`].
#[derive(Debug, Clone)]
pub struct TestAuthContext {
    subject: String,
    issuer: Option<String>,
    audience: Vec<String>,
    kid: Option<String>,
    expires_at: Option<i64>,
    claims: Value,
}

impl TestAuthContext {
    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    pub fn audience(&self) -> &[String] {
        &self.audience
    }

    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    pub fn expires_at(&self) -> Option<i64> {
        self.expires_at
    }

    pub fn claims(&self) -> &Value {
        &self.claims
    }
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
            .ok_or((StatusCode::UNAUTHORIZED, "missing test auth context"))
    }
}

/// Build a router that serves JWKS JSON at `/.well-known/jwks.json`.
pub fn jwks_router() -> Router {
    jwks_router_with_phases(vec![serde_json::json!({"keys": []})])
}

/// Build a JWKS router with deterministic rotation phases.
///
/// The phase can be selected via query parameter `?phase=<idx>`.
pub fn jwks_router_with_phases(phases: Vec<Value>) -> Router {
    let state = Arc::new(JwksState::new(phases));
    Router::new()
        .route(DEFAULT_JWKS_PATH, get(jwks_handler))
        .with_state(state)
}

/// Build an OIDC discovery router at `/.well-known/openid-configuration`.
pub fn oidc_router(issuer: impl Into<String>, jwks_uri: impl Into<String>) -> Router {
    let state = Arc::new(OidcState {
        issuer: issuer.into(),
        jwks_uri: jwks_uri.into(),
    });
    Router::new()
        .route(DEFAULT_OIDC_PATH, get(oidc_handler))
        .with_state(state)
}

#[derive(Debug, Clone)]
struct JwksState {
    phases: Vec<Value>,
}

impl JwksState {
    fn new(mut phases: Vec<Value>) -> Self {
        if phases.is_empty() {
            phases.push(serde_json::json!({"keys": []}));
        }
        Self { phases }
    }

    fn phase(&self, idx: usize) -> Value {
        self.phases
            .get(idx)
            .cloned()
            .or_else(|| self.phases.last().cloned())
            .unwrap_or_else(|| serde_json::json!({"keys": []}))
    }
}

#[derive(Debug, Deserialize)]
struct PhaseQuery {
    phase: Option<usize>,
}

async fn jwks_handler(
    State(state): State<Arc<JwksState>>,
    Query(query): Query<PhaseQuery>,
) -> impl IntoResponse {
    Json(state.phase(query.phase.unwrap_or_default()))
}

#[derive(Debug, Clone)]
struct OidcState {
    issuer: String,
    jwks_uri: String,
}

#[derive(Debug, Serialize)]
struct OidcConfiguration {
    issuer: String,
    jwks_uri: String,
    token_endpoint_auth_signing_alg_values_supported: Vec<&'static str>,
    id_token_signing_alg_values_supported: Vec<&'static str>,
}

async fn oidc_handler(State(state): State<Arc<OidcState>>) -> impl IntoResponse {
    Json(OidcConfiguration {
        issuer: state.issuer.clone(),
        jwks_uri: state.jwks_uri.clone(),
        token_endpoint_auth_signing_alg_values_supported: vec!["RS256"],
        id_token_signing_alg_values_supported: vec!["RS256"],
    })
}

/// Configuration for [`mock_jwt_verifier_layer`].
#[derive(Debug, Clone)]
pub struct MockJwtVerifierConfig {
    expected: ExpectedAuthValues,
    keys_by_kid: BTreeMap<String, DecodingKey>,
    fallback_key: Option<DecodingKey>,
    now_unix: Option<i64>,
}

impl MockJwtVerifierConfig {
    pub fn new(expected: ExpectedAuthValues) -> Self {
        Self {
            expected,
            keys_by_kid: BTreeMap::new(),
            fallback_key: None,
            now_unix: None,
        }
    }

    /// Add a decoding key that matches a specific `kid` header.
    pub fn with_decoding_key_for_kid(
        mut self,
        kid: impl Into<String>,
        key: DecodingKey,
    ) -> Self {
        self.keys_by_kid.insert(kid.into(), key);
        self
    }

    /// Set a fallback decoding key for tokens without `kid`.
    pub fn with_fallback_decoding_key(mut self, key: DecodingKey) -> Self {
        self.fallback_key = Some(key);
        self
    }

    /// Override current unix timestamp for deterministic expiry tests.
    pub fn with_now_unix(mut self, now_unix: i64) -> Self {
        self.now_unix = Some(now_unix);
        self
    }
}

impl MockJwtVerifierConfig {
    /// Convenience helper for uselesskey RSA fixtures.
    pub fn with_rsa_keypair(mut self, keypair: &uselesskey_rsa::RsaKeyPair) -> Self {
        let key = DecodingKey::from_rsa_pem(keypair.public_key_spki_pem().as_bytes())
            .expect("valid uselesskey RSA public key PEM");
        self.keys_by_kid.insert(keypair.kid(), key);
        self
    }
}

/// Build a test-only bearer JWT verification layer.
pub fn mock_jwt_verifier_layer(config: MockJwtVerifierConfig) -> MockJwtVerifierLayer {
    MockJwtVerifierLayer {
        config: Arc::new(config),
    }
}

/// Tower layer that verifies bearer JWTs and injects [`TestAuthContext`].
#[derive(Clone, Debug)]
pub struct MockJwtVerifierLayer {
    config: Arc<MockJwtVerifierConfig>,
}

impl<S> Layer<S> for MockJwtVerifierLayer {
    type Service = MockJwtVerifierService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MockJwtVerifierService {
            inner,
            config: Arc::clone(&self.config),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MockJwtVerifierService<S> {
    inner: S,
    config: Arc<MockJwtVerifierConfig>,
}

impl<S, B> Service<http::Request<B>> for MockJwtVerifierService<S>
where
    S: Service<http::Request<B>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        let maybe_ctx = build_auth_context(req.headers(), &self.config);

        match maybe_ctx {
            Ok(ctx) => {
                req.extensions_mut().insert(ctx);
                let mut inner = self.inner.clone();
                Box::pin(async move { inner.call(req).await })
            }
            Err((status, message)) => {
                let response = (status, message).into_response();
                Box::pin(async move { Ok(response) })
            }
        }
    }
}

fn build_auth_context(
    headers: &http::HeaderMap,
    config: &MockJwtVerifierConfig,
) -> Result<TestAuthContext, (StatusCode, &'static str)> {
    let authz = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "missing authorization header"))?;

    let token = authz
        .strip_prefix("Bearer ")
        .ok_or((StatusCode::UNAUTHORIZED, "authorization must be Bearer"))?;

    let header = decode_header(token).map_err(|_| (StatusCode::UNAUTHORIZED, "invalid jwt"))?;

    let kid = header.kid.clone();
    if config.expected.kid().is_some() && kid.as_deref() != config.expected.kid() {
        return Err((StatusCode::UNAUTHORIZED, "unexpected kid"));
    }

    let key = select_decoding_key(config, kid.as_deref())?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[config.expected.issuer()]);
    validation.set_audience(&[config.expected.audience()]);
    validation.validate_exp = true;
    if let Some(now_unix) = config.now_unix {
        validation.validate_nbf = false;
        validation.reject_tokens_expiring_in_less_than = 0;
        validation.leeway = 0;
        validation.validate_exp = false;

        let token_data = decode::<Value>(token, key, &Validation::new(Algorithm::RS256))
            .map_err(|_| (StatusCode::UNAUTHORIZED, "jwt verification failed"))?;
        return validate_claims_after_decode(token_data.claims, kid, config, now_unix);
    }

    let token_data = decode::<Value>(token, key, &validation)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "jwt verification failed"))?;

    value_to_context(token_data.claims, kid)
}

fn validate_claims_after_decode(
    claims: Value,
    kid: Option<String>,
    config: &MockJwtVerifierConfig,
    now_unix: i64,
) -> Result<TestAuthContext, (StatusCode, &'static str)> {
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or((StatusCode::UNAUTHORIZED, "missing iss claim"))?;
    if iss != config.expected.issuer() {
        return Err((StatusCode::UNAUTHORIZED, "unexpected issuer"));
    }

    let aud_ok = audience_values(&claims)
        .iter()
        .any(|aud| aud == config.expected.audience());
    if !aud_ok {
        return Err((StatusCode::UNAUTHORIZED, "unexpected audience"));
    }

    if let Some(exp) = claims.get("exp").and_then(Value::as_i64)
        && exp <= now_unix
    {
        return Err((StatusCode::UNAUTHORIZED, "token expired"));
    }

    value_to_context(claims, kid)
}

fn audience_values(claims: &Value) -> Vec<String> {
    match claims.get("aud") {
        Some(Value::String(single)) => vec![single.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn select_decoding_key<'a>(
    config: &'a MockJwtVerifierConfig,
    kid: Option<&str>,
) -> Result<&'a DecodingKey, (StatusCode, &'static str)> {
    if let Some(kid) = kid {
        return config
            .keys_by_kid
            .get(kid)
            .ok_or((StatusCode::UNAUTHORIZED, "unknown kid"));
    }

    config
        .fallback_key
        .as_ref()
        .or_else(|| config.keys_by_kid.values().next())
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "no decoding keys configured"))
}

fn value_to_context(
    claims: Value,
    kid: Option<String>,
) -> Result<TestAuthContext, (StatusCode, &'static str)> {
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .unwrap_or("test-subject")
        .to_owned();

    Ok(TestAuthContext {
        subject,
        issuer: claims.get("iss").and_then(Value::as_str).map(str::to_owned),
        audience: audience_values(&claims),
        kid,
        expires_at: claims.get("exp").and_then(Value::as_i64),
        claims,
    })
}

/// Build a deterministic claim-set helper for tests.
pub fn deterministic_claims<T>(claims: T) -> Value
where
    T: Serialize + DeserializeOwned,
{
    let value = serde_json::to_value(claims).expect("serializable claims");
    canonicalize_json(value)
}

fn canonicalize_json(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut ordered = BTreeMap::<String, Value>::new();
            for (k, v) in map {
                ordered.insert(k, canonicalize_json(v));
            }
            Value::Object(ordered.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_json).collect()),
        primitive => primitive,
    }
}

/// Helper listing a deterministic set of expected audience values.
pub fn expected_audiences(primary: &str, additional: &[&str]) -> Vec<String> {
    let mut values = BTreeSet::new();
    values.insert(primary.to_owned());
    for aud in additional {
        values.insert((*aud).to_owned());
    }
    values.into_iter().collect()
}
