#![forbid(unsafe_code)]

//! Drop-in auth-test helpers for `axum` apps built on `uselesskey` fixtures.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{FromRequestParts, State};
use axum::http::{Request, StatusCode, header};
use axum::middleware::{self, Next};
use tower::ServiceBuilder;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uselesskey_jwk::{Jwks, JwksBuilder};
use uselesskey_rsa::RsaKeyPair;

/// OIDC discovery path.
pub const DEFAULT_OIDC_PATH: &str = "/.well-known/openid-configuration";
/// JWKS path.
pub const DEFAULT_JWKS_PATH: &str = "/.well-known/jwks.json";

/// Expected auth values used by mock verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedAuthValues {
    /// Expected `iss` claim.
    pub issuer: String,
    /// Expected `aud` claim.
    pub audience: String,
    /// Optional expected `kid` header value.
    pub kid: Option<String>,
}

impl ExpectedAuthValues {
    /// Build expected values for issuer + audience.
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            kid: None,
        }
    }

    /// Set expected `kid` value.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }
}

/// Verified test auth context injected into request extensions by middleware.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestAuthContext {
    /// Subject claim.
    pub sub: String,
    /// Issuer claim.
    pub iss: String,
    /// Audience claim.
    pub aud: Vec<String>,
    /// Expiration claim.
    pub exp: u64,
    /// Optional JWT key id.
    pub kid: Option<String>,
    /// Raw bearer token used for this request.
    pub token: String,
}

impl<S> FromRequestParts<S> for TestAuthContext
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or((StatusCode::UNAUTHORIZED, "missing auth context"))
    }
}

/// Deterministic helper to inject a known auth context into a request.
pub fn inject_auth_context<B>(mut req: Request<B>, ctx: TestAuthContext) -> Request<B> {
    req.extensions_mut().insert(ctx);
    req
}

/// Deterministic JWKS rotation phases for tests.
#[derive(Clone)]
pub struct DeterministicJwksRotation {
    phases: Arc<Vec<Jwks>>,
    phase_idx: Arc<AtomicUsize>,
}

impl DeterministicJwksRotation {
    /// Build a rotation schedule from explicit phase key sets.
    pub fn new(phases: Vec<Vec<RsaKeyPair>>) -> Self {
        let built = phases
            .into_iter()
            .map(|keys| {
                let mut builder = JwksBuilder::new();
                for key in keys {
                    builder.push_public(key.public_jwk());
                }
                builder.build()
            })
            .collect::<Vec<_>>();
        Self {
            phases: Arc::new(built),
            phase_idx: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Set active phase (out-of-range values clamp to the last phase).
    pub fn set_phase(&self, idx: usize) {
        let max = self.phases.len().saturating_sub(1);
        self.phase_idx.store(idx.min(max), Ordering::SeqCst);
    }

    /// Return current phase index.
    pub fn current_phase(&self) -> usize {
        self.phase_idx.load(Ordering::SeqCst)
    }

    fn current_jwks(&self) -> Jwks {
        let idx = self.current_phase();
        self.phases.get(idx).cloned().unwrap_or(Jwks { keys: vec![] })
    }
}

/// Build a router serving `/.well-known/jwks.json` (or custom path) for fixed keys.
pub fn jwks_router(keys: Vec<RsaKeyPair>) -> Router {
    jwks_router_at(DEFAULT_JWKS_PATH, keys)
}

/// Build a router serving JWKS at a custom path for fixed keys.
pub fn jwks_router_at(path: &str, keys: Vec<RsaKeyPair>) -> Router {
    let mut builder = JwksBuilder::new();
    for key in keys {
        builder.push_public(key.public_jwk());
    }
    let jwks = builder.build();
    Router::new().route(path, get(move || jwks_handler(jwks.clone())))
}

/// Build a router serving JWKS from deterministic rotation state.
pub fn jwks_router_with_rotation(path: &str, rotation: DeterministicJwksRotation) -> Router {
    Router::new()
        .route(path, get(jwks_rotation_handler))
        .with_state(rotation)
}

async fn jwks_handler(jwks: Jwks) -> Json<Value> {
    Json(jwks.to_value())
}

async fn jwks_rotation_handler(State(rotation): State<DeterministicJwksRotation>) -> Json<Value> {
    Json(rotation.current_jwks().to_value())
}

/// OIDC discovery config used by [`oidc_router`].
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// Issuer URL.
    pub issuer: String,
    /// JWKS URL path or absolute URL.
    pub jwks_uri: String,
}

impl OidcConfig {
    /// New OIDC config.
    pub fn new(issuer: impl Into<String>, jwks_uri: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            jwks_uri: jwks_uri.into(),
        }
    }
}

/// Build a router serving OpenID discovery JSON at the default path.
pub fn oidc_router(config: OidcConfig) -> Router {
    oidc_router_at(DEFAULT_OIDC_PATH, config)
}

/// Build a router serving OpenID discovery JSON at a custom path.
pub fn oidc_router_at(path: &str, config: OidcConfig) -> Router {
    Router::new().route(path, get(move || oidc_handler(config.clone())))
}

async fn oidc_handler(config: OidcConfig) -> Json<Value> {
    Json(json!({
        "issuer": config.issuer,
        "jwks_uri": config.jwks_uri,
        "id_token_signing_alg_values_supported": ["RS256", "RS384", "RS512"],
        "subject_types_supported": ["public"],
        "response_types_supported": ["code", "token", "id_token"],
    }))
}

/// Configuration for [`mock_jwt_verifier_layer`].
#[derive(Clone)]
pub struct MockJwtVerifier {
    expected: Option<ExpectedAuthValues>,
    decoding_keys: Arc<HashMap<String, DecodingKey>>,
}

impl std::fmt::Debug for MockJwtVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockJwtVerifier")
            .field("expected", &self.expected)
            .field("known_kid_count", &self.decoding_keys.len())
            .finish()
    }
}

impl Default for MockJwtVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl MockJwtVerifier {
    /// Empty verifier. Add keys and expected values via builder methods.
    pub fn new() -> Self {
        Self {
            expected: None,
            decoding_keys: Arc::new(HashMap::new()),
        }
    }

    /// Set expected issuer/audience/kid.
    pub fn with_expected(mut self, expected: ExpectedAuthValues) -> Self {
        self.expected = Some(expected);
        self
    }

    /// Add verification keys from RSA fixtures (indexed by fixture `kid()`).
    pub fn with_keys(mut self, keys: Vec<RsaKeyPair>) -> Self {
        let map = keys
            .into_iter()
            .map(|k| {
                (
                    k.kid(),
                    DecodingKey::from_rsa_pem(k.public_key_spki_pem().as_bytes())
                        .expect("valid RSA public key PEM from fixture"),
                )
            })
            .collect::<HashMap<_, _>>();
        self.decoding_keys = Arc::new(map);
        self
    }

    fn decoding_key_for_kid(&self, kid: Option<&str>) -> Option<&DecodingKey> {
        let kid = kid?;
        self.decoding_keys.get(kid)
    }
}

/// Apply bearer-token mock verification middleware to an axum [`Router`].
pub fn mock_jwt_verifier_layer(router: Router, config: MockJwtVerifier) -> Router {
    router.layer(
        ServiceBuilder::new()
            .layer(Extension(config))
            .layer(middleware::from_fn(jwt_verifier_middleware)),
    )
}


#[derive(Debug, Clone, Deserialize)]
struct WireClaims {
    sub: String,
    iss: String,
    #[serde(default)]
    aud: Aud,
    exp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum Aud {
    One(String),
    Many(Vec<String>),
    Missing,
}

impl Default for Aud {
    fn default() -> Self {
        Self::Missing
    }
}

impl Aud {
    fn contains(&self, target: &str) -> bool {
        match self {
            Self::One(aud) => aud == target,
            Self::Many(auds) => auds.iter().any(|aud| aud == target),
            Self::Missing => false,
        }
    }

    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(v) => vec![v],
            Self::Many(v) => v,
            Self::Missing => vec![],
        }
    }
}

async fn jwt_verifier_middleware(
    Extension(config): Extension<MockJwtVerifier>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let token = match bearer_from_request(&req) {
        Some(token) => token,
        None => return (StatusCode::UNAUTHORIZED, "missing bearer token").into_response(),
    };

    let header_data = match decode_header(token) {
        Ok(h) => h,
        Err(_) => return (StatusCode::UNAUTHORIZED, "invalid jwt header").into_response(),
    };

    let Some(key) = config.decoding_key_for_kid(header_data.kid.as_deref()) else {
        return (StatusCode::UNAUTHORIZED, "unknown kid").into_response();
    };

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims = HashSet::new();

    let decoded = match decode::<WireClaims>(token, key, &validation) {
        Ok(data) => data,
        Err(_) => return (StatusCode::UNAUTHORIZED, "signature verification failed").into_response(),
    };

    if !verify_claims(&decoded.claims, header_data.kid.as_deref(), &config.expected) {
        return (StatusCode::UNAUTHORIZED, "claims verification failed").into_response();
    }

    let ctx = TestAuthContext {
        sub: decoded.claims.sub,
        iss: decoded.claims.iss,
        aud: decoded.claims.aud.into_vec(),
        exp: decoded.claims.exp,
        kid: header_data.kid,
        token: token.to_string(),
    };
    req.extensions_mut().insert(ctx);

    next.run(req).await
}

fn verify_claims(claims: &WireClaims, kid: Option<&str>, expected: &Option<ExpectedAuthValues>) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if claims.exp <= now {
        return false;
    }

    let Some(expected) = expected else {
        return true;
    };

    if claims.iss != expected.issuer {
        return false;
    }

    if !claims.aud.contains(&expected.audience) {
        return false;
    }

    match &expected.kid {
        Some(expected_kid) => kid == Some(expected_kid.as_str()),
        None => true,
    }
}

fn bearer_from_request<B>(req: &Request<B>) -> Option<&str> {
    let header_value = req.headers().get(header::AUTHORIZATION)?;
    let raw = header_value.to_str().ok()?;
    raw.strip_prefix("Bearer ")
}

/// Helper to build expected auth values from fixture + audience.
pub fn expected_values_for_key(
    keypair: &RsaKeyPair,
    issuer: impl Into<String>,
    audience: impl Into<String>,
) -> ExpectedAuthValues {
    ExpectedAuthValues::new(issuer, audience).with_kid(keypair.kid())
}

/// Build a tiny claim set for test token creation.
pub fn basic_claims(
    sub: impl Into<String>,
    issuer: impl Into<String>,
    audience: impl Into<String>,
    exp: u64,
) -> Value {
    json!({
        "sub": sub.into(),
        "iss": issuer.into(),
        "aud": audience.into(),
        "exp": exp,
    })
}

/// Build a JWKS from one or more keypairs.
pub fn jwks_from_keys(keys: impl IntoIterator<Item = RsaKeyPair>) -> Jwks {
    let mut builder = JwksBuilder::new();
    for key in keys {
        builder.push_public(key.public_jwk());
    }
    builder.build()
}
