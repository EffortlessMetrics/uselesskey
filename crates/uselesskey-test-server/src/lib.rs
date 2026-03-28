#![forbid(unsafe_code)]

//! Deterministic OIDC discovery/JWKS HTTP fixture server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;

use axum::body::Body;
use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
use uselesskey_jwk::{JwksBuilder, PublicJwk};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

/// How the discovery document issuer URL should be populated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IssuerUrlMode {
    /// Use this explicit issuer URL in discovery output.
    Fixed(String),
    /// Use the runtime-local bound server URL (`http://127.0.0.1:<random_port>`).
    RandomPortLocalhost,
}

/// Cache policy controls for `/jwks.json` and discovery metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CachePolicySpec {
    /// `max-age` value in seconds.
    pub max_age_seconds: u64,
    /// Whether to include `public` (otherwise `private`).
    pub public: bool,
    /// Whether to append `must-revalidate`.
    pub must_revalidate: bool,
}

impl CachePolicySpec {
    fn as_header_value(self) -> String {
        let visibility = if self.public { "public" } else { "private" };
        let mut out = format!("{visibility}, max-age={}", self.max_age_seconds);
        if self.must_revalidate {
            out.push_str(", must-revalidate");
        }
        out
    }
}

/// Rotation behavior for JWKS serving.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JwksRotation {
    /// Always serve one static phase.
    Static(JwksPhase),
    /// Serve one of several named phases selected by [`OidcTestServer::with_phase`].
    Sequence(Vec<JwksPhase>),
}

/// A named JWKS phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JwksPhase {
    /// Stable test-facing phase name.
    pub phase_name: String,
    /// JWKS fixture spec for this phase.
    pub jwks_spec: JwksSpec,
}

impl JwksPhase {
    /// Build a named phase.
    pub fn new(phase_name: impl Into<String>, jwks_spec: JwksSpec) -> Self {
        Self {
            phase_name: phase_name.into(),
            jwks_spec,
        }
    }
}

/// OIDC/JWKS server configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcServerSpec {
    pub issuer_url_mode: IssuerUrlMode,
    pub jwks_rotation: JwksRotation,
    pub cache_headers: Option<CachePolicySpec>,
    pub serve_discovery: bool,
    pub serve_jwks: bool,
}

impl Default for OidcServerSpec {
    fn default() -> Self {
        Self {
            issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
            jwks_rotation: JwksRotation::Static(JwksPhase::new("static", JwksSpec::default())),
            cache_headers: None,
            serve_discovery: true,
            serve_jwks: true,
        }
    }
}

/// Key fixture choices used to build a JWKS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JwkFixtureSpec {
    Rsa { label: String, spec: RsaSpec },
    Ecdsa { label: String, spec: EcdsaSpec },
    Ed25519 { label: String, spec: Ed25519Spec },
}

/// JWKS fixture specification.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JwksSpec {
    pub keys: Vec<JwkFixtureSpec>,
}

impl JwksSpec {
    pub fn new(keys: Vec<JwkFixtureSpec>) -> Self {
        Self { keys }
    }
}

/// Startup and runtime errors for the OIDC test server.
#[derive(Debug, thiserror::Error)]
pub enum TestServerError {
    #[error("no JWKS phases configured")]
    EmptyPhases,
    #[error("phase not found: {0}")]
    UnknownPhase(String),
    #[error("invalid header value: {0}")]
    Header(#[from] http::header::InvalidHeaderValue),
    #[error("bind failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("server task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

#[derive(Clone, Debug)]
struct PhaseMaterial {
    phase_name: String,
    jwks_json: serde_json::Value,
    etag: String,
}

#[derive(Debug)]
struct ServerState {
    issuer: String,
    base_url: String,
    discovery_enabled: bool,
    jwks_enabled: bool,
    cache_control_header: Option<HeaderValue>,
    phases: Vec<PhaseMaterial>,
    phase_index: Arc<RwLock<usize>>,
}

/// Running OIDC/JWKS fixture server handle.
#[derive(Debug)]
pub struct OidcTestServer {
    state: Arc<ServerState>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
}

/// Alias for call sites that want a generic server handle name.
pub type TestServerHandle = OidcTestServer;

impl OidcTestServer {
    /// Start a server from `Factory` and [`OidcServerSpec`].
    pub async fn start(factory: Factory, spec: OidcServerSpec) -> Result<Self, TestServerError> {
        let phases = materialize_phases(&factory, &spec.jwks_rotation)?;
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        std_listener.set_nonblocking(true)?;
        let addr: SocketAddr = std_listener.local_addr()?;
        let base_url = format!("http://{addr}");

        let issuer = match &spec.issuer_url_mode {
            IssuerUrlMode::Fixed(url) => url.clone(),
            IssuerUrlMode::RandomPortLocalhost => base_url.clone(),
        };

        let cache_control_header = spec
            .cache_headers
            .map(CachePolicySpec::as_header_value)
            .map(|v| HeaderValue::from_str(&v))
            .transpose()?;

        let state = Arc::new(ServerState {
            issuer,
            base_url,
            discovery_enabled: spec.serve_discovery,
            jwks_enabled: spec.serve_jwks,
            cache_control_header,
            phases,
            phase_index: Arc::new(RwLock::new(0)),
        });

        let app = Router::new()
            .route("/.well-known/openid-configuration", get(serve_discovery))
            .route("/jwks.json", get(serve_jwks))
            .with_state(state.clone());

        let listener = TcpListener::from_std(std_listener)?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let join = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        Ok(Self {
            state,
            shutdown_tx: Some(shutdown_tx),
            join: Some(join),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.state.base_url
    }

    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.base_url())
    }

    pub fn jwks_url(&self) -> String {
        format!("{}/jwks.json", self.base_url())
    }

    /// Switch the active JWKS phase by name.
    pub fn with_phase(&self, phase_name: &str) -> Result<&Self, TestServerError> {
        let idx = self
            .state
            .phases
            .iter()
            .position(|p| p.phase_name == phase_name)
            .ok_or_else(|| TestServerError::UnknownPhase(phase_name.to_string()))?;

        let mut guard = self.state.phase_index.write().expect("phase lock poisoned");
        *guard = idx;
        Ok(self)
    }

    /// Return current phase name.
    pub fn phase_name(&self) -> String {
        let idx = *self.state.phase_index.read().expect("phase lock poisoned");
        self.state.phases[idx].phase_name.clone()
    }

    /// Shut down the background server task.
    pub async fn shutdown(mut self) -> Result<(), TestServerError> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        if let Some(join) = self.join.take() {
            join.await??;
        }

        Ok(())
    }
}

fn materialize_phases(
    factory: &Factory,
    rotation: &JwksRotation,
) -> Result<Vec<PhaseMaterial>, TestServerError> {
    let mut out = Vec::new();
    let phases = match rotation {
        JwksRotation::Static(phase) => std::slice::from_ref(phase),
        JwksRotation::Sequence(phases) => phases.as_slice(),
    };

    if phases.is_empty() {
        return Err(TestServerError::EmptyPhases);
    }

    for phase in phases {
        let mut builder = JwksBuilder::new();

        for key in &phase.jwks_spec.keys {
            let jwk: PublicJwk = match key {
                JwkFixtureSpec::Rsa { label, spec } => factory.rsa(label, *spec).public_jwk(),
                JwkFixtureSpec::Ecdsa { label, spec } => {
                    factory.ecdsa(label, *spec).public_jwk()
                }
                JwkFixtureSpec::Ed25519 { label, spec } => {
                    factory.ed25519(label, *spec).public_jwk()
                }
            };
            builder.push_public(jwk);
        }

        let jwks = builder.build();
        let jwks_json = jwks.to_value();
        let raw = serde_json::to_vec(&jwks_json).expect("serializable jwks");
        let etag = format!("\"{}\"", blake3::hash(&raw).to_hex());

        out.push(PhaseMaterial {
            phase_name: phase.phase_name.clone(),
            jwks_json,
            etag,
        });
    }

    Ok(out)
}

async fn serve_discovery(State(state): State<Arc<ServerState>>) -> Response {
    if !state.discovery_enabled {
        return (StatusCode::NOT_FOUND, "discovery disabled").into_response();
    }

    let body = json!({
        "issuer": state.issuer,
        "jwks_uri": format!("{}/jwks.json", state.base_url),
    });

    let mut res = Json(body).into_response();
    maybe_add_cache(&state, &mut res);
    res
}

async fn serve_jwks(State(state): State<Arc<ServerState>>) -> Response {
    if !state.jwks_enabled {
        return (StatusCode::NOT_FOUND, "jwks disabled").into_response();
    }

    let idx = *state.phase_index.read().expect("phase lock poisoned");
    let phase = &state.phases[idx];

    let mut res = Response::new(Body::from(phase.jwks_json.to_string()));
    *res.status_mut() = StatusCode::OK;
    res.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    if let Ok(v) = HeaderValue::from_str(&phase.etag) {
        res.headers_mut().insert(ETAG, v);
    }

    maybe_add_cache(&state, &mut res);
    res
}

fn maybe_add_cache(state: &ServerState, response: &mut Response) {
    if let Some(value) = state.cache_control_header.clone() {
        response.headers_mut().insert(CACHE_CONTROL, value);
    }
}
