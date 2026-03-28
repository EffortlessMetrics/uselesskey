#![forbid(unsafe_code)]

use std::sync::Arc;

use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, ETAG};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock, oneshot};
use tokio::task::JoinHandle;
use uselesskey_core::Factory;
use uselesskey_jwk::{Jwks, JwksBuilder};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

#[derive(Debug, Clone)]
pub enum IssuerUrlMode {
    Fixed(String),
    RandomPortLocalhost,
}

#[derive(Debug, Clone)]
pub enum JwksRotation {
    Static,
    Sequence(Vec<JwksPhase>),
}

#[derive(Debug, Clone)]
pub struct OidcServerSpec {
    pub issuer_url_mode: IssuerUrlMode,
    pub jwks_rotation: JwksRotation,
    pub cache_headers: Option<CachePolicySpec>,
    pub serve_discovery: bool,
    pub serve_jwks: bool,
}

impl OidcServerSpec {
    pub fn static_rsa() -> Self {
        Self {
            issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
            jwks_rotation: JwksRotation::Static,
            cache_headers: None,
            serve_discovery: true,
            serve_jwks: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct JwksPhase {
    pub phase_name: String,
    pub jwks_spec: JwksSpec,
    pub phase_index: Option<usize>,
}

impl JwksPhase {
    pub fn new(phase_name: impl Into<String>, jwks_spec: JwksSpec) -> Self {
        Self {
            phase_name: phase_name.into(),
            jwks_spec,
            phase_index: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct JwksSpec {
    pub key_labels: Vec<String>,
    pub rsa_spec: RsaSpec,
}

impl JwksSpec {
    pub fn single_rs256(label: impl Into<String>) -> Self {
        Self {
            key_labels: vec![label.into()],
            rsa_spec: RsaSpec::rs256(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CachePolicySpec {
    pub max_age_seconds: u64,
    pub include_etag: bool,
}

impl CachePolicySpec {
    fn cache_control_value(&self) -> String {
        format!("public, max-age={}", self.max_age_seconds)
    }
}

#[derive(Debug, Error)]
pub enum TestServerError {
    #[error("no JWKS phases configured")]
    NoPhases,
    #[error("phase '{0}' not found")]
    PhaseNotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone)]
pub struct TestServerHandle {
    state: Arc<ServerState>,
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    join_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl std::fmt::Debug for TestServerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestServerHandle")
            .field("base_url", &self.state.base_url)
            .finish_non_exhaustive()
    }
}

pub struct OidcTestServer;

impl OidcTestServer {
    pub async fn start(
        factory: Factory,
        spec: OidcServerSpec,
    ) -> Result<TestServerHandle, TestServerError> {
        let phases = phases_from_rotation(&spec.jwks_rotation);
        if phases.is_empty() {
            return Err(TestServerError::NoPhases);
        }

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;
        let base_url = match &spec.issuer_url_mode {
            IssuerUrlMode::Fixed(url) => url.clone(),
            IssuerUrlMode::RandomPortLocalhost => format!("http://{}", local_addr),
        };

        let precomputed = phases
            .iter()
            .enumerate()
            .map(|(idx, phase)| {
                let name = phase.phase_name.clone();
                let jwks = build_jwks_for_phase(&factory, &name, &phase.jwks_spec);
                let jwks_json = serde_json::to_string(&jwks).expect("serialize jwks");
                let etag = format!("\"{}\"", blake3::hash(jwks_json.as_bytes()).to_hex());
                let _numeric_index = phase.phase_index.unwrap_or(idx);
                CachedPhase {
                    phase_name: name,
                    jwks,
                    etag,
                }
            })
            .collect::<Vec<_>>();

        let state = Arc::new(ServerState {
            base_url,
            discovery_path: "/.well-known/openid-configuration".to_owned(),
            jwks_path: "/jwks.json".to_owned(),
            current_phase: RwLock::new(0),
            phases: precomputed,
            cache_policy: spec.cache_headers,
            serve_discovery: spec.serve_discovery,
            serve_jwks: spec.serve_jwks,
        });

        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery_handler))
            .route("/jwks.json", get(jwks_handler))
            .with_state(state.clone());

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        });
        let join_handle = tokio::spawn(async move {
            let _ = server.await;
        });

        Ok(TestServerHandle {
            state,
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
            join_handle: Arc::new(Mutex::new(Some(join_handle))),
        })
    }
}

impl TestServerHandle {
    pub fn base_url(&self) -> String {
        self.state.base_url.clone()
    }

    pub fn discovery_url(&self) -> String {
        format!("{}{}", self.state.base_url, self.state.discovery_path)
    }

    pub fn jwks_url(&self) -> String {
        format!("{}{}", self.state.base_url, self.state.jwks_path)
    }

    pub async fn with_phase(&self, phase_name: impl AsRef<str>) -> Result<Self, TestServerError> {
        let phase_name = phase_name.as_ref();
        let idx = self
            .state
            .phases
            .iter()
            .position(|phase| phase.phase_name == phase_name)
            .ok_or_else(|| TestServerError::PhaseNotFound(phase_name.to_owned()))?;
        *self.state.current_phase.write().await = idx;
        Ok(self.clone())
    }

    pub async fn current_phase_name(&self) -> String {
        let idx = *self.state.current_phase.read().await;
        self.state.phases[idx].phase_name.clone()
    }

    pub async fn shutdown(&self) {
        if let Some(tx) = self.shutdown_tx.lock().await.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join_handle.lock().await.take() {
            let _ = join.await;
        }
    }
}

#[derive(Clone)]
struct CachedPhase {
    phase_name: String,
    jwks: Jwks,
    etag: String,
}

struct ServerState {
    base_url: String,
    discovery_path: String,
    jwks_path: String,
    phases: Vec<CachedPhase>,
    current_phase: RwLock<usize>,
    cache_policy: Option<CachePolicySpec>,
    serve_discovery: bool,
    serve_jwks: bool,
}

#[derive(Serialize)]
struct DiscoveryDoc {
    issuer: String,
    jwks_uri: String,
}

async fn discovery_handler(State(state): State<Arc<ServerState>>) -> Response {
    if !state.serve_discovery {
        return StatusCode::NOT_FOUND.into_response();
    }

    let payload = DiscoveryDoc {
        issuer: state.base_url.clone(),
        jwks_uri: format!("{}{}", state.base_url, state.jwks_path),
    };

    with_cache_headers(Json(payload).into_response(), &state.cache_policy, None)
}

async fn jwks_handler(State(state): State<Arc<ServerState>>) -> Response {
    if !state.serve_jwks {
        return StatusCode::NOT_FOUND.into_response();
    }

    let idx = *state.current_phase.read().await;
    let phase = &state.phases[idx];
    let payload = Json(phase.jwks.to_value()).into_response();
    with_cache_headers(payload, &state.cache_policy, Some(phase.etag.as_str()))
}

fn with_cache_headers(
    mut response: Response,
    cache_policy: &Option<CachePolicySpec>,
    etag: Option<&str>,
) -> Response {
    if let Some(policy) = cache_policy {
        if let Ok(cache_value) = HeaderValue::from_str(&policy.cache_control_value()) {
            response.headers_mut().insert(CACHE_CONTROL, cache_value);
        }
        if policy.include_etag
            && let Some(etag) = etag
            && let Ok(etag_value) = HeaderValue::from_str(etag)
        {
            response.headers_mut().insert(ETAG, etag_value);
        }
    }
    response
}

fn phases_from_rotation(rotation: &JwksRotation) -> Vec<JwksPhase> {
    match rotation {
        JwksRotation::Static => vec![JwksPhase::new("static", JwksSpec::single_rs256("default"))],
        JwksRotation::Sequence(phases) => phases.clone(),
    }
}

fn build_jwks_for_phase(factory: &Factory, phase_name: &str, spec: &JwksSpec) -> Jwks {
    let mut builder = JwksBuilder::new();
    for label in &spec.key_labels {
        let key_label = format!("oidc:{phase_name}:{label}");
        let key = factory.rsa(key_label, spec.rsa_spec);
        builder.push_public(key.public_jwk());
    }
    builder.build()
}

pub fn extract_etag(headers: &HeaderMap) -> Option<String> {
    headers
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
}

