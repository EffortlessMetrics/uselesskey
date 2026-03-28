#![forbid(unsafe_code)]

//! Deterministic OIDC/JWKS HTTP fixture server for tests.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, oneshot};
use uselesskey_core::Factory;
use uselesskey_jwk::{Jwks, JwksBuilder};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerUrlMode {
    Fixed(String),
    RandomPortLocalhost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwksRotation {
    Static(JwksPhase),
    Sequence(Vec<JwksPhase>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachePolicySpec {
    pub etag: bool,
    pub max_age_seconds: u64,
}

impl CachePolicySpec {
    pub fn no_store() -> Self {
        Self {
            etag: false,
            max_age_seconds: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcServerSpec {
    pub issuer_url_mode: IssuerUrlMode,
    pub jwks_rotation: JwksRotation,
    pub cache_headers: Option<CachePolicySpec>,
    pub serve_discovery: bool,
    pub serve_jwks: bool,
}

impl OidcServerSpec {
    pub fn localhost_with_rotation(phases: Vec<JwksPhase>) -> Self {
        Self {
            issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
            jwks_rotation: JwksRotation::Sequence(phases),
            cache_headers: None,
            serve_discovery: true,
            serve_jwks: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwksPhase {
    pub phase_name: String,
    pub jwks_spec: JwksSpec,
    pub phase_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwksSpec {
    pub keys: Vec<RsaJwkFixtureSpec>,
}

impl JwksSpec {
    pub fn single_rsa(label: impl AsRef<str>, spec: RsaSpec) -> Self {
        Self {
            keys: vec![RsaJwkFixtureSpec {
                label: label.as_ref().to_string(),
                spec,
            }],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaJwkFixtureSpec {
    pub label: String,
    pub spec: RsaSpec,
}

#[derive(Debug)]
pub enum TestServerError {
    Io(std::io::Error),
    Addr(std::net::AddrParseError),
    MissingPhase(String),
    NoPhases,
}

impl fmt::Display for TestServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::Addr(err) => write!(f, "invalid fixed issuer address: {err}"),
            Self::MissingPhase(name) => write!(f, "unknown JWKS phase: {name}"),
            Self::NoPhases => write!(f, "jwks rotation must contain at least one phase"),
        }
    }
}

impl std::error::Error for TestServerError {}

impl From<std::io::Error> for TestServerError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<std::net::AddrParseError> for TestServerError {
    fn from(value: std::net::AddrParseError) -> Self {
        Self::Addr(value)
    }
}

#[derive(Clone)]
pub struct TestServerHandle {
    state: Arc<SharedState>,
}

impl fmt::Debug for TestServerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestServerHandle")
            .field("base_url", &self.state.base_url)
            .finish_non_exhaustive()
    }
}

impl TestServerHandle {
    pub fn base_url(&self) -> &str {
        &self.state.base_url
    }

    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.state.base_url)
    }

    pub fn jwks_url(&self) -> String {
        format!("{}/jwks.json", self.state.base_url)
    }

    pub async fn with_phase(&self, phase_name: impl AsRef<str>) -> Result<Self, TestServerError> {
        self.state.set_phase(phase_name.as_ref()).await?;
        Ok(self.clone())
    }

    pub async fn shutdown(self) {
        let mut guard = self.state.shutdown_tx.lock().await;
        if let Some(tx) = guard.take() {
            let _ = tx.send(());
        }
        drop(guard);

        let mut task_guard = self.state.server_task.lock().await;
        if let Some(handle) = task_guard.take() {
            let _ = handle.await;
        }
    }
}

pub struct OidcTestServer;

impl OidcTestServer {
    pub async fn start(factory: Factory, spec: OidcServerSpec) -> Result<TestServerHandle, TestServerError> {
        let phases = normalize_phases(spec.jwks_rotation.clone())?;
        let state_seed = ServerStateSeed {
            factory,
            phases,
            current_phase_idx: 0,
            cache_policy: spec.cache_headers.clone(),
            serve_discovery: spec.serve_discovery,
            serve_jwks: spec.serve_jwks,
        };

        let (listener, base_url) = bind_listener(&spec.issuer_url_mode).await?;

        let shared_state = Arc::new(SharedState {
            base_url,
            server_state: Mutex::new(state_seed),
            shutdown_tx: Mutex::new(None),
            server_task: Mutex::new(None),
        });

        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery_handler))
            .route("/jwks.json", get(jwks_handler))
            .with_state(shared_state.clone());

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        {
            let mut guard = shared_state.shutdown_tx.lock().await;
            *guard = Some(shutdown_tx);
        }

        let task = tokio::spawn(async move {
            let server = axum::serve(listener, app);
            let _ = server
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        {
            let mut guard = shared_state.server_task.lock().await;
            *guard = Some(task);
        }

        Ok(TestServerHandle {
            state: shared_state,
        })
    }
}

async fn bind_listener(mode: &IssuerUrlMode) -> Result<(TcpListener, String), TestServerError> {
    match mode {
        IssuerUrlMode::RandomPortLocalhost => {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            Ok((listener, format!("http://{addr}")))
        }
        IssuerUrlMode::Fixed(base_url) => {
            let host = base_url
                .strip_prefix("http://")
                .unwrap_or(base_url)
                .trim_end_matches('/');
            let addr: SocketAddr = host.parse()?;
            let listener = TcpListener::bind(addr).await?;
            let real_addr = listener.local_addr()?;
            Ok((listener, format!("http://{real_addr}")))
        }
    }
}

fn normalize_phases(rotation: JwksRotation) -> Result<Vec<JwksPhase>, TestServerError> {
    let phases = match rotation {
        JwksRotation::Static(phase) => vec![phase],
        JwksRotation::Sequence(phases) => phases,
    };
    if phases.is_empty() {
        return Err(TestServerError::NoPhases);
    }
    Ok(phases)
}

struct SharedState {
    base_url: String,
    server_state: Mutex<ServerStateSeed>,
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
    server_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl SharedState {
    async fn set_phase(&self, phase_name: &str) -> Result<(), TestServerError> {
        let mut state = self.server_state.lock().await;
        let idx = state
            .phases
            .iter()
            .position(|phase| phase.phase_name == phase_name)
            .ok_or_else(|| TestServerError::MissingPhase(phase_name.to_string()))?;
        state.current_phase_idx = idx;
        Ok(())
    }
}

struct ServerStateSeed {
    factory: Factory,
    phases: Vec<JwksPhase>,
    current_phase_idx: usize,
    cache_policy: Option<CachePolicySpec>,
    serve_discovery: bool,
    serve_jwks: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct OidcDiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

async fn discovery_handler(
    State(shared): State<Arc<SharedState>>,
) -> Result<(HeaderMap, Json<OidcDiscoveryDocument>), StatusCode> {
    let state = shared.server_state.lock().await;
    if !state.serve_discovery {
        return Err(StatusCode::NOT_FOUND);
    }

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let doc = OidcDiscoveryDocument {
        issuer: shared.base_url.clone(),
        jwks_uri: format!("{}/jwks.json", shared.base_url),
    };

    Ok((headers, Json(doc)))
}

async fn jwks_handler(
    State(shared): State<Arc<SharedState>>,
) -> Result<(HeaderMap, Json<Value>), StatusCode> {
    let state = shared.server_state.lock().await;
    if !state.serve_jwks {
        return Err(StatusCode::NOT_FOUND);
    }

    let phase = &state.phases[state.current_phase_idx];
    let jwks = build_jwks_for_phase(&state.factory, phase);
    let jwks_value = jwks.to_value();

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    if let Some(cache) = &state.cache_policy {
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_str(&format!("public, max-age={}", cache.max_age_seconds))
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        );
        if cache.etag {
            let etag = etag_for_value(&jwks_value);
            headers.insert(
                ETAG,
                HeaderValue::from_str(&etag).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
            );
        }
    }

    Ok((headers, Json(jwks_value)))
}

fn etag_for_value(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("serializing JWKS value for etag should not fail");
    let digest = blake3::hash(&bytes);
    format!("\"{}\"", digest.to_hex())
}

fn build_jwks_for_phase(factory: &Factory, phase: &JwksPhase) -> Jwks {
    let mut ordered = BTreeMap::<String, uselesskey_jwk::PublicJwk>::new();

    for key in &phase.jwks_spec.keys {
        let phase_label = format!("{}::phase:{}::idx:{}", key.label, phase.phase_name, phase.phase_index);
        let kp = factory.rsa(phase_label, key.spec);
        let jwk = kp.public_jwk();
        ordered.insert(jwk.kid().to_string(), jwk);
    }

    let mut builder = JwksBuilder::new();
    for (_, jwk) in ordered {
        builder.push_public(jwk);
    }

    builder.build()
}

#[allow(clippy::missing_const_for_fn)]
pub fn simple_rsa_rotation(phase_names: &[&str]) -> Vec<JwksPhase> {
    phase_names
        .iter()
        .enumerate()
        .map(|(idx, name)| JwksPhase {
            phase_name: (*name).to_string(),
            jwks_spec: JwksSpec::single_rsa(format!("oidc-{name}"), RsaSpec::rs256()),
            phase_index: idx,
        })
        .collect()
}

pub fn cache_policy(max_age_seconds: u64, etag: bool) -> CachePolicySpec {
    CachePolicySpec {
        etag,
        max_age_seconds,
    }
}

pub fn oidc_discovery_json(base_url: &str) -> Value {
    json!({
        "issuer": base_url,
        "jwks_uri": format!("{base_url}/jwks.json"),
    })
}
