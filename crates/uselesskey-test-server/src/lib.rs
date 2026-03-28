#![forbid(unsafe_code)]

//! Deterministic OIDC discovery and JWKS fixture server.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use uselesskey_core::Factory;
use uselesskey_jwk::JwksBuilder;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

/// Errors returned by `uselesskey-test-server`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The server could not bind or start.
    #[error("failed to bind or start server: {0}")]
    Start(#[from] std::io::Error),

    /// No JWKS phases were configured.
    #[error("at least one jwks phase is required")]
    EmptyPhaseSequence,

    /// A named phase was requested but not found.
    #[error("unknown jwks phase: {0}")]
    UnknownPhase(String),
}

/// URL base handling for the server's advertised issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerUrlMode {
    /// Use a fixed issuer URL in discovery documents.
    Fixed(String),
    /// Use the live localhost bind address, e.g. `http://127.0.0.1:NNNN`.
    RandomPortLocalhost,
}

/// Cache policy controls for HTTP responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePolicySpec {
    /// `max-age` in seconds included in `Cache-Control`.
    pub max_age_seconds: u64,
    /// Whether to emit an `ETag` header and support `If-None-Match` revalidation.
    pub emit_etag: bool,
}

impl CachePolicySpec {
    /// Disable cache storage.
    pub const fn no_store() -> Self {
        Self {
            max_age_seconds: 0,
            emit_etag: false,
        }
    }

    fn cache_control_value(&self) -> String {
        if self.max_age_seconds == 0 {
            "no-store".to_string()
        } else {
            format!("public, max-age={}", self.max_age_seconds)
        }
    }
}

/// RSA key descriptor used to construct a JWKS phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaJwkKeySpec {
    /// Fixture label for deterministic key derivation.
    pub label: String,
    /// RSA algorithm/size spec.
    pub spec: RsaSpec,
}

impl RsaJwkKeySpec {
    /// Convenience constructor.
    pub fn new(label: impl Into<String>, spec: RsaSpec) -> Self {
        Self {
            label: label.into(),
            spec,
        }
    }
}

/// JWKS generation spec for a phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwksSpec {
    /// Public keys included in this phase's JWKS document.
    pub rsa_keys: Vec<RsaJwkKeySpec>,
}

impl JwksSpec {
    /// Construct a single-key JWKS spec.
    pub fn single_rsa(label: impl Into<String>, spec: RsaSpec) -> Self {
        Self {
            rsa_keys: vec![RsaJwkKeySpec::new(label, spec)],
        }
    }
}

/// A deterministic JWKS rotation phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwksPhase {
    /// Logical phase name (e.g. `primary`, `rotated`).
    pub phase_name: String,
    /// Spec used to generate the JWKS for this phase.
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

/// JWKS rotation behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwksRotation {
    /// Serve one static JWKS phase.
    Static(JwksSpec),
    /// Deterministic, explicit phase sequence.
    Sequence(Vec<JwksPhase>),
}

/// Server configuration for OIDC/JWKS fixture serving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcServerSpec {
    /// Issuer URL advertisement mode.
    pub issuer_url_mode: IssuerUrlMode,
    /// JWKS rotation model.
    pub jwks_rotation: JwksRotation,
    /// Cache policy to apply to discovery and JWKS responses.
    pub cache_headers: Option<CachePolicySpec>,
    /// Whether to serve `/.well-known/openid-configuration`.
    pub serve_discovery: bool,
    /// Whether to serve `/jwks.json`.
    pub serve_jwks: bool,
}

impl OidcServerSpec {
    /// A default local test spec with discovery + JWKS enabled.
    pub fn localhost_static(jwks_spec: JwksSpec) -> Self {
        Self {
            issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
            jwks_rotation: JwksRotation::Static(jwks_spec),
            cache_headers: None,
            serve_discovery: true,
            serve_jwks: true,
        }
    }
}

#[derive(Clone)]
struct AppState {
    spec: OidcServerSpec,
    base_url: String,
    issuer_url: String,
    phases: Arc<Vec<PhaseMaterial>>,
    phase_index: Arc<AtomicUsize>,
}

#[derive(Debug, Clone)]
struct PhaseMaterial {
    name: String,
    jwks_json: serde_json::Value,
    etag: String,
}

/// Running test server handle.
pub struct TestServerHandle {
    state: AppState,
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl TestServerHandle {
    /// Return the base URL for this server, e.g. `http://127.0.0.1:41231`.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Return the OpenID discovery URL.
    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.base_url)
    }

    /// Return the JWKS URL.
    pub fn jwks_url(&self) -> String {
        format!("{}/jwks.json", self.base_url)
    }

    /// Switch active JWKS phase by name.
    pub fn with_phase(&self, phase_name: &str) -> Result<(), Error> {
        let idx = self
            .state
            .phases
            .iter()
            .position(|phase| phase.name == phase_name)
            .ok_or_else(|| Error::UnknownPhase(phase_name.to_string()))?;
        self.state.phase_index.store(idx, Ordering::SeqCst);
        Ok(())
    }

    /// Return the currently active phase name.
    pub fn active_phase_name(&self) -> &str {
        let idx = self.state.phase_index.load(Ordering::SeqCst);
        &self.state.phases[idx].name
    }

    /// Gracefully shut down the server.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

/// Entrypoint for starting OIDC/JWKS fixture servers.
pub struct OidcTestServer;

impl OidcTestServer {
    /// Start a new server from a `Factory` and `OidcServerSpec`.
    pub async fn start(factory: Factory, spec: OidcServerSpec) -> Result<TestServerHandle, Error> {
        let phases = materialize_phases(&factory, &spec)?;
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let base_url = format!("http://{}", addr);
        let issuer_url = match &spec.issuer_url_mode {
            IssuerUrlMode::Fixed(value) => value.clone(),
            IssuerUrlMode::RandomPortLocalhost => base_url.clone(),
        };

        let state = AppState {
            spec,
            base_url: base_url.clone(),
            issuer_url,
            phases: Arc::new(phases),
            phase_index: Arc::new(AtomicUsize::new(0)),
        };

        let router = Router::new()
            .route("/.well-known/openid-configuration", get(openid_configuration))
            .route("/jwks.json", get(jwks))
            .with_state(state.clone());

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let join = tokio::spawn(async move {
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        Ok(TestServerHandle {
            state,
            base_url,
            shutdown: Some(shutdown_tx),
            join: Some(join),
        })
    }
}

fn materialize_phases(factory: &Factory, spec: &OidcServerSpec) -> Result<Vec<PhaseMaterial>, Error> {
    let phases = match &spec.jwks_rotation {
        JwksRotation::Static(jwks_spec) => vec![JwksPhase::new("static", jwks_spec.clone())],
        JwksRotation::Sequence(phases) => {
            if phases.is_empty() {
                return Err(Error::EmptyPhaseSequence);
            }
            phases.clone()
        }
    };

    Ok(phases
        .into_iter()
        .map(|phase| {
            let mut builder = JwksBuilder::new();
            for key in phase.jwks_spec.rsa_keys {
                builder.push_public(factory.rsa(key.label, key.spec).public_jwk());
            }
            let jwks = builder.build();
            let jwks_json = jwks.to_value();
            let jwks_body = serde_json::to_vec(&jwks_json).expect("serialize jwks json");
            let etag = format!("\"{}\"", blake3::hash(&jwks_body).to_hex());

            PhaseMaterial {
                name: phase.phase_name,
                jwks_json,
                etag,
            }
        })
        .collect())
}

async fn openid_configuration(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !state.spec.serve_discovery {
        return StatusCode::NOT_FOUND.into_response();
    }

    let payload = json!({
        "issuer": state.issuer_url,
        "jwks_uri": format!("{}/jwks.json", state.base_url()),
    });
    cached_json_response(payload, &headers, state.spec.cache_headers, None)
}

async fn jwks(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !state.spec.serve_jwks {
        return StatusCode::NOT_FOUND.into_response();
    }

    let idx = state.phase_index.load(Ordering::SeqCst);
    let phase = &state.phases[idx];
    cached_json_response(
        phase.jwks_json.clone(),
        &headers,
        state.spec.cache_headers,
        Some(phase),
    )
}

fn cached_json_response(
    payload: serde_json::Value,
    request_headers: &HeaderMap,
    cache_spec: Option<CachePolicySpec>,
    phase: Option<&PhaseMaterial>,
) -> Response {
    let body = serde_json::to_vec(&payload).expect("serialize json payload");

    if let (Some(cache), Some(phase_material)) = (cache_spec, phase)
        && cache.emit_etag
        && request_headers
            .get(IF_NONE_MATCH)
            .is_some_and(|tag| tag.as_bytes() == phase_material.etag.as_bytes())
    {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        if let Ok(value) = HeaderValue::from_str(&phase_material.etag) {
            response.headers_mut().insert(ETAG, value);
        }
        if let Ok(value) = HeaderValue::from_str(&cache.cache_control_value()) {
            response.headers_mut().insert(CACHE_CONTROL, value);
        }
        return response;
    }

    let mut response = (StatusCode::OK, Json(payload)).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    if let Some(cache) = cache_spec {
        if let Ok(value) = HeaderValue::from_str(&cache.cache_control_value()) {
            response.headers_mut().insert(CACHE_CONTROL, value);
        }
        if cache.emit_etag {
            let etag = phase
                .map(|material| material.etag.clone())
                .unwrap_or_else(|| format!("\"{}\"", blake3::hash(&body).to_hex()));
            if let Ok(value) = HeaderValue::from_str(&etag) {
                response.headers_mut().insert(ETAG, value);
            }
        }
    }

    response
}

impl AppState {
    fn base_url(&self) -> String {
        self.base_url.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use uselesskey_core::{Factory, Seed};

    fn deterministic_factory() -> Factory {
        let seed = Seed::from_env_value("oidc-server-seed").expect("valid test seed");
        Factory::deterministic(seed)
    }

    fn sequence_spec() -> OidcServerSpec {
        OidcServerSpec {
            issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
            jwks_rotation: JwksRotation::Sequence(vec![
                JwksPhase::new("primary", JwksSpec::single_rsa("issuer-primary", RsaSpec::rs256())),
                JwksPhase::new("rotated", JwksSpec::single_rsa("issuer-rotated", RsaSpec::rs256())),
            ]),
            cache_headers: Some(CachePolicySpec {
                max_age_seconds: 30,
                emit_etag: true,
            }),
            serve_discovery: true,
            serve_jwks: true,
        }
    }

    fn http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("build http client")
    }

    #[tokio::test]
    async fn deterministic_jwks_for_same_seed_and_phase() {
        let spec = sequence_spec();
        let server_a = OidcTestServer::start(deterministic_factory(), spec.clone())
            .await
            .expect("start server a");
        let server_b = OidcTestServer::start(deterministic_factory(), spec)
            .await
            .expect("start server b");

        let client = http_client();
        let jwks_a: serde_json::Value = client
            .get(server_a.jwks_url())
            .send()
            .await
            .expect("send a")
            .json()
            .await
            .expect("json a");
        let jwks_b: serde_json::Value = client
            .get(server_b.jwks_url())
            .send()
            .await
            .expect("send b")
            .json()
            .await
            .expect("json b");

        assert_eq!(jwks_a, jwks_b, "same seed + phase should match");

        server_a.shutdown().await;
        server_b.shutdown().await;
    }

    #[tokio::test]
    async fn different_phase_changes_jwks() {
        let server = OidcTestServer::start(deterministic_factory(), sequence_spec())
            .await
            .expect("start server");

        let client = http_client();
        let jwks_primary: serde_json::Value = client
            .get(server.jwks_url())
            .send()
            .await
            .expect("send primary")
            .json()
            .await
            .expect("json primary");

        server.with_phase("rotated").expect("switch phase");
        let jwks_rotated: serde_json::Value = client
            .get(server.jwks_url())
            .send()
            .await
            .expect("send rotated")
            .json()
            .await
            .expect("json rotated");

        assert_ne!(jwks_primary, jwks_rotated);

        let kid_primary = jwks_primary["keys"][0]["kid"].as_str().expect("kid primary");
        let kid_rotated = jwks_rotated["keys"][0]["kid"].as_str().expect("kid rotated");
        assert_ne!(kid_primary, kid_rotated);

        server.shutdown().await;
    }

    #[tokio::test]
    async fn discovery_points_to_server_jwks_url() {
        let server = OidcTestServer::start(deterministic_factory(), sequence_spec())
            .await
            .expect("start server");

        let document: serde_json::Value = http_client()
            .get(server.discovery_url())
            .send()
            .await
            .expect("discovery response")
            .json()
            .await
            .expect("discovery json");

        assert_eq!(document["jwks_uri"], server.jwks_url());
        assert_eq!(document["issuer"], server.base_url());

        server.shutdown().await;
    }

    #[tokio::test]
    async fn cache_invalidation_across_phase_rotation_uses_etag() {
        let server = OidcTestServer::start(deterministic_factory(), sequence_spec())
            .await
            .expect("start server");

        let client = http_client();
        let first = client
            .get(server.jwks_url())
            .send()
            .await
            .expect("first response");
        assert_eq!(first.status(), StatusCode::OK);
        let first_etag = first
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("etag header")
            .to_string();

        let not_modified = client
            .get(server.jwks_url())
            .header(IF_NONE_MATCH, first_etag.clone())
            .send()
            .await
            .expect("revalidate same phase");
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);

        server.with_phase("rotated").expect("switch phase");

        let rotated = client
            .get(server.jwks_url())
            .header(IF_NONE_MATCH, first_etag.clone())
            .send()
            .await
            .expect("revalidate rotated phase");
        assert_eq!(rotated.status(), StatusCode::OK);
        let rotated_etag = rotated
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("rotated etag");

        assert_ne!(rotated_etag, first_etag);

        server.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_releases_port() {
        let server = OidcTestServer::start(deterministic_factory(), sequence_spec())
            .await
            .expect("start server");
        let addr: SocketAddr = server
            .base_url()
            .strip_prefix("http://")
            .expect("prefix")
            .parse()
            .expect("socket addr");

        server.shutdown().await;

        let rebound = TcpListener::bind(addr).await;
        assert!(rebound.is_ok(), "expected port to be reusable after shutdown");
    }
}
