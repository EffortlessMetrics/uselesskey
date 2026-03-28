use uselesskey_core::{Factory, Seed};
use uselesskey_rsa::RsaSpec;
use uselesskey_test_server::{
    CachePolicySpec, IssuerUrlMode, JwksPhase, JwksRotation, JwksSpec, OidcServerSpec, OidcTestServer,
    extract_etag,
};

fn local_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("build reqwest client")
}

fn deterministic_factory() -> Factory {
    let seed = Seed::from_env_value("oidc-server-tests").expect("valid seed");
    Factory::deterministic(seed)
}

fn rotation_spec() -> OidcServerSpec {
    OidcServerSpec {
        issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
        jwks_rotation: JwksRotation::Sequence(vec![
            JwksPhase::new(
                "initial",
                JwksSpec {
                    key_labels: vec!["issuer-main".to_string()],
                    rsa_spec: RsaSpec::rs256(),
                },
            ),
            JwksPhase::new(
                "rotated",
                JwksSpec {
                    key_labels: vec!["issuer-main".to_string(), "issuer-next".to_string()],
                    rsa_spec: RsaSpec::rs256(),
                },
            ),
        ]),
        cache_headers: Some(CachePolicySpec {
            max_age_seconds: 60,
            include_etag: true,
        }),
        serve_discovery: true,
        serve_jwks: true,
    }
}

#[tokio::test]
async fn deterministic_jwks_for_same_seed_and_phase() {
    let client = local_client();

    let s1 = OidcTestServer::start(deterministic_factory(), rotation_spec())
        .await
        .expect("start server 1");
    let s2 = OidcTestServer::start(deterministic_factory(), rotation_spec())
        .await
        .expect("start server 2");

    let jwks_1 = client
        .get(s1.jwks_url())
        .send()
        .await
        .expect("get jwks from server 1")
        .json::<serde_json::Value>()
        .await
        .expect("json jwks 1");
    let jwks_2 = client
        .get(s2.jwks_url())
        .send()
        .await
        .expect("get jwks from server 2")
        .json::<serde_json::Value>()
        .await
        .expect("json jwks 2");

    assert_eq!(jwks_1, jwks_2, "same seed + phase should match JWKS");

    s1.shutdown().await;
    s2.shutdown().await;
}

#[tokio::test]
async fn different_phase_changes_jwks_and_kids() {
    let client = local_client();
    let server = OidcTestServer::start(deterministic_factory(), rotation_spec())
        .await
        .expect("start server");

    let phase1 = client
        .get(server.jwks_url())
        .send()
        .await
        .expect("get phase1")
        .json::<serde_json::Value>()
        .await
        .expect("phase1 json");

    server
        .with_phase("rotated")
        .await
        .expect("switch to rotated phase");

    let phase2 = client
        .get(server.jwks_url())
        .send()
        .await
        .expect("get phase2")
        .json::<serde_json::Value>()
        .await
        .expect("phase2 json");

    assert_ne!(phase1, phase2, "phase rotation should change JWKS payload");

    let kids1 = phase1["keys"]
        .as_array()
        .expect("keys array phase1")
        .iter()
        .map(|k| k["kid"].as_str().expect("kid phase1").to_string())
        .collect::<Vec<_>>();
    let kids2 = phase2["keys"]
        .as_array()
        .expect("keys array phase2")
        .iter()
        .map(|k| k["kid"].as_str().expect("kid phase2").to_string())
        .collect::<Vec<_>>();

    assert_ne!(kids1, kids2, "rotation should expose different kids");
    server.shutdown().await;
}

#[tokio::test]
async fn discovery_points_to_server_jwks_url() {
    let client = local_client();
    let server = OidcTestServer::start(deterministic_factory(), rotation_spec())
        .await
        .expect("start server");

    let discovery = client
        .get(server.discovery_url())
        .send()
        .await
        .expect("get discovery")
        .json::<serde_json::Value>()
        .await
        .expect("discovery json");

    assert_eq!(discovery["issuer"], server.base_url());
    assert_eq!(discovery["jwks_uri"], server.jwks_url());

    server.shutdown().await;
}

#[tokio::test]
async fn cache_headers_and_etag_change_on_phase_switch() {
    let client = local_client();
    let server = OidcTestServer::start(deterministic_factory(), rotation_spec())
        .await
        .expect("start server");

    let first = client
        .get(server.jwks_url())
        .send()
        .await
        .expect("get first jwks");
    let etag1 = extract_etag(first.headers()).expect("etag present");
    let cache_control = first
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .expect("cache-control header");
    assert!(cache_control.contains("max-age=60"));

    server
        .with_phase("rotated")
        .await
        .expect("switch phase to rotated");

    let second = client
        .get(server.jwks_url())
        .send()
        .await
        .expect("get second jwks");
    let etag2 = extract_etag(second.headers()).expect("etag present after phase change");

    assert_ne!(etag1, etag2, "etag should change when phase changes");

    server.shutdown().await;
}

#[tokio::test]
async fn shutdown_releases_listener() {
    let spec = rotation_spec();
    let server = OidcTestServer::start(deterministic_factory(), spec)
        .await
        .expect("start server");
    let jwks_url = server.jwks_url();

    let client = local_client();
    let before = client
        .get(&jwks_url)
        .send()
        .await
        .expect("server reachable before shutdown");
    assert!(before.status().is_success());

    server.shutdown().await;

    let after = client.get(&jwks_url).send().await;
    assert!(after.is_err(), "server should be unreachable after shutdown");
}

