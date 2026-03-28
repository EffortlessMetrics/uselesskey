use reqwest::Client;
use serde_json::Value;
use uselesskey_core::{Factory, Seed};
use uselesskey_test_server::{
    IssuerUrlMode, JwksRotation, OidcServerSpec, OidcTestServer, cache_policy, simple_rsa_rotation,
};

async fn fetch_json(client: &Client, url: String) -> Value {
    let resp = client.get(url).send().await.expect("request");
    let status = resp.status();
    let body = resp.text().await.expect("body text");
    assert!(status.is_success(), "unexpected status {status}: {body}");
    serde_json::from_str(&body).expect("json body")
}

fn deterministic_factory() -> Factory {
    Factory::deterministic(Seed::from_env_value("oidc-test-seed").expect("valid deterministic seed"))
}

fn test_client() -> Client {
    Client::builder()
        .no_proxy()
        .build()
        .expect("reqwest client")
}

fn spec() -> OidcServerSpec {
    OidcServerSpec {
        issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
        jwks_rotation: JwksRotation::Sequence(simple_rsa_rotation(&["initial", "rotated"])),
        cache_headers: Some(cache_policy(60, true)),
        serve_discovery: true,
        serve_jwks: true,
    }
}

#[tokio::test]
async fn deterministic_jwks_for_same_seed_and_phase() {
    let factory = deterministic_factory();
    let server_a = OidcTestServer::start(factory.clone(), spec())
        .await
        .expect("server starts");
    let server_b = OidcTestServer::start(factory, spec())
        .await
        .expect("server starts");

    let client = test_client();
    let jwks_a: Value = fetch_json(&client, server_a.jwks_url()).await;
    let jwks_b: Value = fetch_json(&client, server_b.jwks_url()).await;

    assert_eq!(jwks_a, jwks_b);

    server_a.shutdown().await;
    server_b.shutdown().await;
}

#[tokio::test]
async fn different_phase_changes_jwks_and_kid() {
    let server = OidcTestServer::start(deterministic_factory(), spec())
        .await
        .expect("server starts");
    let client = test_client();

    let initial: Value = fetch_json(&client, server.jwks_url()).await;
    let initial_kid = initial["keys"][0]["kid"].as_str().expect("kid string").to_owned();

    let _ = server.with_phase("rotated").await.expect("phase update");

    let rotated: Value = fetch_json(&client, server.jwks_url()).await;
    let rotated_kid = rotated["keys"][0]["kid"].as_str().expect("kid string").to_owned();

    assert_ne!(initial, rotated);
    assert_ne!(initial_kid, rotated_kid);

    server.shutdown().await;
}

#[tokio::test]
async fn discovery_points_to_jwks_url() {
    let server = OidcTestServer::start(deterministic_factory(), spec())
        .await
        .expect("server starts");
    let client = test_client();

    let discovery: Value = fetch_json(&client, server.discovery_url()).await;

    assert_eq!(discovery["issuer"], server.base_url());
    assert_eq!(discovery["jwks_uri"], server.jwks_url());

    server.shutdown().await;
}

#[tokio::test]
async fn etag_changes_after_rotation_with_cache_headers() {
    let server = OidcTestServer::start(deterministic_factory(), spec())
        .await
        .expect("server starts");
    let client = test_client();

    let before = client
        .get(server.jwks_url())
        .send()
        .await
        .expect("request before");
    let etag_before = before
        .headers()
        .get(reqwest::header::ETAG)
        .expect("etag")
        .to_str()
        .expect("utf8")
        .to_owned();
    let cache_control = before
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .expect("cache-control")
        .to_str()
        .expect("utf8");
    assert!(cache_control.contains("max-age=60"));

    let _ = server.with_phase("rotated").await.expect("phase update");

    let after = client
        .get(server.jwks_url())
        .send()
        .await
        .expect("request after");
    let etag_after = after
        .headers()
        .get(reqwest::header::ETAG)
        .expect("etag")
        .to_str()
        .expect("utf8")
        .to_owned();

    assert_ne!(etag_before, etag_after);

    server.shutdown().await;
}

#[tokio::test]
async fn shutdown_closes_server_port() {
    let server = OidcTestServer::start(deterministic_factory(), spec())
        .await
        .expect("server starts");
    let client = test_client();

    let ok = client
        .get(server.jwks_url())
        .send()
        .await
        .expect("request before shutdown");
    assert!(ok.status().is_success());

    let url = server.jwks_url();
    server.shutdown().await;

    let err = client
        .get(url)
        .send()
        .await
        .expect_err("request should fail after shutdown");
    assert!(err.is_connect(), "expected connection error after shutdown: {err}");
}
