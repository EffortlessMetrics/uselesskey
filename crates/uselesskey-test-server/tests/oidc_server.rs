use uselesskey_core::Factory;
use uselesskey_ecdsa::EcdsaSpec;
use uselesskey_ed25519::Ed25519Spec;
use uselesskey_rsa::RsaSpec;
use uselesskey_test_server::{
    CachePolicySpec, IssuerUrlMode, JwkFixtureSpec, JwksPhase, JwksRotation, JwksSpec,
    OidcServerSpec, OidcTestServer,
};

async fn get_ok(url: String) -> reqwest::Response {
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client");
    for _ in 0..40u8 {
        match client.get(&url).send().await {
            Ok(response) if response.status().is_success() => return response,
            Ok(_) | Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }

    let response = client.get(&url).send().await.expect("final request");
    let status = response.status();
    let body = response.text().await.expect("response text");
    panic!("request to {url} did not succeed: status={status} body={body}");
}

fn seeded_factory() -> Factory {
    Factory::deterministic_from_str("oidc-server-seed")
}

fn rotating_spec() -> OidcServerSpec {
    OidcServerSpec {
        issuer_url_mode: IssuerUrlMode::RandomPortLocalhost,
        jwks_rotation: JwksRotation::Sequence(vec![
            JwksPhase::new(
                "initial",
                JwksSpec::new(vec![
                    JwkFixtureSpec::Rsa {
                        label: "issuer-rsa-a".into(),
                        spec: RsaSpec::rs256(),
                    },
                    JwkFixtureSpec::Ed25519 {
                        label: "issuer-ed-a".into(),
                        spec: Ed25519Spec::new(),
                    },
                ]),
            ),
            JwksPhase::new(
                "rotated",
                JwksSpec::new(vec![
                    JwkFixtureSpec::Rsa {
                        label: "issuer-rsa-b".into(),
                        spec: RsaSpec::rs256(),
                    },
                    JwkFixtureSpec::Ecdsa {
                        label: "issuer-es-b".into(),
                        spec: EcdsaSpec::es256(),
                    },
                ]),
            ),
        ]),
        cache_headers: Some(CachePolicySpec {
            max_age_seconds: 60,
            public: true,
            must_revalidate: true,
        }),
        serve_discovery: true,
        serve_jwks: true,
    }
}

#[tokio::test]
async fn deterministic_same_seed_and_phase_produce_same_jwks() {
    let spec = rotating_spec();

    let server1 = OidcTestServer::start(seeded_factory(), spec.clone())
        .await
        .expect("start server1");
    let server2 = OidcTestServer::start(seeded_factory(), spec)
        .await
        .expect("start server2");

    let body1 = get_ok(server1.jwks_url())
        .await
        .text()
        .await
        .expect("server1 text");
    let body2 = get_ok(server2.jwks_url())
        .await
        .text()
        .await
        .expect("server2 text");

    assert_eq!(body1, body2);

    server1.shutdown().await.expect("shutdown1");
    server2.shutdown().await.expect("shutdown2");
}

#[tokio::test]
async fn switching_phase_changes_jwks_and_etag() {
    let server = OidcTestServer::start(seeded_factory(), rotating_spec())
        .await
        .expect("start server");

    let first = get_ok(server.jwks_url()).await;
    let first_etag = first
        .headers()
        .get(reqwest::header::ETAG)
        .expect("etag present")
        .to_str()
        .expect("etag str")
        .to_string();
    let first_body = first.text().await.expect("first text");

    server.with_phase("rotated").expect("set rotated phase");

    let second = get_ok(server.jwks_url()).await;
    let second_etag = second
        .headers()
        .get(reqwest::header::ETAG)
        .expect("etag present")
        .to_str()
        .expect("etag str")
        .to_string();
    let second_body = second.text().await.expect("second text");

    assert_ne!(first_body, second_body);
    assert_ne!(first_etag, second_etag);

    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn discovery_document_points_to_runtime_jwks_url() {
    let server = OidcTestServer::start(seeded_factory(), rotating_spec())
        .await
        .expect("start server");

    let discovery: serde_json::Value = get_ok(server.discovery_url())
        .await
        .json()
        .await
        .expect("json discovery");

    assert_eq!(discovery["jwks_uri"], server.jwks_url());
    assert_eq!(discovery["issuer"], server.base_url());

    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn cache_headers_present_for_client_cache_tests() {
    let server = OidcTestServer::start(seeded_factory(), rotating_spec())
        .await
        .expect("start server");

    let response = get_ok(server.jwks_url()).await;
    let cache_control = response
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .expect("cache-control")
        .to_str()
        .expect("cache-control string");

    assert!(cache_control.contains("max-age=60"));
    assert!(cache_control.contains("must-revalidate"));

    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn shutdown_releases_listening_port() {
    let server = OidcTestServer::start(seeded_factory(), rotating_spec())
        .await
        .expect("start server");

    let addr = server
        .base_url()
        .trim_start_matches("http://")
        .parse::<std::net::SocketAddr>()
        .expect("socket addr");

    server.shutdown().await.expect("shutdown");

    let rebound = std::net::TcpListener::bind(addr).expect("port should be reusable");
    drop(rebound);
}
