use axum::{
    Json, Router,
    http::{Request, StatusCode, header},
    routing::get,
};
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uselesskey_axum::{
    AuthServerConfig, JwtVerifierConfig, TestAuthContext, jwks_router, mock_jwt_verifier_layer,
    oidc_router,
};
use uselesskey_core::Factory;
use uselesskey_jose_openid::JoseOpenIdKeyExt;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

fn verifier_config() -> JwtVerifierConfig {
    JwtVerifierConfig::deterministic(
        "axum-auth-seed-v1",
        "issuer-main",
        "https://issuer.example",
        "api://tests",
    )
}

fn encoding_key(seed: &str, label: &str) -> EncodingKey {
    Factory::deterministic_from_str(seed)
        .rsa(label, RsaSpec::rs256())
        .encoding_key()
}

fn token(seed: &str, label: &str, issuer: &str, audience: &str, exp: i64) -> String {
    let keypair = Factory::deterministic_from_str(seed).rsa(label, RsaSpec::rs256());
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(keypair.kid());
    let claims = json!({
        "sub": "alice",
        "iss": issuer,
        "aud": audience,
        "exp": exp,
    });
    encode(&header, &claims, &encoding_key(seed, label)).expect("token")
}

#[tokio::test]
async fn axum_round_trip_injects_auth_context() {
    let cfg = verifier_config();
    let app = Router::new()
        .route(
            "/protected",
            get(|ctx: TestAuthContext| async move {
                Json(json!({
                    "sub": ctx.subject,
                    "aud": ctx.audiences,
                    "iss": ctx.issuer,
                }))
            }),
        )
        .layer(mock_jwt_verifier_layer(cfg.clone()));

    let token = token(
        &cfg.seed,
        &cfg.label,
        &cfg.expected.issuer,
        &cfg.expected.audience,
        4_102_444_800,
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["sub"], "alice");
    assert_eq!(payload["iss"], cfg.expected.issuer);
    assert_eq!(payload["aud"], json!([cfg.expected.audience]));
}

#[tokio::test]
async fn unauthorized_expired_wrong_audience_and_missing_token() {
    let cfg = verifier_config();
    let app = Router::new()
        .route("/protected", get(|| async { StatusCode::NO_CONTENT }))
        .layer(mock_jwt_verifier_layer(cfg.clone()));

    let missing = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);

    let expired = token(
        &cfg.seed,
        &cfg.label,
        &cfg.expected.issuer,
        &cfg.expected.audience,
        1,
    );
    let expired_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(header::AUTHORIZATION, format!("Bearer {expired}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(expired_res.status(), StatusCode::UNAUTHORIZED);

    let wrong_aud = token(
        &cfg.seed,
        &cfg.label,
        &cfg.expected.issuer,
        "api://wrong",
        4_102_444_800,
    );
    let wrong_aud_res = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(header::AUTHORIZATION, format!("Bearer {wrong_aud}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_aud_res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwks_and_oidc_routers_support_rotation_phase() {
    let cfg = AuthServerConfig {
        seed: "axum-jwks-seed-v1".into(),
        label: "issuer".into(),
        issuer: "https://issuer.example".into(),
        phases: vec!["phase0".into(), "phase1".into()],
        ..Default::default()
    };

    let app = jwks_router(cfg.clone()).merge(oidc_router(cfg.clone()));

    let phase0 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json?phase=phase0")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(phase0.status(), StatusCode::OK);
    let kid0 = serde_json::from_slice::<Value>(&phase0.into_body().collect().await.unwrap().to_bytes())
        .unwrap()["keys"][0]["kid"]
        .as_str()
        .unwrap()
        .to_string();

    let phase1 = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json?phase=phase1")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let kid1 = serde_json::from_slice::<Value>(&phase1.into_body().collect().await.unwrap().to_bytes())
        .unwrap()["keys"][0]["kid"]
        .as_str()
        .unwrap()
        .to_string();

    assert_ne!(kid0, kid1);

    let oidc = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oidc.status(), StatusCode::OK);
    let discovery: Value =
        serde_json::from_slice(&oidc.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(discovery["issuer"], "https://issuer.example");
    assert_eq!(
        discovery["jwks_uri"],
        "https://issuer.example/.well-known/jwks.json"
    );
}
