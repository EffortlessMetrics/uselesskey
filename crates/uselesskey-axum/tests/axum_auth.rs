use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use axum::{Json, Router, routing::get};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uselesskey_axum::{
    DeterministicJwksRotation, ExpectedAuthValues, OidcConfig, TestAuthContext, basic_claims,
    jwks_router, jwks_router_with_rotation, mock_jwt_verifier_layer, oidc_router,
};
use uselesskey_core::{Factory, Seed};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs()
}

fn sign_token(key: &uselesskey_rsa::RsaKeyPair, claims: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(key.private_key_pkcs8_pem().as_bytes()).expect("valid fixture"),
    )
    .expect("sign token")
}

async fn protected(TestAuthContext { sub, iss, aud, kid, .. }: TestAuthContext) -> Json<Value> {
    Json(json!({"sub": sub, "iss": iss, "aud": aud, "kid": kid}))
}

#[tokio::test]
async fn axum_round_trip_with_verifier_layer() {
    let fx = Factory::deterministic(Seed::from_env_value("uk-axum-roundtrip").expect("seed"));
    let key = fx.rsa("issuer", RsaSpec::rs256());

    let verifier = uselesskey_axum::MockJwtVerifier::new()
        .with_keys(vec![key.clone()])
        .with_expected(ExpectedAuthValues::new("https://issuer.test", "api://test").with_kid(key.kid()));

    let app = Router::new()
        .route("/protected", get(protected))
        ;
    let app = mock_jwt_verifier_layer(app, verifier);

    let token = sign_token(
        &key,
        basic_claims("alice", "https://issuer.test", "api://test", now() + 300),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(body["sub"], "alice");
    assert_eq!(body["iss"], "https://issuer.test");
}

#[tokio::test]
async fn jwks_rotation_router_switches_phases() {
    let fx = Factory::deterministic(Seed::from_env_value("uk-axum-rotation").expect("seed"));
    let old = fx.rsa("old", RsaSpec::rs256());
    let new = fx.rsa("new", RsaSpec::rs256());

    let rotation = DeterministicJwksRotation::new(vec![vec![old.clone()], vec![new.clone()]]);
    let app = jwks_router_with_rotation("/.well-known/jwks.json", rotation.clone());

    let get_kids = |app: Router| async move {
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let body: Value = serde_json::from_slice(&bytes).expect("json");
        body["keys"]
            .as_array()
            .expect("keys")
            .iter()
            .map(|k| k["kid"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>()
    };

    let phase0 = get_kids(app.clone()).await;
    assert_eq!(phase0, vec![old.kid()]);

    rotation.set_phase(1);
    let phase1 = get_kids(app).await;
    assert_eq!(phase1, vec![new.kid()]);
}

#[tokio::test]
async fn jwks_and_oidc_routers_serve_payloads() {
    let fx = Factory::deterministic(Seed::from_env_value("uk-axum-jwks-oidc").expect("seed"));
    let key = fx.rsa("issuer", RsaSpec::rs256());

    let app = Router::new()
        .merge(jwks_router(vec![key.clone()]))
        .merge(oidc_router(OidcConfig::new(
            "https://issuer.test",
            "https://issuer.test/.well-known/jwks.json",
        )));

    let jwks_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("jwks response");
    assert_eq!(jwks_response.status(), StatusCode::OK);

    let oidc_response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("oidc response");
    assert_eq!(oidc_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn unauthorized_expired_and_wrong_audience_are_rejected() {
    let fx = Factory::deterministic(Seed::from_env_value("uk-axum-negatives").expect("seed"));
    let key = fx.rsa("issuer", RsaSpec::rs256());

    let verifier = uselesskey_axum::MockJwtVerifier::new()
        .with_keys(vec![key.clone()])
        .with_expected(ExpectedAuthValues::new("https://issuer.test", "api://good").with_kid(key.kid()));

    let app = Router::new()
        .route("/protected", get(|| async { "ok" }))
        ;
    let app = mock_jwt_verifier_layer(app, verifier);

    let no_auth = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(no_auth.status(), StatusCode::UNAUTHORIZED);

    let expired = sign_token(
        &key,
        basic_claims("alice", "https://issuer.test", "api://good", now() - 60),
    );
    let expired_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", format!("Bearer {expired}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(expired_resp.status(), StatusCode::UNAUTHORIZED);

    let wrong_aud = sign_token(
        &key,
        basic_claims("alice", "https://issuer.test", "api://wrong", now() + 60),
    );
    let wrong_aud_resp = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", format!("Bearer {wrong_aud}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(wrong_aud_resp.status(), StatusCode::UNAUTHORIZED);
}
