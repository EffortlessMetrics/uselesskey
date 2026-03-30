use axum::{
    Json, Router,
    body::{self, Body},
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::get,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use tower::ServiceExt;
use uselesskey_axum::{
    DeterministicJwksPhase, MockJwtVerifierState, RotationPhase, TestAuthContext,
    inject_auth_context_layer, jwks_router, mock_jwt_verifier_layer, oidc_router,
};
use uselesskey_core::{Factory, Seed};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

fn auth_state() -> MockJwtVerifierState {
    let seed = Seed::from_env_value("uselesskey-axum-integration-v1").expect("seed");
    let phase = DeterministicJwksPhase::new(
        seed,
        "auth-suite",
        RotationPhase::Primary,
        "https://issuer.example.test",
        "api://example-aud",
    );
    MockJwtVerifierState::new(phase)
}

fn signer_fixture() -> (uselesskey_rsa::RsaKeyPair, String, String) {
    let fx =
        Factory::deterministic(Seed::from_env_value("uselesskey-axum-signer-v1").expect("seed"));
    let key = fx.rsa("auth-suite-signer", RsaSpec::rs256());
    let issuer = "https://issuer.example.test".to_string();
    let audience = "api://example-aud".to_string();
    (key, issuer, audience)
}

fn signed_token(key: &uselesskey_rsa::RsaKeyPair, claims: serde_json::Value, kid: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());

    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(key.private_key_pkcs8_pem().as_bytes())
            .expect("valid private key PEM"),
    )
    .expect("token encoding should succeed")
}

#[tokio::test]
async fn jwks_and_oidc_routes_round_trip() {
    let state = auth_state();
    let app = Router::new()
        .merge(jwks_router(state.clone()))
        .merge(oidc_router(state.clone(), "https://issuer.example.test"));

    let jwks_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(jwks_response.status(), StatusCode::OK);
    let jwks_body = body::to_bytes(jwks_response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&jwks_body).unwrap(),
        state.jwks_json()
    );

    let oidc_response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oidc_response.status(), StatusCode::OK);
    let oidc_body = body::to_bytes(oidc_response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&oidc_body).unwrap(),
        state.oidc_json("https://issuer.example.test")
    );
}

#[tokio::test]
async fn verifier_accepts_valid_bearer_token_and_injects_context() {
    let state = auth_state();
    let token = state.issue_token(json!({"sub":"alice"}), 300);

    let app = mock_jwt_verifier_layer(
        Router::new().route(
            "/me",
            get(|auth: TestAuthContext| async move {
                Json(json!({
                    "sub": auth.sub,
                    "iss": auth.iss,
                    "aud": auth.aud,
                    "kid": auth.kid,
                }))
                .into_response()
            }),
        ),
        state.clone(),
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/me")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
    assert_eq!(value["sub"], "alice");
    assert_eq!(value["iss"], "https://issuer.example.test");
    assert_eq!(value["aud"], "api://example-aud");
    assert_eq!(value["kid"], state.expectations().kid);
}

#[tokio::test]
async fn verifier_rejects_wrong_audience_and_expired_tokens() {
    let state = auth_state();
    let (key, issuer, audience) = signer_fixture();

    let app = mock_jwt_verifier_layer(
        Router::new().route("/me", get(|| async { StatusCode::OK })),
        state.clone(),
    );

    let wrong_aud = signed_token(
        &key,
        json!({
            "sub": "alice",
            "iss": issuer,
            "aud": "api://wrong-aud",
            "exp": 4_102_444_800i64,
        }),
        &state.expectations().kid,
    );
    let wrong_aud_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/me")
                .header("authorization", format!("Bearer {wrong_aud}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_aud_response.status(), StatusCode::UNAUTHORIZED);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("unix time")
        .as_secs() as i64;
    let expired = signed_token(
        &key,
        json!({
            "sub": "alice",
            "iss": issuer,
            "aud": audience,
            "exp": now.saturating_sub(5),
        }),
        &state.expectations().kid,
    );
    let expired_response = app
        .oneshot(
            Request::builder()
                .uri("/me")
                .header("authorization", format!("Bearer {expired}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(expired_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_context_injection_layer_works_without_jwt_parsing() {
    let app = inject_auth_context_layer(
        Router::new().route(
            "/me",
            get(|auth: TestAuthContext| async move {
                Json(json!({
                    "sub": auth.sub,
                    "kid": auth.kid,
                }))
                .into_response()
            }),
        ),
        TestAuthContext {
            sub: "test-user".into(),
            iss: "iss".into(),
            aud: "aud".into(),
            kid: "kid-1".into(),
            exp: 42,
        },
    );

    let response = app
        .oneshot(Request::builder().uri("/me").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value = serde_json::from_slice::<serde_json::Value>(&body).unwrap();
    assert_eq!(value["sub"], "test-user");
    assert_eq!(value["kid"], "kid-1");
}
