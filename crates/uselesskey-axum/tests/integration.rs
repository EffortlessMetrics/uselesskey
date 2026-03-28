use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::get,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;
use uselesskey_axum::{
    ExpectedAuthValues, MockJwtVerifierConfig, TestAuthContext, deterministic_claims,
    expected_audiences, jwks_router_with_phases, mock_jwt_verifier_layer, oidc_router,
};
use uselesskey_core::{Factory, Seed};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    exp: i64,
}

async fn protected_handler(ctx: TestAuthContext) -> impl IntoResponse {
    let payload = serde_json::json!({
        "sub": ctx.subject(),
        "iss": ctx.issuer(),
        "aud": ctx.audience(),
        "kid": ctx.kid(),
    });
    axum::Json(payload)
}

fn signer_fixture() -> (uselesskey_rsa::RsaKeyPair, ExpectedAuthValues) {
    let fx = Factory::deterministic(Seed::from_env_value("axum-auth-helpers-seed-v1").expect("seed"));
    let key = fx.rsa("issuer", RsaSpec::rs256());
    let expected = ExpectedAuthValues::new("https://issuer.test", "api://payments").with_kid(key.kid());
    (key, expected)
}

fn signed_token(key: &uselesskey_rsa::RsaKeyPair, claims: &Claims) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid());

    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(key.private_key_pkcs8_pem().as_bytes())
            .expect("valid private pem"),
    )
    .expect("token encoding should succeed")
}

#[tokio::test]
async fn jwks_and_oidc_routers_round_trip() {
    let phase0 = serde_json::json!({ "keys": [{"kid": "old"}] });
    let phase1 = serde_json::json!({ "keys": [{"kid": "new"}] });

    let app = Router::new()
        .merge(jwks_router_with_phases(vec![phase0.clone(), phase1.clone()]))
        .merge(oidc_router(
            "https://issuer.test",
            "https://issuer.test/.well-known/jwks.json",
        ));

    let jwks_default = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(jwks_default.status(), StatusCode::OK);

    let body = axum::body::to_bytes(jwks_default.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value, phase0);

    let jwks_rotated = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json?phase=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(jwks_rotated.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value, phase1);

    let oidc = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(oidc.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["issuer"], "https://issuer.test");
    assert_eq!(
        value["jwks_uri"],
        "https://issuer.test/.well-known/jwks.json"
    );
}

#[tokio::test]
async fn verifier_accepts_valid_bearer_token() {
    let (key, expected) = signer_fixture();

    let app = Router::new()
        .route("/protected", get(protected_handler))
        .layer(mock_jwt_verifier_layer(
            MockJwtVerifierConfig::new(expected).with_rsa_keypair(&key),
        ));

    let token = signed_token(
        &key,
        &Claims {
            sub: "alice".into(),
            iss: "https://issuer.test".into(),
            aud: "api://payments".into(),
            exp: 4_102_444_800,
        },
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn verifier_rejects_expired_wrong_audience_and_missing_auth() {
    let (key, expected) = signer_fixture();

    let app = Router::new()
        .route("/protected", get(protected_handler))
        .layer(mock_jwt_verifier_layer(
            MockJwtVerifierConfig::new(expected.clone())
                .with_rsa_keypair(&key)
                .with_now_unix(2_000),
        ));

    let expired = signed_token(
        &key,
        &Claims {
            sub: "bob".into(),
            iss: expected.issuer().to_owned(),
            aud: expected.audience().to_owned(),
            exp: 1_999,
        },
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", format!("Bearer {expired}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let wrong_aud = signed_token(
        &key,
        &Claims {
            sub: "bob".into(),
            iss: expected.issuer().to_owned(),
            aud: "api://other".into(),
            exp: 2_500,
        },
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("authorization", format!("Bearer {wrong_aud}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn deterministic_helper_outputs_canonical_claim_order() {
    let ordered = deterministic_claims(serde_json::json!({
        "z": 1,
        "a": 2,
        "sub": "alice"
    }));
    let txt = serde_json::to_string(&ordered).unwrap();
    assert_eq!(txt, r#"{"a":2,"sub":"alice","z":1}"#);

    assert_eq!(
        expected_audiences("api://one", &["api://two", "api://one"]),
        vec!["api://one".to_string(), "api://two".to_string()]
    );
}
