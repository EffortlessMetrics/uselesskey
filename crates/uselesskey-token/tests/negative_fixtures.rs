use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use uselesskey_core::{Factory, Seed};
use uselesskey_token::{NegativeToken, TokenFactoryExt, TokenSpec};

fn decode_payload(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("JWT payload segment");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("decode payload");
    serde_json::from_slice(&bytes).expect("parse payload")
}

#[test]
fn token_fixture_emits_expired_oauth_negative_value() {
    let fx = Factory::deterministic(Seed::from_env_value("token-negative-it").unwrap());
    let token = fx.token("issuer", TokenSpec::oauth_access_token());

    let expired = token.negative_value(NegativeToken::ExpiredClaims);

    assert_eq!(expired.matches('.').count(), 2);
    assert_eq!(decode_payload(&expired)["exp"], 1);
    assert_ne!(expired, token.value());
}

#[test]
fn token_fixture_emits_malformed_bearer_negative_value() {
    let fx = Factory::deterministic(Seed::from_env_value("token-negative-bearer").unwrap());
    let token = fx.token("gateway", TokenSpec::bearer());

    let malformed = token.negative_value(NegativeToken::MalformedBearer);

    assert!(URL_SAFE_NO_PAD.decode(&malformed).is_err());
    assert_ne!(malformed, token.value());
}

#[test]
fn token_fixture_emits_api_key_near_miss_negative_value() {
    let fx = Factory::deterministic(Seed::from_env_value("token-negative-api").unwrap());
    let token = fx.token("billing", TokenSpec::api_key());

    let near_miss = token.negative_value(NegativeToken::NearMissApiKey);

    assert!(near_miss.starts_with("uk_tset_"));
    assert!(!near_miss.starts_with("uk_test_"));
    assert_ne!(near_miss, token.value());
}
