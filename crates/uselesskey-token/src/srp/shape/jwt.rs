use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value, json};
use uselesskey_core::Seed;

use super::generate_oauth_access_token;

pub(super) fn oauth_parts(label: &str, seed: Seed) -> [String; 3] {
    let token = generate_oauth_access_token(label, seed);
    let mut parts = token.split('.');
    let header = parts.next().expect("JWT header segment").to_string();
    let payload = parts.next().expect("JWT payload segment").to_string();
    let signature = parts.next().expect("JWT signature segment").to_string();
    assert!(
        parts.next().is_none(),
        "JWT should have exactly three segments"
    );

    [header, payload, signature]
}

pub(super) fn jwt_header() -> Map<String, Value> {
    Map::from_iter([
        ("alg".to_string(), json!("RS256")),
        ("typ".to_string(), json!("JWT")),
    ])
}

pub(super) fn decode_object(segment: &str) -> Map<String, Value> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .expect("decode generated JWT JSON segment");
    let value: Value = serde_json::from_slice(&bytes).expect("parse generated JWT JSON segment");
    value
        .as_object()
        .expect("generated JWT JSON segment should be an object")
        .clone()
}

pub(super) fn encode_object(value: &Map<String, Value>) -> String {
    encode_json(&Value::Object(value.clone()))
}

pub(super) fn encode_json(value: &Value) -> String {
    let json = serde_json::to_vec(value).expect("serialize token JSON");
    URL_SAFE_NO_PAD.encode(json)
}

