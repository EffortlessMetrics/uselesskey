use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};
use serde_json::json;
use uselesskey_core::Seed;

use super::{
    API_KEY_PREFIX, API_KEY_RANDOM_LEN, BEARER_RANDOM_BYTES, OAUTH_JTI_BYTES,
    OAUTH_SIGNATURE_BYTES, random_base62,
};

/// Generate an API-key style token fixture (`uk_test_<base62>`).
pub fn generate_api_key(seed: Seed) -> String {
    let mut out = String::from(API_KEY_PREFIX);
    out.push_str(&random_base62(seed, API_KEY_RANDOM_LEN));
    out
}

/// Generate an opaque bearer token fixture (base64url of 32 random bytes).
pub fn generate_bearer_token(seed: Seed) -> String {
    let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
    let mut bytes = [0u8; BEARER_RANDOM_BYTES];
    rng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate an OAuth access token fixture in JWT shape (`header.payload.signature`).
pub fn generate_oauth_access_token(label: &str, seed: Seed) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
    let mut rng = ChaCha20Rng::from_seed(*seed.bytes());

    let mut jti = [0u8; OAUTH_JTI_BYTES];
    rng.fill_bytes(&mut jti);

    let payload = json!({
        "iss": "uselesskey",
        "sub": label,
        "aud": "tests",
        "scope": "fixture.read",
        "jti": URL_SAFE_NO_PAD.encode(jti),
        "exp": 2_000_000_000u64,
    });
    let payload_json = serde_json::to_vec(&payload).expect("payload JSON");
    let payload_segment = URL_SAFE_NO_PAD.encode(payload_json);

    let mut signature = [0u8; OAUTH_SIGNATURE_BYTES];
    rng.fill_bytes(&mut signature);
    let signature_segment = URL_SAFE_NO_PAD.encode(signature);

    format!("{header}.{payload_segment}.{signature_segment}")
}

