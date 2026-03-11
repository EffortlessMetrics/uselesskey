#![forbid(unsafe_code)]

//! JWT-shaped OAuth access token primitives.
//!
//! Generates deterministic (for seeded RNGs) OAuth access-token strings in
//! `header.payload.signature` form without cryptographic signing.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::RngCore;
use serde_json::json;

/// Number of random bytes used for OAuth `jti`.
pub const OAUTH_JTI_BYTES: usize = 16;

/// Number of random bytes used for OAuth signature-like segment.
pub const OAUTH_SIGNATURE_BYTES: usize = 32;

/// Generate a JWT-shaped OAuth access token (`header.payload.signature`).
pub fn generate_oauth_access_token(label: &str, rng: &mut impl RngCore) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);

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
