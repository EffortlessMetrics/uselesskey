#![forbid(unsafe_code)]

//! JWT-shaped OAuth access token primitives for test fixtures.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::RngCore;
use serde_json::json;

/// Number of random bytes used for OAuth `jti`.
pub const OAUTH_JTI_BYTES: usize = 16;

/// Number of random bytes used for OAuth signature-like segment.
pub const OAUTH_SIGNATURE_BYTES: usize = 32;

/// Generate an OAuth access token fixture in JWT shape (`header.payload.signature`).
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

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::{OAUTH_JTI_BYTES, OAUTH_SIGNATURE_BYTES, generate_oauth_access_token};

    #[test]
    fn oauth_shape_has_three_segments_and_subject() {
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let value = generate_oauth_access_token("issuer", &mut rng);
        let parts: Vec<&str> = value.split('.').collect();
        assert_eq!(parts.len(), 3);

        let payload = URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("decode payload segment");
        let json: serde_json::Value = serde_json::from_slice(&payload).expect("parse payload");
        assert_eq!(json["sub"], "issuer");
        assert_eq!(json["iss"], "uselesskey");

        let jti = json["jti"].as_str().expect("jti is a string");
        let jti_raw = URL_SAFE_NO_PAD.decode(jti).expect("decode jti");
        assert_eq!(jti_raw.len(), OAUTH_JTI_BYTES);

        let sig_raw = URL_SAFE_NO_PAD
            .decode(parts[2])
            .expect("decode signature segment");
        assert_eq!(sig_raw.len(), OAUTH_SIGNATURE_BYTES);
    }
}
