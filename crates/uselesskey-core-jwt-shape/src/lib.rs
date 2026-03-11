#![forbid(unsafe_code)]

//! JWT-shape generation primitives for token fixtures.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::RngCore;
use serde_json::json;

/// Number of random bytes used for OAuth `jti`.
pub const OAUTH_JTI_BYTES: usize = 16;

/// Number of random bytes used for OAuth signature-like segment.
pub const OAUTH_SIGNATURE_BYTES: usize = 32;

/// Standard test header encoded for JWT-shape tokens.
#[must_use]
pub fn oauth_header_segment() -> String {
    URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#)
}

/// Generate the payload segment for OAuth JWT-shape tokens.
#[must_use]
pub fn oauth_payload_segment(label: &str, rng: &mut impl RngCore) -> String {
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
    URL_SAFE_NO_PAD.encode(payload_json)
}

/// Generate the signature segment for OAuth JWT-shape tokens.
#[must_use]
pub fn oauth_signature_segment(rng: &mut impl RngCore) -> String {
    let mut signature = [0u8; OAUTH_SIGNATURE_BYTES];
    rng.fill_bytes(&mut signature);
    URL_SAFE_NO_PAD.encode(signature)
}

/// Generate an OAuth access token fixture in JWT shape (`header.payload.signature`).
#[must_use]
pub fn generate_oauth_access_token(label: &str, rng: &mut impl RngCore) -> String {
    let header = oauth_header_segment();
    let payload = oauth_payload_segment(label, rng);
    let signature = oauth_signature_segment(rng);
    format!("{header}.{payload}.{signature}")
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::{
        OAUTH_JTI_BYTES, OAUTH_SIGNATURE_BYTES, generate_oauth_access_token, oauth_header_segment,
        oauth_payload_segment, oauth_signature_segment,
    };

    #[test]
    fn header_segment_is_expected_shape() {
        let header = oauth_header_segment();
        let decoded = URL_SAFE_NO_PAD.decode(header).expect("decode header");
        let value: serde_json::Value = serde_json::from_slice(&decoded).expect("header json");
        assert_eq!(value["alg"], "RS256");
        assert_eq!(value["typ"], "JWT");
    }

    #[test]
    fn payload_segment_contains_subject_and_jti_length() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let payload = oauth_payload_segment("issuer", &mut rng);
        let decoded = URL_SAFE_NO_PAD.decode(payload).expect("decode payload");
        let value: serde_json::Value = serde_json::from_slice(&decoded).expect("payload json");

        assert_eq!(value["sub"], "issuer");
        assert_eq!(value["iss"], "uselesskey");

        let jti = value["jti"].as_str().expect("jti string");
        let jti_bytes = URL_SAFE_NO_PAD.decode(jti).expect("decode jti");
        assert_eq!(jti_bytes.len(), OAUTH_JTI_BYTES);
    }

    #[test]
    fn signature_segment_has_expected_bytes() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let sig = oauth_signature_segment(&mut rng);
        let decoded = URL_SAFE_NO_PAD.decode(sig).expect("decode signature");
        assert_eq!(decoded.len(), OAUTH_SIGNATURE_BYTES);
    }

    #[test]
    fn oauth_token_has_three_segments() {
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let token = generate_oauth_access_token("issuer", &mut rng);
        assert_eq!(token.split('.').count(), 3);
    }
}
