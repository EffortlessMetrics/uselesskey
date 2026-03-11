use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use uselesskey_core_jwt_shape::{
    OAUTH_JTI_BYTES, OAUTH_SIGNATURE_BYTES, generate_oauth_access_token,
};

fn rng(seed_byte: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed_byte; 32])
}

#[test]
fn oauth_shape_has_three_segments_and_expected_claims() {
    let token = generate_oauth_access_token("issuer", &mut rng(11));
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);

    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("decode payload segment");
    let json: serde_json::Value = serde_json::from_slice(&payload).expect("parse payload");

    assert_eq!(json["sub"], "issuer");
    assert_eq!(json["iss"], "uselesskey");
    assert_eq!(json["aud"], "tests");
}

#[test]
fn signature_and_jti_lengths_match_constants() {
    let token = generate_oauth_access_token("svc", &mut rng(33));
    let parts: Vec<&str> = token.split('.').collect();

    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("decode payload segment");
    let json: serde_json::Value = serde_json::from_slice(&payload).expect("parse payload");
    let jti = json["jti"].as_str().expect("jti string");

    let decoded_jti = URL_SAFE_NO_PAD.decode(jti).expect("decode jti");
    let decoded_signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("decode signature");

    assert_eq!(decoded_jti.len(), OAUTH_JTI_BYTES);
    assert_eq!(decoded_signature.len(), OAUTH_SIGNATURE_BYTES);
}
