use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use uselesskey_core_token_oauth_shape::{
    OAUTH_JTI_BYTES, OAUTH_SIGNATURE_BYTES, generate_oauth_access_token,
};

#[test]
fn oauth_shape_has_three_segments_and_expected_claims() {
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

    let jti = URL_SAFE_NO_PAD
        .decode(json["jti"].as_str().expect("jti string"))
        .expect("decode jti");
    assert_eq!(jti.len(), OAUTH_JTI_BYTES);

    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("decode signature segment");
    assert_eq!(signature.len(), OAUTH_SIGNATURE_BYTES);
}
