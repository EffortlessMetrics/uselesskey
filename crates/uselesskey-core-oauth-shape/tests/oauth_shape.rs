use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use uselesskey_core_oauth_shape::generate_oauth_access_token;

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
}

#[test]
fn oauth_signature_decodes_to_expected_length() {
    let mut rng = ChaCha20Rng::from_seed([14u8; 32]);
    let value = generate_oauth_access_token("issuer", &mut rng);
    let signature = value.split('.').nth(2).expect("signature segment");
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .expect("decode signature segment");
    assert_eq!(sig_bytes.len(), 32);
}
