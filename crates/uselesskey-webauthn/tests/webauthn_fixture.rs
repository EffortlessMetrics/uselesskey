use sha2::Digest;
use base64::Engine;
use serde_cbor::Value as CborValue;
use serde_json::Value as JsonValue;
use uselesskey_core_seed::Seed;
use uselesskey_webauthn::{AttestationMode, WebAuthnSpec, deterministic_fixture};

fn spec() -> WebAuthnSpec {
    WebAuthnSpec {
        rp_id: "example.test".to_owned(),
        challenge: b"challenge-123".to_vec(),
        credential_id: b"credential-abc".to_vec(),
        authenticator_model: "uk-authn-mock-v1".to_owned(),
        attestation_mode: AttestationMode::Packed,
        sign_count_start: 41,
        aaguid: [7u8; 16],
    }
}

#[test]
fn attestation_object_parses_and_contains_ceremony_fields() {
    let fixture = deterministic_fixture(Seed::from_text("wa-seed"), "registration", &spec()).unwrap();
    let value: CborValue = serde_cbor::from_slice(&fixture.registration.attestation_object).unwrap();

    let map = match value {
        CborValue::Map(map) => map,
        _ => panic!("expected CBOR map"),
    };

    assert!(map.iter().any(|(k, _)| *k == CborValue::Text("fmt".into())));
    assert!(map.iter().any(|(k, _)| *k == CborValue::Text("authData".into())));
    assert!(map.iter().any(|(k, _)| *k == CborValue::Text("attStmt".into())));

    let client_json: JsonValue = serde_json::from_slice(&fixture.registration.client_data_json).unwrap();
    assert_eq!(client_json["type"], "webauthn.create");
    assert_eq!(
        client_json["challenge"],
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&fixture.registration.challenge)
    );
    let expected_rp_hash: [u8; 32] = sha2::Sha256::digest(b"example.test").into();
    assert_eq!(fixture.registration.rp_id_hash, expected_rp_hash);
}

#[test]
fn deterministic_sign_count_and_challenge_behavior() {
    let seed = Seed::from_text("wa-det-seed");
    let a = deterministic_fixture(seed, "login", &spec()).unwrap();
    let b = deterministic_fixture(seed, "login", &spec()).unwrap();

    assert_eq!(a, b);
    assert_eq!(a.registration.sign_count, 41);
    assert_eq!(a.assertion.sign_count, 42);
    assert_eq!(a.registration.challenge, b"challenge-123".to_vec());
    assert_eq!(a.assertion.challenge, b"challenge-123".to_vec());
}

#[test]
fn spec_stable_bytes_include_attestation_mode_and_model() {
    let packed = spec();
    let mut self_att = spec();
    self_att.attestation_mode = AttestationMode::SelfAttestation;
    self_att.authenticator_model = "other-model".to_owned();

    assert_ne!(packed.stable_bytes(), self_att.stable_bytes());
}
