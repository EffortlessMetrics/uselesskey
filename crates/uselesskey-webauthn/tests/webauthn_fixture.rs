use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uselesskey_core::{Factory, Seed};
use uselesskey_webauthn::{WebauthnFactoryExt, WebauthnSpec};

#[test]
fn cbor_attestation_object_contains_required_fields() {
    let fx = Factory::deterministic(Seed::from_env_value("webauthn-cbor").unwrap());
    let fixture = fx.webauthn("passkey", WebauthnSpec::default());
    let registration = fixture.registration();

    let parsed = fixture.parse_attestation_object(&registration).unwrap();
    assert_eq!(parsed.get("fmt").and_then(|v| v.as_text()), Some("packed"));
    assert!(parsed.contains_key("authData"));
    assert!(parsed.contains_key("attStmt"));
}

#[test]
fn assertion_verification_and_sign_count_are_deterministic() {
    let fx = Factory::deterministic(Seed::from_env_value("webauthn-verify").unwrap());
    let fixture = fx.webauthn("passkey", WebauthnSpec::default());

    let a0 = fixture.assertion(0);
    let a1 = fixture.assertion(1);

    fixture.verify_assertion(&a0).unwrap();
    fixture.verify_assertion(&a1).unwrap();

    assert_eq!(a1.sign_count, a0.sign_count + 1);
}

#[test]
fn challenge_flows_into_client_data_json() {
    let challenge = b"deterministic-challenge".to_vec();
    let spec = WebauthnSpec {
        challenge: challenge.clone(),
        ..WebauthnSpec::default()
    };

    let fx = Factory::deterministic(Seed::from_env_value("webauthn-challenge").unwrap());
    let fixture = fx.webauthn("passkey", spec);
    let assertion = fixture.assertion(0);
    let parsed = assertion.parse_client_data();

    assert_eq!(parsed.challenge, URL_SAFE_NO_PAD.encode(challenge));
}

trait CborText {
    fn as_text(&self) -> Option<&str>;
}

impl CborText for serde_cbor::Value {
    fn as_text(&self) -> Option<&str> {
        if let serde_cbor::Value::Text(s) = self {
            Some(s)
        } else {
            None
        }
    }
}
