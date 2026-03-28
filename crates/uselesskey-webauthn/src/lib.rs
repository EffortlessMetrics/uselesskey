#![forbid(unsafe_code)]

//! Deterministic WebAuthn ceremony fixtures.
//!
//! This crate provides realistic fixture shapes for registration/assertion
//! testing. It is not a full WebAuthn server implementation.

use std::collections::BTreeMap;

use serde_cbor::{Value, to_vec};
use serde_json::json;
use sha2::{Digest, Sha256};
use uselesskey_core::Factory;

/// Stable cache domain for WebAuthn fixtures.
pub const DOMAIN_WEBAUTHN_FIXTURE: &str = "uselesskey:webauthn:fixture:v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationMode {
    Packed,
    SelfAttestation,
}

impl AttestationMode {
    fn as_tag(self) -> &'static str {
        match self {
            Self::Packed => "packed",
            Self::SelfAttestation => "self",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebAuthnSpec {
    pub rp_id: String,
    pub challenge: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub authenticator_model: String,
    pub attestation_mode: AttestationMode,
}

impl WebAuthnSpec {
    pub fn packed(rp_id: impl Into<String>, challenge: impl AsRef<[u8]>) -> Self {
        Self {
            rp_id: rp_id.into(),
            challenge: challenge.as_ref().to_vec(),
            credential_id: b"uk-credential-id".to_vec(),
            authenticator_model: "UK-PASSKEY-MOCK".to_string(),
            attestation_mode: AttestationMode::Packed,
        }
    }

    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_field(&mut out, "rp_id", self.rp_id.as_bytes());
        write_field(&mut out, "challenge", &self.challenge);
        write_field(&mut out, "credential_id", &self.credential_id);
        write_field(&mut out, "authenticator_model", self.authenticator_model.as_bytes());
        write_field(
            &mut out,
            "attestation_mode",
            self.attestation_mode.as_tag().as_bytes(),
        );
        out
    }
}

#[derive(Clone, Debug)]
pub struct RegistrationFixture {
    pub spec: WebAuthnSpec,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub rp_id_hash: [u8; 32],
    pub sign_count: u32,
    pub aaguid: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct AssertionFixture {
    pub spec: WebAuthnSpec,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub rp_id_hash: [u8; 32],
    pub sign_count: u32,
}

pub trait WebAuthnFactoryExt {
    fn webauthn_registration(
        &self,
        label: impl AsRef<str>,
        spec: WebAuthnSpec,
    ) -> RegistrationFixture;

    fn webauthn_assertion(&self, label: impl AsRef<str>, spec: WebAuthnSpec) -> AssertionFixture;
}

impl WebAuthnFactoryExt for Factory {
    fn webauthn_registration(
        &self,
        label: impl AsRef<str>,
        spec: WebAuthnSpec,
    ) -> RegistrationFixture {
        let spec_bytes = spec.stable_bytes();
        self.get_or_init(
            DOMAIN_WEBAUTHN_FIXTURE,
            label.as_ref(),
            &spec_bytes,
            "registration",
            move |seed| build_registration(spec, *seed.bytes()),
        )
        .as_ref()
        .clone()
    }

    fn webauthn_assertion(&self, label: impl AsRef<str>, spec: WebAuthnSpec) -> AssertionFixture {
        let spec_bytes = spec.stable_bytes();
        self.get_or_init(
            DOMAIN_WEBAUTHN_FIXTURE,
            label.as_ref(),
            &spec_bytes,
            "assertion",
            move |seed| build_assertion(spec, *seed.bytes()),
        )
        .as_ref()
        .clone()
    }
}

fn build_registration(spec: WebAuthnSpec, seed: [u8; 32]) -> RegistrationFixture {
    let rp_id_hash = sha256_arr(spec.rp_id.as_bytes());
    let sign_count = deterministic_sign_count(&spec);
    let aaguid = deterministic_aaguid(&seed, &spec.authenticator_model);
    let client_data_json = build_client_data_json("webauthn.create", &spec.challenge, &spec.rp_id);

    let credential_public_key = cbor_public_key(&seed);
    let auth_data = build_authenticator_data(
        rp_id_hash,
        sign_count,
        Some((&aaguid, &spec.credential_id, credential_public_key.as_slice())),
    );

    let mut att_stmt = BTreeMap::new();
    att_stmt.insert(Value::Text("alg".to_string()), Value::Integer(-7));
    att_stmt.insert(
        Value::Text("sig".to_string()),
        Value::Bytes(mock_signature(
            &seed,
            &[auth_data.as_slice(), client_data_json.as_slice()].concat(),
            b"attestation",
        )),
    );

    let mut root = BTreeMap::new();
    root.insert(
        Value::Text("fmt".to_string()),
        Value::Text(match spec.attestation_mode {
            AttestationMode::Packed => "packed",
            AttestationMode::SelfAttestation => "self",
        }
        .to_string()),
    );
    root.insert(
        Value::Text("attStmt".to_string()),
        Value::Map(att_stmt.into_iter().collect()),
    );
    root.insert(
        Value::Text("authData".to_string()),
        Value::Bytes(auth_data.clone()),
    );

    RegistrationFixture {
        spec,
        client_data_json,
        authenticator_data: auth_data,
        attestation_object: to_vec(&Value::Map(root.into_iter().collect()))
            .expect("serialize attestation object"),
        rp_id_hash,
        sign_count,
        aaguid,
    }
}

fn build_assertion(spec: WebAuthnSpec, seed: [u8; 32]) -> AssertionFixture {
    let rp_id_hash = sha256_arr(spec.rp_id.as_bytes());
    let sign_count = deterministic_sign_count(&spec).saturating_add(1);
    let client_data_json = build_client_data_json("webauthn.get", &spec.challenge, &spec.rp_id);
    let auth_data = build_authenticator_data(rp_id_hash, sign_count, None);
    let signature = mock_signature(
        &seed,
        &[auth_data.as_slice(), client_data_json.as_slice()].concat(),
        b"assertion",
    );

    AssertionFixture {
        spec,
        client_data_json,
        authenticator_data: auth_data,
        signature,
        rp_id_hash,
        sign_count,
    }
}

fn build_client_data_json(kind: &str, challenge: &[u8], rp_id: &str) -> Vec<u8> {
    let val = json!({
        "type": kind,
        "challenge": base64url(challenge),
        "origin": format!("https://{rp_id}"),
        "crossOrigin": false
    });
    serde_json::to_vec(&val).expect("serialize clientDataJSON")
}

fn build_authenticator_data(
    rp_id_hash: [u8; 32],
    sign_count: u32,
    attested: Option<(&[u8; 16], &[u8], &[u8])>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&rp_id_hash);
    let mut flags: u8 = 0x01; // user present
    if attested.is_some() {
        flags |= 0x40; // attested credential data included
    }
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());

    if let Some((aaguid, credential_id, credential_public_key)) = attested {
        out.extend_from_slice(aaguid);
        out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        out.extend_from_slice(credential_id);
        out.extend_from_slice(credential_public_key);
    }

    out
}

fn cbor_public_key(seed: &[u8; 32]) -> Vec<u8> {
    // COSE EC2 public key map shape used by many WebAuthn implementations.
    let x = sha256_arr(&[seed.as_slice(), b"x"].concat());
    let y = sha256_arr(&[seed.as_slice(), b"y"].concat());

    let map = Value::Map(
        vec![
            (Value::Integer(1), Value::Integer(2)),  // kty: EC2
            (Value::Integer(3), Value::Integer(-7)), // alg: ES256
            (Value::Integer(-1), Value::Integer(1)), // crv: P-256
            (Value::Integer(-2), Value::Bytes(x.to_vec())),
            (Value::Integer(-3), Value::Bytes(y.to_vec())),
        ]
        .into_iter()
        .collect(),
    );
    to_vec(&map).expect("serialize credential public key")
}

fn deterministic_sign_count(spec: &WebAuthnSpec) -> u32 {
    let digest = sha256_arr(&spec.stable_bytes());
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

fn deterministic_aaguid(seed: &[u8; 32], model: &str) -> [u8; 16] {
    let digest = sha256_arr(&[seed.as_slice(), model.as_bytes()].concat());
    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&digest[..16]);
    aaguid
}

fn mock_signature(seed: &[u8; 32], body: &[u8], context: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(seed);
    h.update(context);
    h.update(body);
    h.finalize().to_vec()
}

fn base64url(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= input.len() {
        let chunk = &input[i..i + 3];
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
    }
    out
}

fn sha256_arr(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

fn write_field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(name.as_bytes());
    out.push(0x1f);
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use serde_cbor::Value;
    use uselesskey_core::Seed;

    use super::*;

    #[test]
    fn registration_is_deterministic() {
        let fx = Factory::deterministic(Seed::from_env_value("webauthn-det").unwrap());
        let spec = WebAuthnSpec::packed("example.com", b"challenge-a");

        let a = fx.webauthn_registration("alice", spec.clone());
        let b = fx.webauthn_registration("alice", spec);

        assert_eq!(a.attestation_object, b.attestation_object);
        assert_eq!(a.sign_count, b.sign_count);
    }

    #[test]
    fn attestation_object_is_cbor_map() {
        let fx = Factory::random();
        let reg = fx.webauthn_registration(
            "alice",
            WebAuthnSpec::packed("example.com", b"challenge-cbor"),
        );
        let v: Value = serde_cbor::from_slice(&reg.attestation_object).expect("parse cbor");
        let m = match v {
            Value::Map(entries) => entries,
            _ => panic!("attestation object must be cbor map"),
        };
        assert!(m.iter().any(|(k, _)| *k == Value::Text("fmt".to_string())));
        assert!(m.iter().any(|(k, _)| *k == Value::Text("authData".to_string())));
    }

    #[test]
    fn assertion_sign_count_monotonic_per_fixture() {
        let fx = Factory::deterministic(Seed::from_env_value("webauthn-sign-count").unwrap());
        let spec = WebAuthnSpec::packed("example.com", b"challenge-sign");
        let reg = fx.webauthn_registration("alice", spec.clone());
        let assertion = fx.webauthn_assertion("alice", spec);
        assert_eq!(assertion.sign_count, reg.sign_count.saturating_add(1));
    }

    #[test]
    fn client_data_contains_challenge() {
        let fx = Factory::random();
        let challenge = b"abc-123";
        let reg = fx.webauthn_registration("alice", WebAuthnSpec::packed("example.com", challenge));
        let json: serde_json::Value =
            serde_json::from_slice(&reg.client_data_json).expect("parse clientDataJSON");
        assert_eq!(json["challenge"], base64url(challenge));
        assert_eq!(json["origin"], "https://example.com");
    }
}
