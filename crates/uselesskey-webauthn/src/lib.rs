#![forbid(unsafe_code)]

//! Deterministic WebAuthn ceremony fixtures.
//!
//! This crate is for test harnesses that need WebAuthn-shaped blobs
//! (`attestationObject`, `clientDataJSON`, authenticator data, etc.) without
//! implementing a full authenticator or FIDO2 server.

use core::fmt;
use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uselesskey_core::{Factory, Seed};

pub const DOMAIN_WEBAUTHN_FIXTURE: &str = "uselesskey:webauthn:fixture:v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttestationMode {
    Packed,
    SelfAttestation,
}

impl AttestationMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Packed => "packed",
            Self::SelfAttestation => "self",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebauthnSpec {
    pub rp_id: String,
    pub challenge: Vec<u8>,
    pub credential_id_len: u16,
    pub authenticator_model: String,
    pub attestation_mode: AttestationMode,
    pub aaguid: [u8; 16],
    pub sign_count_start: u32,
}

impl Default for WebauthnSpec {
    fn default() -> Self {
        Self {
            rp_id: "example.com".to_string(),
            challenge: b"test-challenge".to_vec(),
            credential_id_len: 32,
            authenticator_model: "uk-softtoken-v1".to_string(),
            attestation_mode: AttestationMode::Packed,
            aaguid: [0u8; 16],
            sign_count_start: 1,
        }
    }
}

impl WebauthnSpec {
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_field(&mut out, self.rp_id.as_bytes());
        write_field(&mut out, &self.challenge);
        out.extend_from_slice(&self.credential_id_len.to_be_bytes());
        write_field(&mut out, self.authenticator_model.as_bytes());
        write_field(&mut out, self.attestation_mode.as_str().as_bytes());
        out.extend_from_slice(&self.aaguid);
        out.extend_from_slice(&self.sign_count_start.to_be_bytes());
        out
    }
}

pub trait WebauthnFactoryExt {
    fn webauthn(&self, label: impl AsRef<str>, spec: WebauthnSpec) -> WebauthnFixture;
}

impl WebauthnFactoryExt for Factory {
    fn webauthn(&self, label: impl AsRef<str>, spec: WebauthnSpec) -> WebauthnFixture {
        let label = label.as_ref();
        let spec_bytes = spec.stable_bytes();
        let inner = self.get_or_init(DOMAIN_WEBAUTHN_FIXTURE, label, &spec_bytes, "good", |seed| {
            Inner::from_seed(&spec, seed)
        });

        WebauthnFixture {
            label: label.to_string(),
            spec,
            inner,
        }
    }
}

#[derive(Clone)]
pub struct WebauthnFixture {
    label: String,
    spec: WebauthnSpec,
    inner: Arc<Inner>,
}

impl fmt::Debug for WebauthnFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebauthnFixture")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

impl WebauthnFixture {
    pub fn registration(&self) -> RegistrationFixture {
        self.inner.registration.clone()
    }

    pub fn assertion(&self, step: u32) -> AssertionFixture {
        let sign_count = self.spec.sign_count_start.saturating_add(step);
        let auth_data = build_assertion_auth_data(self.inner.rp_id_hash, sign_count);
        let client_data_json = build_client_data_json("webauthn.get", &self.spec.challenge);
        let signature = sign_assertion(&self.inner.signing_secret, &auth_data, &client_data_json);

        AssertionFixture {
            credential_id: self.inner.credential_id.clone(),
            authenticator_data: auth_data,
            client_data_json,
            signature,
            sign_count,
        }
    }

    pub fn rp_id_hash(&self) -> [u8; 32] {
        self.inner.rp_id_hash
    }

    pub fn aaguid(&self) -> [u8; 16] {
        self.spec.aaguid
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationFixture {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub client_data_json: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssertionFixture {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
    pub sign_count: u32,
}

#[derive(Debug, Error)]
pub enum WebauthnFixtureError {
    #[error("invalid cbor for attestation object")]
    InvalidAttestationCbor,
    #[error("unsupported attestation format")]
    UnsupportedAttestationFormat,
    #[error("signature mismatch")]
    SignatureMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParsedClientData {
    #[serde(rename = "type")]
    pub typ: String,
    pub challenge: String,
    pub origin: String,
}

impl AssertionFixture {
    pub fn parse_client_data(&self) -> ParsedClientData {
        serde_json::from_slice(&self.client_data_json).expect("fixture clientDataJSON must parse")
    }
}

impl WebauthnFixture {
    pub fn verify_assertion(&self, assertion: &AssertionFixture) -> Result<(), WebauthnFixtureError> {
        let expected = sign_assertion(
            &self.inner.signing_secret,
            &assertion.authenticator_data,
            &assertion.client_data_json,
        );

        if expected != assertion.signature {
            return Err(WebauthnFixtureError::SignatureMismatch);
        }

        Ok(())
    }

    pub fn parse_attestation_object(
        &self,
        registration: &RegistrationFixture,
    ) -> Result<BTreeMap<String, Value>, WebauthnFixtureError> {
        let value: Value =
            serde_cbor::from_slice(&registration.attestation_object).map_err(|_| {
                WebauthnFixtureError::InvalidAttestationCbor
            })?;

        match value {
            Value::Map(entries) => {
                let mut out = BTreeMap::new();
                for (k, v) in entries {
                    if let Value::Text(key) = k {
                        out.insert(key, v);
                    }
                }
                Ok(out)
            }
            _ => Err(WebauthnFixtureError::InvalidAttestationCbor),
        }
    }
}

struct Inner {
    signing_secret: [u8; 32],
    credential_id: Vec<u8>,
    rp_id_hash: [u8; 32],
    registration: RegistrationFixture,
}

impl Inner {
    fn from_seed(spec: &WebauthnSpec, seed: Seed) -> Self {
        let mut rng = ChaCha20Rng::from_seed(*seed.bytes());

        let mut signing_secret = [0u8; 32];
        rng.fill_bytes(&mut signing_secret);

        let mut credential_id = vec![0u8; spec.credential_id_len as usize];
        rng.fill_bytes(&mut credential_id);

        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        rng.fill_bytes(&mut x);
        rng.fill_bytes(&mut y);

        let rp_id_hash: [u8; 32] = Sha256::digest(spec.rp_id.as_bytes()).into();
        let client_data_json = build_client_data_json("webauthn.create", &spec.challenge);
        let auth_data = build_registration_auth_data(
            rp_id_hash,
            spec.sign_count_start,
            spec.aaguid,
            &credential_id,
            cose_key_bytes(&x, &y),
        );

        let attestation_sig = sign_assertion(&signing_secret, &auth_data, &client_data_json);
        let attestation_object = build_attestation_object(spec.attestation_mode, &auth_data, &attestation_sig);

        let registration = RegistrationFixture {
            credential_id: credential_id.clone(),
            authenticator_data: auth_data,
            attestation_object,
            client_data_json,
        };

        Self {
            signing_secret,
            credential_id,
            rp_id_hash,
            registration,
        }
    }
}

fn build_client_data_json(typ: &str, challenge: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "type": typ,
        "challenge": URL_SAFE_NO_PAD.encode(challenge),
        "origin": "https://fixture.invalid"
    }))
    .expect("static map serializes")
}

fn build_registration_auth_data(
    rp_id_hash: [u8; 32],
    sign_count: u32,
    aaguid: [u8; 16],
    credential_id: &[u8],
    cose_key: Vec<u8>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + credential_id.len() + cose_key.len());
    out.extend_from_slice(&rp_id_hash);
    out.push(0x41); // user present + attested credential data
    out.extend_from_slice(&sign_count.to_be_bytes());
    out.extend_from_slice(&aaguid);
    out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    out.extend_from_slice(credential_id);
    out.extend_from_slice(&cose_key);
    out
}

fn build_assertion_auth_data(rp_id_hash: [u8; 32], sign_count: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&rp_id_hash);
    out.push(0x01); // user present
    out.extend_from_slice(&sign_count.to_be_bytes());
    out
}

fn cose_key_bytes(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut map = BTreeMap::new();
    map.insert(Value::Integer(1), Value::Integer(2));
    map.insert(Value::Integer(3), Value::Integer(-7));
    map.insert(Value::Integer(-1), Value::Integer(1));
    map.insert(Value::Integer(-2), Value::Bytes(x.to_vec()));
    map.insert(Value::Integer(-3), Value::Bytes(y.to_vec()));
    serde_cbor::to_vec(&Value::Map(map.into_iter().collect())).expect("cose key serializes")
}

fn build_attestation_object(mode: AttestationMode, auth_data: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut att_stmt = BTreeMap::new();
    att_stmt.insert(Value::Text("alg".to_string()), Value::Integer(-7));
    att_stmt.insert(Value::Text("sig".to_string()), Value::Bytes(sig.to_vec()));
    if mode == AttestationMode::Packed {
        att_stmt.insert(Value::Text("x5c".to_string()), Value::Array(vec![]));
    }

    let value = Value::Map(BTreeMap::from([
        (Value::Text("fmt".to_string()), Value::Text("packed".to_string())),
        (
            Value::Text("authData".to_string()),
            Value::Bytes(auth_data.to_vec()),
        ),
        (
            Value::Text("attStmt".to_string()),
            Value::Map(att_stmt.into_iter().collect()),
        ),
    ]));

    serde_cbor::to_vec(&value).expect("attestation object serializes")
}

fn sign_assertion(secret: &[u8; 32], authenticator_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
    let client_hash = Sha256::digest(client_data_json);
    let mut hasher = blake3::Hasher::new_keyed(secret);
    hasher.update(authenticator_data);
    hasher.update(&client_hash);
    hasher.finalize().as_bytes().to_vec()
}

fn write_field(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use uselesskey_core::Seed;

    use super::*;

    #[test]
    fn deterministic_registration_fixture() {
        let fx = Factory::deterministic(Seed::from_env_value("webauthn-registration").unwrap());
        let fixture = fx.webauthn("passkey", WebauthnSpec::default());

        let reg1 = fixture.registration();
        let reg2 = fixture.registration();
        assert_eq!(reg1, reg2);
    }

    #[test]
    fn sign_count_changes_authenticator_data() {
        let fx = Factory::deterministic(Seed::from_env_value("webauthn-counter").unwrap());
        let fixture = fx.webauthn("passkey", WebauthnSpec::default());

        let a1 = fixture.assertion(0);
        let a2 = fixture.assertion(1);

        assert_ne!(a1.authenticator_data, a2.authenticator_data);
        assert_eq!(a2.sign_count, a1.sign_count + 1);
    }
}
