#![forbid(unsafe_code)]

//! Deterministic WebAuthn ceremony fixtures.
//!
//! The fixture model is intentionally minimal and test-oriented. It encodes realistic
//! shape and ceremony boundaries without trying to emulate a full authenticator stack.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uselesskey_core::Factory;

pub const DOMAIN_WEBAUTHN_FIXTURE: &str = "uselesskey:webauthn:fixture";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebauthnSpec {
    pub rp_id: String,
    pub challenge: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub authenticator_model: String,
    pub attestation_mode: AttestationMode,
}

impl WebauthnSpec {
    pub fn new(
        rp_id: impl Into<String>,
        challenge: impl Into<Vec<u8>>,
        credential_id: impl Into<Vec<u8>>,
        authenticator_model: impl Into<String>,
        attestation_mode: AttestationMode,
    ) -> Self {
        Self {
            rp_id: rp_id.into(),
            challenge: challenge.into(),
            credential_id: credential_id.into(),
            authenticator_model: authenticator_model.into(),
            attestation_mode,
        }
    }

    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_len_prefixed(&mut out, self.rp_id.as_bytes());
        write_len_prefixed(&mut out, &self.challenge);
        write_len_prefixed(&mut out, &self.credential_id);
        write_len_prefixed(&mut out, self.authenticator_model.as_bytes());
        out.extend_from_slice(self.attestation_mode.as_tag().as_bytes());
        out
    }
}

#[derive(Clone)]
pub struct WebauthnFixture {
    inner: Arc<Inner>,
}

#[derive(Clone)]
struct Inner {
    pub rp_id_hash: [u8; 32],
    pub challenge: Vec<u8>,
    pub sign_count: u32,
    pub aaguid: [u8; 16],
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

pub trait WebauthnFactoryExt {
    fn webauthn(&self, label: impl AsRef<str>, spec: WebauthnSpec) -> WebauthnFixture;
}

impl WebauthnFactoryExt for Factory {
    fn webauthn(&self, label: impl AsRef<str>, spec: WebauthnSpec) -> WebauthnFixture {
        let spec_bytes = spec.stable_bytes();
        let inner = self.get_or_init(
            DOMAIN_WEBAUTHN_FIXTURE,
            label.as_ref(),
            &spec_bytes,
            "good",
            |seed| {
                let mut seed_bytes = [0u8; 32];
                seed.fill_bytes(&mut seed_bytes);

                let rp_id_hash = *blake3::hash(spec.rp_id.as_bytes()).as_bytes();
                let sign_count = u32::from_be_bytes([
                    seed_bytes[0],
                    seed_bytes[1],
                    seed_bytes[2],
                    seed_bytes[3],
                ]);
                let mut aaguid = [0u8; 16];
                aaguid.copy_from_slice(&seed_bytes[4..20]);

                let client_data_json = build_client_data_json(&spec);
                let authenticator_data = build_authenticator_data(
                    rp_id_hash,
                    sign_count,
                    aaguid,
                    &spec.credential_id,
                );
                let attestation_object = build_attestation_object(
                    spec.attestation_mode,
                    &authenticator_data,
                    &spec.authenticator_model,
                );

                Inner {
                    rp_id_hash,
                    challenge: spec.challenge,
                    sign_count,
                    aaguid,
                    client_data_json,
                    authenticator_data,
                    attestation_object,
                }
            },
        );

        WebauthnFixture { inner }
    }
}

impl WebauthnFixture {
    pub fn registration(&self) -> RegistrationCeremony {
        RegistrationCeremony {
            attestation_object: self.inner.attestation_object.clone(),
            client_data_json: self.inner.client_data_json.clone(),
        }
    }

    pub fn assertion(&self) -> AssertionCeremony {
        AssertionCeremony {
            authenticator_data: self.inner.authenticator_data.clone(),
            client_data_json: self.inner.client_data_json.clone(),
            sign_count: self.inner.sign_count,
        }
    }

    pub fn rp_id_hash(&self) -> [u8; 32] {
        self.inner.rp_id_hash
    }

    pub fn challenge(&self) -> &[u8] {
        &self.inner.challenge
    }

    pub fn sign_count(&self) -> u32 {
        self.inner.sign_count
    }

    pub fn aaguid(&self) -> [u8; 16] {
        self.inner.aaguid
    }

    pub fn authenticator_data(&self) -> &[u8] {
        &self.inner.authenticator_data
    }

    pub fn attestation_object(&self) -> &[u8] {
        &self.inner.attestation_object
    }

    pub fn client_data_json(&self) -> &[u8] {
        &self.inner.client_data_json
    }
}

#[derive(Clone, Debug)]
pub struct RegistrationCeremony {
    pub attestation_object: Vec<u8>,
    pub client_data_json: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct AssertionCeremony {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub sign_count: u32,
}

pub fn verify_registration_ceremony(reg: &RegistrationCeremony) -> bool {
    parse_attestation_object(&reg.attestation_object)
        .map(|map| map.contains_key("authData") && map.contains_key("fmt"))
        .unwrap_or(false)
}

pub fn verify_assertion_ceremony(assertion: &AssertionCeremony) -> bool {
    if assertion.authenticator_data.len() < 37 {
        return false;
    }

    let count = u32::from_be_bytes([
        assertion.authenticator_data[33],
        assertion.authenticator_data[34],
        assertion.authenticator_data[35],
        assertion.authenticator_data[36],
    ]);

    count == assertion.sign_count
}

fn build_client_data_json(spec: &WebauthnSpec) -> Vec<u8> {
    let value = serde_json::json!({
        "type": "webauthn.create",
        "challenge": URL_SAFE_NO_PAD.encode(&spec.challenge),
        "origin": format!("https://{}", spec.rp_id),
    });
    serde_json::to_vec(&value).expect("json should serialize")
}

fn build_authenticator_data(
    rp_id_hash: [u8; 32],
    sign_count: u32,
    aaguid: [u8; 16],
    credential_id: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&rp_id_hash);
    out.push(0x41); // UP + AT flags
    out.extend_from_slice(&sign_count.to_be_bytes());
    out.extend_from_slice(&aaguid);
    out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    out.extend_from_slice(credential_id);
    out.extend_from_slice(&[0xa1, 0x01, 0x02]); // tiny COSE-key-shaped stub
    out
}

fn build_attestation_object(
    mode: AttestationMode,
    auth_data: &[u8],
    authenticator_model: &str,
) -> Vec<u8> {
    let mut map = BTreeMap::new();
    map.insert("fmt".to_string(), CborValue::Text(mode.as_tag().to_string()));
    map.insert("authData".to_string(), CborValue::Bytes(auth_data.to_vec()));

    let mut att_stmt = BTreeMap::new();
    att_stmt.insert(
        "alg".to_string(),
        CborValue::Integer(if matches!(mode, AttestationMode::Packed) {
            -7
        } else {
            -8
        }),
    );
    att_stmt.insert(
        "x5c".to_string(),
        CborValue::Bytes(blake3::hash(authenticator_model.as_bytes()).as_bytes()[..16].to_vec()),
    );
    map.insert("attStmt".to_string(), CborValue::Map(att_stmt));

    encode_cbor_map(&map)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CborValue {
    Text(String),
    Bytes(Vec<u8>),
    Integer(i64),
    Map(BTreeMap<String, CborValue>),
}

fn encode_cbor_map(map: &BTreeMap<String, CborValue>) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa0 | (map.len() as u8));
    for (k, v) in map {
        encode_text(k, &mut out);
        encode_value(v, &mut out);
    }
    out
}

fn encode_value(value: &CborValue, out: &mut Vec<u8>) {
    match value {
        CborValue::Text(s) => encode_text(s, out),
        CborValue::Bytes(b) => encode_bytes(b, out),
        CborValue::Integer(i) => encode_int(*i, out),
        CborValue::Map(m) => out.extend_from_slice(&encode_cbor_map(m)),
    }
}

fn encode_text(s: &str, out: &mut Vec<u8>) {
    encode_head(3, s.len(), out);
    out.extend_from_slice(s.as_bytes());
}

fn encode_bytes(b: &[u8], out: &mut Vec<u8>) {
    encode_head(2, b.len(), out);
    out.extend_from_slice(b);
}

fn encode_int(i: i64, out: &mut Vec<u8>) {
    if i >= 0 {
        encode_head(0, i as usize, out);
    } else {
        encode_head(1, (-1 - i) as usize, out);
    }
}

fn encode_head(major: u8, len: usize, out: &mut Vec<u8>) {
    match len {
        0..=23 => out.push((major << 5) | (len as u8)),
        24..=0xff => {
            out.push((major << 5) | 24);
            out.push(len as u8);
        }
        _ => {
            out.push((major << 5) | 25);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
    }
}

fn parse_attestation_object(bytes: &[u8]) -> Option<BTreeMap<String, CborValue>> {
    let (value, consumed) = decode_value(bytes)?;
    if consumed != bytes.len() {
        return None;
    }
    match value {
        CborValue::Map(map) => Some(map),
        _ => None,
    }
}

fn decode_value(input: &[u8]) -> Option<(CborValue, usize)> {
    let head = *input.first()?;
    let major = head >> 5;
    let (additional, head_len) = decode_additional(input)?;

    match major {
        2 => {
            let end = head_len + additional;
            Some((CborValue::Bytes(input.get(head_len..end)?.to_vec()), end))
        }
        3 => {
            let end = head_len + additional;
            let s = std::str::from_utf8(input.get(head_len..end)?).ok()?.to_string();
            Some((CborValue::Text(s), end))
        }
        4 => None,
        5 => {
            let mut cursor = head_len;
            let mut map = BTreeMap::new();
            for _ in 0..additional {
                let (k, used_k) = decode_value(input.get(cursor..)?)?;
                cursor += used_k;
                let key = match k {
                    CborValue::Text(s) => s,
                    _ => return None,
                };
                let (v, used_v) = decode_value(input.get(cursor..)?)?;
                cursor += used_v;
                map.insert(key, v);
            }
            Some((CborValue::Map(map), cursor))
        }
        0 => Some((CborValue::Integer(additional as i64), head_len)),
        1 => Some((CborValue::Integer(-(additional as i64) - 1), head_len)),
        _ => None,
    }
}

fn decode_additional(input: &[u8]) -> Option<(usize, usize)> {
    let head = *input.first()?;
    let additional = (head & 0x1f) as usize;
    match additional {
        0..=23 => Some((additional, 1)),
        24 => Some((*input.get(1)? as usize, 2)),
        25 => {
            let bytes = [*input.get(1)?, *input.get(2)?];
            Some((u16::from_be_bytes(bytes) as usize, 3))
        }
        _ => None,
    }
}

fn write_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core::Seed;

    fn base_spec() -> WebauthnSpec {
        WebauthnSpec::new(
            "example.com",
            b"challenge-123".to_vec(),
            b"cred-1".to_vec(),
            "uk-authn-model-a",
            AttestationMode::Packed,
        )
    }

    #[test]
    fn determinism_includes_spec_inputs() {
        let fx = Factory::deterministic(Seed::from_env_value("webauthn-det").unwrap());
        let s1 = base_spec();
        let mut s2 = base_spec();
        s2.challenge = b"different".to_vec();

        let a = fx.webauthn("svc", s1);
        let b = fx.webauthn("svc", s2);

        assert_ne!(a.sign_count(), b.sign_count());
        assert_ne!(a.challenge(), b.challenge());
    }

    #[test]
    fn cbor_parsing_and_registration_verification() {
        let fx = Factory::random();
        let fixture = fx.webauthn("svc", base_spec());
        let reg = fixture.registration();

        assert!(verify_registration_ceremony(&reg));
        let parsed = parse_attestation_object(&reg.attestation_object).expect("valid cbor");
        assert!(parsed.contains_key("attStmt"));
    }

    #[test]
    fn assertion_verification_checks_sign_count() {
        let fx = Factory::deterministic(Seed::from_env_value("webauthn-assert").unwrap());
        let fixture = fx.webauthn("svc", base_spec());
        let mut assertion = fixture.assertion();

        assert!(verify_assertion_ceremony(&assertion));
        assertion.sign_count = assertion.sign_count.wrapping_add(1);
        assert!(!verify_assertion_ceremony(&assertion));
    }
}
