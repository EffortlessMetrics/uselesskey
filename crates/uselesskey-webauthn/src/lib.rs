#![forbid(unsafe_code)]

//! Deterministic WebAuthn fixtures for registration and assertion ceremony tests.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uselesskey_core_id::{ArtifactId, DerivationVersion, derive_seed};
use uselesskey_core_seed::Seed;

const DOMAIN_WEBAUTHN: &str = "webauthn_fixture";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum AttestationMode {
    Packed,
    SelfAttestation,
}

impl AttestationMode {
    fn stable_tag(self) -> u8 {
        match self {
            Self::Packed => 1,
            Self::SelfAttestation => 2,
        }
    }

    fn fmt(self) -> &'static str {
        match self {
            Self::Packed | Self::SelfAttestation => "packed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct WebAuthnSpec {
    pub rp_id: String,
    pub challenge: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub authenticator_model: String,
    pub attestation_mode: AttestationMode,
    pub sign_count_start: u32,
    pub aaguid: [u8; 16],
}

impl WebAuthnSpec {
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1_u16.to_be_bytes());
        push_len_prefixed(&mut out, self.rp_id.as_bytes());
        push_len_prefixed(&mut out, &self.challenge);
        push_len_prefixed(&mut out, &self.credential_id);
        push_len_prefixed(&mut out, self.authenticator_model.as_bytes());
        out.push(self.attestation_mode.stable_tag());
        out.extend_from_slice(&self.sign_count_start.to_be_bytes());
        out.extend_from_slice(&self.aaguid);
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationFixture {
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub challenge: Vec<u8>,
    pub rp_id_hash: [u8; 32],
    pub sign_count: u32,
    pub aaguid: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssertionFixture {
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub challenge: Vec<u8>,
    pub rp_id_hash: [u8; 32],
    pub sign_count: u32,
    pub signature: [u8; 64],
    pub credential_id: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebAuthnFixture {
    pub registration: RegistrationFixture,
    pub assertion: AssertionFixture,
}

#[derive(Debug, Error)]
pub enum WebAuthnError {
    #[error("CBOR serialization failed")]
    CborSerialization(#[from] serde_cbor::Error),
}

pub fn deterministic_fixture(
    master_seed: Seed,
    label: &str,
    spec: &WebAuthnSpec,
) -> Result<WebAuthnFixture, WebAuthnError> {
    let id = ArtifactId::new(
        DOMAIN_WEBAUTHN,
        label,
        &spec.stable_bytes(),
        "default",
        DerivationVersion::V1,
    );
    let seed = derive_seed(&master_seed, &id);

    let mut signing_seed = [0u8; 32];
    seed.fill_bytes(&mut signing_seed);
    let signing_key = SigningKey::from_bytes(&signing_seed);

    let rp_id_hash = sha256(spec.rp_id.as_bytes());

    let registration_client_data_json = build_client_data_json("webauthn.create", &spec.challenge, &spec.rp_id);
    let reg_auth_data = build_registration_auth_data(
        rp_id_hash,
        spec.sign_count_start,
        spec.aaguid,
        &spec.credential_id,
        signing_key.verifying_key().as_bytes(),
    )?;

    let reg_sig = sign_over_auth_data(&signing_key, &reg_auth_data, &registration_client_data_json);
    let attestation_object = build_attestation_object(spec.attestation_mode, &reg_auth_data, &reg_sig)?;

    let assertion_count = spec.sign_count_start.saturating_add(1);
    let assertion_client_data_json =
        build_client_data_json("webauthn.get", &spec.challenge, &spec.rp_id);
    let assertion_auth_data = build_assertion_auth_data(rp_id_hash, assertion_count);
    let assertion_signature = sign_over_auth_data(
        &signing_key,
        &assertion_auth_data,
        &assertion_client_data_json,
    );

    Ok(WebAuthnFixture {
        registration: RegistrationFixture {
            authenticator_data: reg_auth_data,
            attestation_object,
            client_data_json: registration_client_data_json,
            challenge: spec.challenge.clone(),
            rp_id_hash,
            sign_count: spec.sign_count_start,
            aaguid: spec.aaguid,
        },
        assertion: AssertionFixture {
            authenticator_data: assertion_auth_data,
            client_data_json: assertion_client_data_json,
            challenge: spec.challenge.clone(),
            rp_id_hash,
            sign_count: assertion_count,
            signature: assertion_signature,
            credential_id: spec.credential_id.clone(),
        },
    })
}

fn build_client_data_json(kind: &str, challenge: &[u8], rp_id: &str) -> Vec<u8> {
    #[derive(Serialize)]
    struct ClientData<'a> {
        r#type: &'a str,
        challenge: String,
        origin: String,
        #[serde(rename = "crossOrigin")]
        cross_origin: bool,
    }

    serde_json::to_vec(&ClientData {
        r#type: kind,
        challenge: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
        origin: format!("https://{rp_id}"),
        cross_origin: false,
    })
    .expect("serializing clientDataJSON should not fail")
}

fn build_registration_auth_data(
    rp_id_hash: [u8; 32],
    sign_count: u32,
    aaguid: [u8; 16],
    credential_id: &[u8],
    public_key: &[u8; 32],
) -> Result<Vec<u8>, WebAuthnError> {
    // Flags: UP + AT
    let flags = 0x41u8;
    let mut out = Vec::new();
    out.extend_from_slice(&rp_id_hash);
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    out.extend_from_slice(&aaguid);

    let cred_len = u16::try_from(credential_id.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&cred_len.to_be_bytes());
    out.extend_from_slice(credential_id);

    let cose_key = serde_cbor::to_vec(&cose_ed25519_public_key(public_key))?;
    out.extend_from_slice(&cose_key);

    Ok(out)
}

fn build_assertion_auth_data(rp_id_hash: [u8; 32], sign_count: u32) -> Vec<u8> {
    // Flags: UP
    let flags = 0x01u8;
    let mut out = Vec::new();
    out.extend_from_slice(&rp_id_hash);
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    out
}

fn build_attestation_object(
    mode: AttestationMode,
    auth_data: &[u8],
    signature: &[u8; 64],
) -> Result<Vec<u8>, WebAuthnError> {
    let mut att_stmt = std::collections::BTreeMap::new();
    att_stmt.insert(CborValue::Text("alg".into()), CborValue::Integer((-8).into()));
    att_stmt.insert(
        CborValue::Text("sig".into()),
        CborValue::Bytes(signature.to_vec()),
    );

    if mode == AttestationMode::Packed {
        att_stmt.insert(
            CborValue::Text("x5c".into()),
            CborValue::Array(vec![CborValue::Bytes(mock_attestation_cert(auth_data))]),
        );
    }

    let mut map = std::collections::BTreeMap::new();
    map.insert(
        CborValue::Text("fmt".into()),
        CborValue::Text(mode.fmt().to_owned()),
    );
    map.insert(
        CborValue::Text("authData".into()),
        CborValue::Bytes(auth_data.to_vec()),
    );
    map.insert(CborValue::Text("attStmt".into()), CborValue::Map(att_stmt));

    Ok(serde_cbor::to_vec(&CborValue::Map(map))?)
}

fn cose_ed25519_public_key(public_key: &[u8; 32]) -> CborValue {
    let mut map = std::collections::BTreeMap::new();
    map.insert(CborValue::Integer(1.into()), CborValue::Integer(1.into()));
    map.insert(CborValue::Integer(3.into()), CborValue::Integer((-8).into()));
    map.insert(CborValue::Integer((-1).into()), CborValue::Integer(6.into()));
    map.insert(
        CborValue::Integer((-2).into()),
        CborValue::Bytes(public_key.to_vec()),
    );
    CborValue::Map(map)
}

fn sign_over_auth_data(signing_key: &SigningKey, auth_data: &[u8], client_data_json: &[u8]) -> [u8; 64] {
    let mut to_sign = Vec::with_capacity(auth_data.len() + 32);
    to_sign.extend_from_slice(auth_data);
    to_sign.extend_from_slice(&sha256(client_data_json));
    let sig: Signature = signing_key.sign(&to_sign);
    sig.to_bytes()
}

fn mock_attestation_cert(auth_data: &[u8]) -> Vec<u8> {
    let digest = blake3::hash(auth_data);
    let mut cert = vec![0x30, 0x82, 0x00, 0x30];
    cert.extend_from_slice(digest.as_bytes());
    cert
}

fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}
