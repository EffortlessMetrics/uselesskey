#![forbid(unsafe_code)]

//! Deterministic PKCS#11-style mock fixtures for hardware-adjacent tests.
//!
//! This crate intentionally provides a tiny shim for tests and does not attempt to
//! implement a full PKCS#11 provider.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;
use uselesskey_core_id::{ArtifactId, DerivationVersion, derive_seed};
use uselesskey_core_seed::Seed;

const DOMAIN_PKCS11_MOCK: &str = "pkcs11_mock";

/// Stable spec for deterministic PKCS#11 mock artifacts.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Pkcs11MockSpec {
    pub slot_id: u64,
    pub token_label: String,
    pub model: String,
    pub serial: String,
    pub key_label: String,
    pub cert_label: String,
}

impl Pkcs11MockSpec {
    pub fn new(token_label: impl Into<String>) -> Self {
        Self {
            slot_id: 1,
            token_label: token_label.into(),
            model: "uselesskey-hsm-mock-v1".to_owned(),
            serial: "UKMOCK0001".to_owned(),
            key_label: "signing-key".to_owned(),
            cert_label: "signing-cert".to_owned(),
        }
    }

    /// Stable bytes used for deterministic derivation.
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&1_u16.to_be_bytes());
        out.extend_from_slice(&self.slot_id.to_be_bytes());
        push_len_prefixed(&mut out, self.token_label.as_bytes());
        push_len_prefixed(&mut out, self.model.as_bytes());
        push_len_prefixed(&mut out, self.serial.as_bytes());
        push_len_prefixed(&mut out, self.key_label.as_bytes());
        push_len_prefixed(&mut out, self.cert_label.as_bytes());
        out
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct KeyHandle(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CertificateHandle(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlotMetadata {
    pub slot_id: u64,
    pub description: String,
    pub manufacturer_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenMetadata {
    pub label: String,
    pub model: String,
    pub serial: String,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MockError {
    #[error("unknown signing key handle")]
    UnknownKeyHandle,
    #[error("unknown certificate handle")]
    UnknownCertificateHandle,
}

/// Deterministic PKCS#11-like provider shim.
pub struct Pkcs11Mock {
    key_handle: KeyHandle,
    cert_handle: CertificateHandle,
    slot: SlotMetadata,
    token: TokenMetadata,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    certificate_der: Vec<u8>,
}

impl Pkcs11Mock {
    /// Build a deterministic mock from seed + label + spec.
    pub fn deterministic(master_seed: Seed, label: &str, spec: &Pkcs11MockSpec) -> Self {
        let id = ArtifactId::new(
            DOMAIN_PKCS11_MOCK,
            label,
            &spec.stable_bytes(),
            "default",
            DerivationVersion::V1,
        );
        let seed = derive_seed(&master_seed, &id);

        let mut signing_seed = [0u8; 32];
        seed.fill_bytes(&mut signing_seed);
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let verifying_key = signing_key.verifying_key();
        let key_handle = KeyHandle(spec.slot_id.saturating_mul(1000).saturating_add(1));
        let cert_handle = CertificateHandle(spec.slot_id.saturating_mul(1000).saturating_add(2));

        let certificate_der = mock_certificate_der(&verifying_key, spec);

        Self {
            key_handle,
            cert_handle,
            slot: SlotMetadata {
                slot_id: spec.slot_id,
                description: "uselesskey deterministic test slot".to_owned(),
                manufacturer_id: "uselesskey".to_owned(),
            },
            token: TokenMetadata {
                label: spec.token_label.clone(),
                model: spec.model.clone(),
                serial: spec.serial.clone(),
            },
            signing_key,
            verifying_key,
            certificate_der,
        }
    }

    pub fn key_handle(&self) -> KeyHandle {
        self.key_handle
    }

    pub fn certificate_handle(&self) -> CertificateHandle {
        self.cert_handle
    }

    pub fn slot_metadata(&self) -> &SlotMetadata {
        &self.slot
    }

    pub fn token_metadata(&self) -> &TokenMetadata {
        &self.token
    }

    pub fn certificate_der(&self, handle: CertificateHandle) -> Result<&[u8], MockError> {
        if handle != self.cert_handle {
            return Err(MockError::UnknownCertificateHandle);
        }
        Ok(&self.certificate_der)
    }

    pub fn sign(&self, handle: KeyHandle, message: &[u8]) -> Result<[u8; 64], MockError> {
        if handle != self.key_handle {
            return Err(MockError::UnknownKeyHandle);
        }
        let signature: Signature = self.signing_key.sign(message);
        Ok(signature.to_bytes())
    }

    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        let sig = Signature::from_bytes(signature);
        self.verifying_key.verify(message, &sig).is_ok()
    }
}

fn mock_certificate_der(verifying_key: &VerifyingKey, spec: &Pkcs11MockSpec) -> Vec<u8> {
    // Shape-only deterministic DER-ish bytes for tests. Not a real X.509 certificate.
    let mut body = Vec::new();
    body.extend_from_slice(b"UKMOCKCERT");
    body.extend_from_slice(verifying_key.as_bytes());
    body.extend_from_slice(&spec.stable_bytes());
    let digest = blake3::hash(&body);

    let mut out = vec![0x30, 0x82, 0x00, 0x30];
    out.extend_from_slice(digest.as_bytes());
    out.extend_from_slice(&body[..32.min(body.len())]);
    out
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}
