#![forbid(unsafe_code)]

//! Deterministic PKCS#11-style fixtures for hardware-adjacent tests.
//!
//! This crate intentionally models only a tiny subset of PKCS#11 behavior:
//! key handles, sign operations, certificate lookup, and slot/token metadata.
//! It is suitable for tests that want HSM-like integration points without
//! running a daemon or shipping secret-like fixture files.

use core::fmt;
use std::collections::BTreeMap;
use std::sync::Arc;

use blake3::Hasher;
use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};
use thiserror::Error;
use uselesskey_core::{Factory, Seed};

/// Cache domain for PKCS#11 mock fixtures.
pub const DOMAIN_PKCS11_MOCK: &str = "uselesskey:pkcs11:mock:v1";

/// Minimal provider-facing shim trait for PKCS#11-like operations.
pub trait Pkcs11Provider {
    fn slot_metadata(&self) -> &SlotMetadata;
    fn key_handles(&self) -> &[KeyHandle];
    fn certificate(&self, handle: KeyHandle) -> Result<&CertificateFixture, Pkcs11MockError>;
    fn sign(&self, handle: KeyHandle, message: &[u8]) -> Result<Vec<u8>, Pkcs11MockError>;
    fn verify(
        &self,
        handle: KeyHandle,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Pkcs11MockError>;
}

/// Deterministic spec for a PKCS#11 mock fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pkcs11MockSpec {
    pub slot_description: String,
    pub manufacturer: String,
    pub token_label: String,
    pub token_model: String,
    pub token_serial: String,
    pub key_count: u8,
}

impl Default for Pkcs11MockSpec {
    fn default() -> Self {
        Self {
            slot_description: "uselesskey test slot".to_string(),
            manufacturer: "uselesskey".to_string(),
            token_label: "UK-MOCK".to_string(),
            token_model: "DeterministicMock".to_string(),
            token_serial: "00000001".to_string(),
            key_count: 2,
        }
    }
}

impl Pkcs11MockSpec {
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_field(&mut out, self.slot_description.as_bytes());
        write_field(&mut out, self.manufacturer.as_bytes());
        write_field(&mut out, self.token_label.as_bytes());
        write_field(&mut out, self.token_model.as_bytes());
        write_field(&mut out, self.token_serial.as_bytes());
        out.push(self.key_count);
        out
    }
}

/// Metadata for slot/token identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlotMetadata {
    pub slot_id: u64,
    pub slot_description: String,
    pub manufacturer: String,
    pub token_label: String,
    pub token_model: String,
    pub token_serial: String,
}

/// Opaque key handle identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct KeyHandle(pub u64);

/// Certificate fixture bound to a key handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateFixture {
    pub subject_cn: String,
    pub der: Vec<u8>,
}

/// Errors for PKCS#11 mock operations.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum Pkcs11MockError {
    #[error("unknown key handle: {0:?}")]
    UnknownHandle(KeyHandle),
}

/// Extension trait for creating PKCS#11 mock fixtures from [`Factory`].
pub trait Pkcs11MockFactoryExt {
    fn pkcs11_mock(&self, label: impl AsRef<str>, spec: Pkcs11MockSpec) -> Pkcs11Mock;
}

impl Pkcs11MockFactoryExt for Factory {
    fn pkcs11_mock(&self, label: impl AsRef<str>, spec: Pkcs11MockSpec) -> Pkcs11Mock {
        let label = label.as_ref();
        let spec_bytes = spec.stable_bytes();
        let inner = self.get_or_init(DOMAIN_PKCS11_MOCK, label, &spec_bytes, "good", |seed| {
            Inner::from_seed(&spec, seed)
        });

        Pkcs11Mock {
            label: label.to_string(),
            spec,
            inner,
        }
    }
}

/// Deterministic PKCS#11-style mock provider.
#[derive(Clone)]
pub struct Pkcs11Mock {
    label: String,
    spec: Pkcs11MockSpec,
    inner: Arc<Inner>,
}

impl fmt::Debug for Pkcs11Mock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11Mock")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

impl Pkcs11Mock {
    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn spec(&self) -> &Pkcs11MockSpec {
        &self.spec
    }
}

impl Pkcs11Provider for Pkcs11Mock {
    fn slot_metadata(&self) -> &SlotMetadata {
        &self.inner.slot
    }

    fn key_handles(&self) -> &[KeyHandle] {
        &self.inner.handles
    }

    fn certificate(&self, handle: KeyHandle) -> Result<&CertificateFixture, Pkcs11MockError> {
        self.inner
            .entries
            .get(&handle)
            .map(|entry| &entry.certificate)
            .ok_or(Pkcs11MockError::UnknownHandle(handle))
    }

    fn sign(&self, handle: KeyHandle, message: &[u8]) -> Result<Vec<u8>, Pkcs11MockError> {
        let entry = self
            .inner
            .entries
            .get(&handle)
            .ok_or(Pkcs11MockError::UnknownHandle(handle))?;

        Ok(sign_with_secret(&entry.signing_secret, message))
    }

    fn verify(
        &self,
        handle: KeyHandle,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Pkcs11MockError> {
        let expected = self.sign(handle, message)?;
        Ok(expected == signature)
    }
}

struct KeyEntry {
    signing_secret: [u8; 32],
    certificate: CertificateFixture,
}

struct Inner {
    slot: SlotMetadata,
    handles: Vec<KeyHandle>,
    entries: BTreeMap<KeyHandle, KeyEntry>,
}

impl Inner {
    fn from_seed(spec: &Pkcs11MockSpec, seed: Seed) -> Self {
        let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
        let slot_id = rng.next_u64();

        let slot = SlotMetadata {
            slot_id,
            slot_description: spec.slot_description.clone(),
            manufacturer: spec.manufacturer.clone(),
            token_label: spec.token_label.clone(),
            token_model: spec.token_model.clone(),
            token_serial: spec.token_serial.clone(),
        };

        let mut handles = Vec::with_capacity(spec.key_count as usize);
        let mut entries = BTreeMap::new();

        for index in 0..spec.key_count {
            let mut handle_seed = [0u8; 8];
            rng.fill_bytes(&mut handle_seed);
            let handle = KeyHandle(u64::from_be_bytes(handle_seed));

            let mut signing_secret = [0u8; 32];
            rng.fill_bytes(&mut signing_secret);

            let mut cert_bytes = vec![0x30, 0x82, 0x00, 0x20, index];
            let cert_tail = blake3::hash(&signing_secret);
            cert_bytes.extend_from_slice(&cert_tail.as_bytes()[..24]);

            let subject_cn = format!("{}-key-{}", spec.token_label, index + 1);
            let certificate = CertificateFixture {
                subject_cn,
                der: cert_bytes,
            };

            handles.push(handle);
            entries.insert(
                handle,
                KeyEntry {
                    signing_secret,
                    certificate,
                },
            );
        }

        Self {
            slot,
            handles,
            entries,
        }
    }
}

fn sign_with_secret(secret: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new_keyed(secret);
    hasher.update(message);
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
    fn stable_mock_for_same_seed_label_spec() {
        let fx = Factory::deterministic(Seed::from_env_value("pkcs11-fixture").unwrap());
        let spec = Pkcs11MockSpec::default();

        let a = fx.pkcs11_mock("hsm", spec.clone());
        let b = fx.pkcs11_mock("hsm", spec);

        assert_eq!(a.slot_metadata(), b.slot_metadata());
        assert_eq!(a.key_handles(), b.key_handles());
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let fx = Factory::deterministic(Seed::from_env_value("pkcs11-sign").unwrap());
        let mock = fx.pkcs11_mock("hsm", Pkcs11MockSpec::default());
        let handle = mock.key_handles()[0];

        let msg = b"message";
        let sig = mock.sign(handle, msg).unwrap();
        assert!(mock.verify(handle, msg, &sig).unwrap());
        assert!(!mock.verify(handle, b"other", &sig).unwrap());
    }
}
