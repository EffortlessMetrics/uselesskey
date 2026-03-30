#![forbid(unsafe_code)]

//! Deterministic PKCS#11-like mock fixtures.
//!
//! This crate provides a tiny test fixture layer for hardware-adjacent tests.
//! It does **not** emulate a full PKCS#11 daemon.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use uselesskey_core::Factory;

/// Stable cache domain for PKCS#11 mock artifacts.
pub const DOMAIN_PKCS11_MOCK: &str = "uselesskey:pkcs11:mock:v1";

/// Metadata describing a mock slot and token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotTokenInfo {
    pub slot_id: u64,
    pub token_label: String,
    pub manufacturer_id: String,
    pub model: String,
    pub serial_number: String,
}

/// Identifier to reference a key in the mock provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyHandle(pub u64);

#[derive(Clone)]
pub struct MockPkcs11Provider {
    inner: Arc<Inner>,
}

impl fmt::Debug for MockPkcs11Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockPkcs11Provider")
            .field("slot", &self.inner.slot)
            .field("key_count", &self.inner.keys.len())
            .finish()
    }
}

struct Inner {
    slot: SlotTokenInfo,
    certificates: HashMap<KeyHandle, Vec<u8>>,
    keys: HashMap<KeyHandle, KeyRecord>,
    next_sign_count: Mutex<u64>,
}

struct KeyRecord {
    label: String,
    algorithm: String,
    secret: [u8; 32],
}

/// Deterministic builder spec for PKCS#11-like fixtures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pkcs11MockSpec {
    pub token_label: String,
    pub manufacturer_id: String,
    pub model: String,
    pub key_labels: Vec<String>,
}

impl Pkcs11MockSpec {
    pub fn basic(token_label: impl Into<String>) -> Self {
        Self {
            token_label: token_label.into(),
            manufacturer_id: "uselesskey".to_string(),
            model: "UK-PKCS11-MOCK".to_string(),
            key_labels: vec!["signing-key".to_string()],
        }
    }

    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_field(&mut out, "token_label", self.token_label.as_bytes());
        write_field(&mut out, "manufacturer_id", self.manufacturer_id.as_bytes());
        write_field(&mut out, "model", self.model.as_bytes());
        for label in &self.key_labels {
            write_field(&mut out, "key_label", label.as_bytes());
        }
        out
    }
}

/// Extension trait to build PKCS#11-like mock providers from a core [`Factory`].
pub trait Pkcs11MockFactoryExt {
    fn pkcs11_mock(&self, label: impl AsRef<str>, spec: Pkcs11MockSpec) -> MockPkcs11Provider;
}

impl Pkcs11MockFactoryExt for Factory {
    fn pkcs11_mock(&self, label: impl AsRef<str>, spec: Pkcs11MockSpec) -> MockPkcs11Provider {
        let spec_bytes = spec.stable_bytes();
        self.get_or_init(
            DOMAIN_PKCS11_MOCK,
            label.as_ref(),
            &spec_bytes,
            "good",
            move |seed| build_provider(spec, *seed.bytes()),
        )
        .as_ref()
        .clone()
    }
}

impl MockPkcs11Provider {
    pub fn slot_info(&self) -> SlotTokenInfo {
        self.inner.slot.clone()
    }

    pub fn key_handles(&self) -> Vec<KeyHandle> {
        let mut handles: Vec<KeyHandle> = self.inner.keys.keys().copied().collect();
        handles.sort_by_key(|h| h.0);
        handles
    }

    pub fn sign(&self, handle: KeyHandle, message: &[u8]) -> Option<Vec<u8>> {
        let key = self.inner.keys.get(&handle)?;
        let mut hasher = Sha256::new();
        hasher.update(key.secret);
        hasher.update(key.algorithm.as_bytes());
        hasher.update(message);
        Some(hasher.finalize().to_vec())
    }

    pub fn verify(&self, handle: KeyHandle, message: &[u8], signature: &[u8]) -> bool {
        self.sign(handle, message)
            .is_some_and(|expected| expected == signature)
    }

    pub fn certificate_der(&self, handle: KeyHandle) -> Option<&[u8]> {
        self.inner.certificates.get(&handle).map(Vec::as_slice)
    }

    pub fn key_label(&self, handle: KeyHandle) -> Option<&str> {
        self.inner.keys.get(&handle).map(|key| key.label.as_str())
    }

    pub fn next_sign_count(&self) -> u64 {
        let mut guard = self.inner.next_sign_count.lock().expect("sign_count mutex");
        *guard += 1;
        *guard
    }
}

fn build_provider(spec: Pkcs11MockSpec, seed: [u8; 32]) -> MockPkcs11Provider {
    let slot_id = u64::from_le_bytes(seed[0..8].try_into().expect("seed slice for slot id"));
    let serial_hex = hex8(&seed[8..16]);
    let mut keys = HashMap::new();
    let mut certs = HashMap::new();

    for (idx, key_label) in spec.key_labels.iter().enumerate() {
        let mut key_hasher = Sha256::new();
        key_hasher.update(seed);
        key_hasher.update((idx as u32).to_le_bytes());
        key_hasher.update(key_label.as_bytes());
        let key_seed = key_hasher.finalize();

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&key_seed[..32]);

        let handle = KeyHandle((idx as u64) + 1);
        let cert = mock_certificate_der(
            &spec.token_label,
            key_label,
            &spec.manufacturer_id,
            &spec.model,
            &secret,
        );
        certs.insert(handle, cert);
        keys.insert(
            handle,
            KeyRecord {
                label: key_label.clone(),
                algorithm: "MOCK-SHA256".to_string(),
                secret,
            },
        );
    }

    MockPkcs11Provider {
        inner: Arc::new(Inner {
            slot: SlotTokenInfo {
                slot_id,
                token_label: spec.token_label,
                manufacturer_id: spec.manufacturer_id,
                model: spec.model,
                serial_number: serial_hex,
            },
            certificates: certs,
            keys,
            next_sign_count: Mutex::new(0),
        }),
    }
}

fn mock_certificate_der(
    token_label: &str,
    key_label: &str,
    manufacturer_id: &str,
    model: &str,
    secret: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&[0x30, 0x82]); // looks DER-like for parser tests
    out.extend_from_slice(&[0x00, 0x00]);
    write_field(&mut out, "token", token_label.as_bytes());
    write_field(&mut out, "key", key_label.as_bytes());
    write_field(&mut out, "mfr", manufacturer_id.as_bytes());
    write_field(&mut out, "model", model.as_bytes());
    write_field(&mut out, "fingerprint", &Sha256::digest(secret));
    let body_len = (out.len() - 4) as u16;
    out[2..4].copy_from_slice(&body_len.to_be_bytes());
    out
}

fn write_field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(name.as_bytes());
    out.push(b'=');
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    out.push(0);
}

fn hex8(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<String>()
}

#[cfg(test)]
mod tests {
    use uselesskey_core::Seed;

    use super::*;

    #[test]
    fn deterministic_provider_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("pkcs11-seed").unwrap());
        let spec = Pkcs11MockSpec::basic("HSM-A");

        let a = fx.pkcs11_mock("issuer", spec.clone());
        let b = fx.pkcs11_mock("issuer", spec);

        assert_eq!(a.slot_info(), b.slot_info());
        assert_eq!(a.key_handles(), b.key_handles());
    }

    #[test]
    fn sign_verify_round_trip() {
        let fx = Factory::random();
        let provider = fx.pkcs11_mock("rt", Pkcs11MockSpec::basic("HSM-RT"));
        let handle = provider.key_handles()[0];
        let msg = b"hello from fixture";

        let sig = provider.sign(handle, msg).expect("signature");
        assert!(provider.verify(handle, msg, &sig));
        assert!(!provider.verify(handle, b"other", &sig));
    }

    #[test]
    fn cert_lookup_returns_der_like_bytes() {
        let fx = Factory::random();
        let provider = fx.pkcs11_mock("der", Pkcs11MockSpec::basic("HSM-DER"));
        let handle = provider.key_handles()[0];
        let der = provider.certificate_der(handle).expect("certificate");
        assert_eq!(&der[0..2], &[0x30, 0x82]);
    }
}
