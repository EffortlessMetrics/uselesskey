#![forbid(unsafe_code)]

//! Deterministic PKCS#11-like fixtures for hardware-adjacent tests.
//!
//! This crate provides a tiny in-process shim that models common test interactions:
//! key handles, signing, certificate lookup, and slot/token metadata.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use uselesskey_core::Factory;

pub const DOMAIN_PKCS11_MOCK: &str = "uselesskey:pkcs11:mock";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pkcs11Spec {
    slot_id: u64,
    token_label: String,
    manufacturer: String,
    model: String,
    serial_number: String,
    certificate_label: String,
}

impl Pkcs11Spec {
    pub fn new(slot_id: u64, token_label: impl Into<String>) -> Self {
        Self {
            slot_id,
            token_label: token_label.into(),
            manufacturer: "uselesskey".to_string(),
            model: "uk-pkcs11-mock".to_string(),
            serial_number: "UK0001".to_string(),
            certificate_label: "leaf".to_string(),
        }
    }

    pub fn with_model(mut self, manufacturer: impl Into<String>, model: impl Into<String>) -> Self {
        self.manufacturer = manufacturer.into();
        self.model = model.into();
        self
    }

    pub fn with_serial_number(mut self, serial_number: impl Into<String>) -> Self {
        self.serial_number = serial_number.into();
        self
    }

    pub fn with_certificate_label(mut self, certificate_label: impl Into<String>) -> Self {
        self.certificate_label = certificate_label.into();
        self
    }

    pub fn stable_bytes(&self) -> Vec<u8> {
        format!(
            "slot={};token={};manufacturer={};model={};serial={};cert={}",
            self.slot_id,
            self.token_label,
            self.manufacturer,
            self.model,
            self.serial_number,
            self.certificate_label
        )
        .into_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct KeyHandle(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlotMetadata {
    pub slot_id: u64,
    pub description: String,
    pub manufacturer_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenMetadata {
    pub label: String,
    pub manufacturer_id: String,
    pub model: String,
    pub serial_number: String,
}

#[derive(Clone)]
pub struct Pkcs11MockProvider {
    inner: Arc<Inner>,
}

struct Inner {
    keys: BTreeMap<KeyHandle, MockKey>,
    certs: BTreeMap<String, Vec<u8>>,
    slot: SlotMetadata,
    token: TokenMetadata,
}

#[derive(Clone)]
struct MockKey {
    key_id: String,
    signing_secret: [u8; 32],
}

impl fmt::Debug for Pkcs11MockProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key_handles: Vec<KeyHandle> = self.inner.keys.keys().copied().collect();
        f.debug_struct("Pkcs11MockProvider")
            .field("slot", &self.inner.slot)
            .field("token", &self.inner.token)
            .field("key_handles", &key_handles)
            .field("certificate_labels", &self.inner.certs.keys().collect::<Vec<_>>())
            .finish()
    }
}

pub trait Pkcs11MockFactoryExt {
    fn pkcs11_mock(&self, label: impl AsRef<str>, spec: Pkcs11Spec) -> Pkcs11MockProvider;
}

impl Pkcs11MockFactoryExt for Factory {
    fn pkcs11_mock(&self, label: impl AsRef<str>, spec: Pkcs11Spec) -> Pkcs11MockProvider {
        let label = label.as_ref();
        let spec_bytes = spec.stable_bytes();
        let inner = self.get_or_init(DOMAIN_PKCS11_MOCK, label, &spec_bytes, "good", |seed| {
            let mut buf = [0u8; 32];
            seed.fill_bytes(&mut buf);

            let mut key_map = BTreeMap::new();
            let signing = MockKey {
                key_id: format!("{label}-signing"),
                signing_secret: buf,
            };
            key_map.insert(KeyHandle(1), signing);

            let cert_der = build_fake_der_certificate(label, &spec, &buf);
            let mut certs = BTreeMap::new();
            certs.insert(spec.certificate_label.clone(), cert_der);

            Inner {
                keys: key_map,
                certs,
                slot: SlotMetadata {
                    slot_id: spec.slot_id,
                    description: format!("{} {}", spec.manufacturer, spec.model),
                    manufacturer_id: spec.manufacturer.clone(),
                },
                token: TokenMetadata {
                    label: spec.token_label.clone(),
                    manufacturer_id: spec.manufacturer,
                    model: spec.model,
                    serial_number: spec.serial_number,
                },
            }
        });

        Pkcs11MockProvider { inner }
    }
}

impl Pkcs11MockProvider {
    pub fn key_handles(&self) -> Vec<KeyHandle> {
        self.inner.keys.keys().copied().collect()
    }

    pub fn slot_metadata(&self) -> &SlotMetadata {
        &self.inner.slot
    }

    pub fn token_metadata(&self) -> &TokenMetadata {
        &self.inner.token
    }

    pub fn certificate_der(&self, label: &str) -> Option<&[u8]> {
        self.inner.certs.get(label).map(Vec::as_slice)
    }

    pub fn sign(&self, handle: KeyHandle, message: &[u8]) -> Option<Vec<u8>> {
        let key = self.inner.keys.get(&handle)?;
        Some(sign_bytes(key, message))
    }

    pub fn verify(&self, handle: KeyHandle, message: &[u8], signature: &[u8]) -> bool {
        self.inner
            .keys
            .get(&handle)
            .map(|key| sign_bytes(key, message) == signature)
            .unwrap_or(false)
    }
}

fn sign_bytes(key: &MockKey, message: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_keyed(&key.signing_secret);
    hasher.update(key.key_id.as_bytes());
    hasher.update(message);
    hasher.finalize().as_bytes().to_vec()
}

fn build_fake_der_certificate(label: &str, spec: &Pkcs11Spec, key_material: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + label.len() + spec.token_label.len());
    out.extend_from_slice(b"UKC1");
    out.extend_from_slice(&blake3::hash(key_material).as_bytes()[..16]);
    out.extend_from_slice(label.as_bytes());
    out.push(0xff);
    out.extend_from_slice(spec.token_label.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core::Seed;

    #[test]
    fn deterministic_provider_is_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("pkcs11-det").unwrap());
        let spec = Pkcs11Spec::new(7, "test-token");

        let p1 = fx.pkcs11_mock("issuer", spec.clone());
        let p2 = fx.pkcs11_mock("issuer", spec);

        let handle = p1.key_handles()[0];
        let msg = b"hello world";
        assert_eq!(p1.sign(handle, msg), p2.sign(handle, msg));
    }

    #[test]
    fn sign_verify_round_trip() {
        let fx = Factory::random();
        let provider = fx.pkcs11_mock("roundtrip", Pkcs11Spec::new(1, "token"));
        let handle = provider.key_handles()[0];

        let message = b"pkcs11 fixture message";
        let sig = provider.sign(handle, message).expect("handle must exist");

        assert!(provider.verify(handle, message, &sig));
        assert!(!provider.verify(handle, b"different", &sig));
    }

    #[test]
    fn certificate_lookup_and_metadata_work() {
        let fx = Factory::deterministic(Seed::from_env_value("pkcs11-cert").unwrap());
        let spec = Pkcs11Spec::new(99, "ci-token")
            .with_model("Acme", "HSM-Emu")
            .with_serial_number("SN-42")
            .with_certificate_label("leaf-cert");

        let provider = fx.pkcs11_mock("svc", spec);
        let cert = provider
            .certificate_der("leaf-cert")
            .expect("certificate should exist");

        assert!(cert.starts_with(b"UKC1"));
        assert_eq!(provider.slot_metadata().slot_id, 99);
        assert_eq!(provider.token_metadata().serial_number, "SN-42");
    }
}
