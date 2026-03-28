use std::fmt;
use std::sync::Arc;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};
use uselesskey_core::Factory;
use uselesskey_core_kid::kid_from_bytes;
use uselesskey_core_symmetric_spec::{AadMode, AeadVectorSpec, NoncePolicy, PlaintextMode, SymmetricSpec};

/// Cache domain for symmetric key fixtures.
pub const DOMAIN_SYMMETRIC_KEY: &str = "uselesskey:symmetric:key";
/// Cache domain for deterministic AEAD vectors.
pub const DOMAIN_SYMMETRIC_AEAD_VECTOR: &str = "uselesskey:symmetric:aead_vector";

/// A deterministic symmetric fixture for AEAD-style algorithms.
#[derive(Clone)]
pub struct SymmetricFixture {
    algorithm: SymmetricSpec,
    key_bytes: Arc<[u8]>,
    nonce_bytes: Arc<[u8]>,
    kid: Option<String>,
}

impl fmt::Debug for SymmetricFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymmetricFixture")
            .field("algorithm", &self.algorithm)
            .field("key_len", &self.key_bytes.len())
            .field("nonce_len", &self.nonce_bytes.len())
            .field("kid", &self.kid)
            .finish()
    }
}

/// A deterministic AEAD vector fixture.
#[derive(Clone, Debug)]
pub struct AeadVectorFixture {
    /// Plaintext bytes used for encryption.
    pub plaintext: Vec<u8>,
    /// AAD bytes used for encryption.
    pub aad: Vec<u8>,
    /// Ciphertext bytes without authentication tag.
    pub ciphertext: Vec<u8>,
    /// Authentication tag bytes.
    pub tag: Vec<u8>,
    /// Nonce bytes used for encryption.
    pub nonce: Vec<u8>,
}

/// Extension trait for generating symmetric and AEAD vector fixtures.
pub trait SymmetricFactoryExt {
    /// Generate (or fetch from cache) a symmetric fixture.
    fn symmetric(&self, label: impl AsRef<str>, spec: SymmetricSpec) -> SymmetricFixture;

    /// Generate a deterministic AEAD vector fixture.
    fn aead_vector(&self, label: impl AsRef<str>, spec: AeadVectorSpec) -> AeadVectorFixture;
}

impl SymmetricFactoryExt for Factory {
    fn symmetric(&self, label: impl AsRef<str>, spec: SymmetricSpec) -> SymmetricFixture {
        let spec_bytes = spec.stable_bytes();
        let inner = self.get_or_init(
            DOMAIN_SYMMETRIC_KEY,
            label.as_ref(),
            &spec_bytes,
            "good",
            |seed| {
                let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
                let mut key = vec![0u8; spec.key_len()];
                let mut nonce = vec![0u8; spec.nonce_len()];
                rng.fill_bytes(&mut key);
                rng.fill_bytes(&mut nonce);

                SymmetricFixture {
                    algorithm: spec,
                    kid: Some(kid_from_bytes(&key)),
                    key_bytes: Arc::from(key),
                    nonce_bytes: Arc::from(nonce),
                }
            },
        );

        (*inner).clone()
    }

    fn aead_vector(&self, label: impl AsRef<str>, spec: AeadVectorSpec) -> AeadVectorFixture {
        let spec_bytes = spec.stable_bytes();
        let key_fixture = self.symmetric(label.as_ref(), spec.algorithm);
        self.get_or_init(
            DOMAIN_SYMMETRIC_AEAD_VECTOR,
            label.as_ref(),
            &spec_bytes,
            "good",
            |seed| {
                let mut rng = ChaCha20Rng::from_seed(*seed.bytes());

                let plaintext = resolve_plaintext(&spec, &mut rng, label.as_ref());
                let aad = resolve_aad(&spec, &mut rng, label.as_ref());
                let nonce = resolve_nonce(&spec, &mut rng, &key_fixture);

                let mut payload = plaintext.clone();
                let tag = encrypt_in_place(
                    key_fixture.algorithm,
                    key_fixture.key_bytes(),
                    &nonce,
                    &aad,
                    &mut payload,
                );

                AeadVectorFixture {
                    plaintext,
                    aad,
                    ciphertext: payload,
                    tag,
                    nonce,
                }
            },
        )
        .as_ref()
        .clone()
    }
}

impl SymmetricFixture {
    /// Algorithm used by this fixture.
    pub const fn algorithm(&self) -> SymmetricSpec {
        self.algorithm
    }

    /// Key bytes.
    pub fn key_bytes(&self) -> &[u8] {
        &self.key_bytes
    }

    /// Nonce bytes.
    pub fn nonce_bytes(&self) -> &[u8] {
        &self.nonce_bytes
    }

    /// Optional key identifier.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

fn resolve_plaintext(spec: &AeadVectorSpec, rng: &mut ChaCha20Rng, label: &str) -> Vec<u8> {
    match spec.plaintext_mode {
        PlaintextMode::FixedBytes => spec
            .fixed_plaintext
            .clone()
            .unwrap_or_else(|| b"fixture:fixed-plaintext".to_vec()),
        PlaintextMode::JsonBody => {
            let value = serde_json::json!({
                "iss": "uselesskey-fixture",
                "sub": label,
                "scope": ["read", "write"],
                "active": true,
            });
            serde_json::to_vec(&value).expect("json serialization")
        }
        PlaintextMode::RandomShape => {
            let len = 16 + (rng.next_u32() as usize % 80);
            let mut out = vec![0u8; len];
            rng.fill_bytes(&mut out);
            out
        }
    }
}

fn resolve_aad(spec: &AeadVectorSpec, rng: &mut ChaCha20Rng, label: &str) -> Vec<u8> {
    match spec.aad_mode {
        AadMode::None => Vec::new(),
        AadMode::Standard => format!("aad:label={label}:v1").into_bytes(),
        AadMode::FixedBytes => spec.fixed_aad.clone().unwrap_or_else(|| {
            let mut out = vec![0u8; 12];
            rng.fill_bytes(&mut out);
            out
        }),
    }
}

fn resolve_nonce(spec: &AeadVectorSpec, rng: &mut ChaCha20Rng, key: &SymmetricFixture) -> Vec<u8> {
    match &spec.nonce_policy {
        NoncePolicy::Derived => key.nonce_bytes().to_vec(),
        NoncePolicy::Explicit(nonce) => {
            if nonce.is_empty() {
                let mut generated = vec![0u8; key.algorithm().nonce_len()];
                rng.fill_bytes(&mut generated);
                generated
            } else {
                nonce.clone()
            }
        }
    }
}

fn encrypt_in_place(
    algorithm: SymmetricSpec,
    key_bytes: &[u8],
    nonce: &[u8],
    aad: &[u8],
    payload: &mut Vec<u8>,
) -> Vec<u8> {
    match algorithm {
        SymmetricSpec::Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(key_bytes).expect("valid AES-128 key");
            let tag = cipher
                .encrypt_in_place_detached(nonce.into(), aad, payload)
                .expect("encrypt");
            tag.to_vec()
        }
        SymmetricSpec::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key_bytes).expect("valid AES-256 key");
            let tag = cipher
                .encrypt_in_place_detached(nonce.into(), aad, payload)
                .expect("encrypt");
            tag.to_vec()
        }
        SymmetricSpec::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key_bytes).expect("valid c20p key");
            let tag = cipher
                .encrypt_in_place_detached(nonce.into(), aad, payload)
                .expect("encrypt");
            tag.to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core::Seed;

    #[test]
    fn deterministic_key_and_nonce_are_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("sym-seed").expect("seed"));
        let a = fx.symmetric("issuer", SymmetricSpec::aes256_gcm());
        let b = fx.symmetric("issuer", SymmetricSpec::aes256_gcm());

        assert_eq!(a.key_bytes(), b.key_bytes());
        assert_eq!(a.nonce_bytes(), b.nonce_bytes());
        assert_eq!(a.kid(), b.kid());
    }

    #[test]
    fn deterministic_vector_is_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("sym-vector").expect("seed"));
        let mut spec = AeadVectorSpec::new(SymmetricSpec::chacha20_poly1305());
        spec.plaintext_mode = PlaintextMode::JsonBody;
        spec.aad_mode = AadMode::Standard;

        let a = fx.aead_vector("svc", spec.clone());
        let b = fx.aead_vector("svc", spec);

        assert_eq!(a.plaintext, b.plaintext);
        assert_eq!(a.aad, b.aad);
        assert_eq!(a.ciphertext, b.ciphertext);
        assert_eq!(a.tag, b.tag);
        assert_eq!(a.nonce, b.nonce);
    }

    #[test]
    fn aead_round_trip_with_rustcrypto() {
        let fx = Factory::deterministic(Seed::from_env_value("sym-roundtrip").expect("seed"));
        let mut spec = AeadVectorSpec::new(SymmetricSpec::aes128_gcm());
        spec.plaintext_mode = PlaintextMode::FixedBytes;
        spec.fixed_plaintext = Some(b"hello-symmetric".to_vec());
        spec.aad_mode = AadMode::FixedBytes;
        spec.fixed_aad = Some(b"fixture-aad".to_vec());

        let vector = fx.aead_vector("rt", spec.clone());
        let key = fx.symmetric("rt", spec.algorithm);

        let cipher = Aes128Gcm::new_from_slice(key.key_bytes()).expect("cipher");
        let mut ct_plus_tag = vector.ciphertext.clone();
        ct_plus_tag.extend_from_slice(&vector.tag);
        let mut detached = ct_plus_tag[..ct_plus_tag.len() - 16].to_vec();

        let tag = aes_gcm::Tag::from_slice(&ct_plus_tag[ct_plus_tag.len() - 16..]);
        cipher
            .decrypt_in_place_detached(vector.nonce.as_slice().into(), &vector.aad, &mut detached, tag)
            .expect("decrypt");

        assert_eq!(detached, vector.plaintext);
    }
}
