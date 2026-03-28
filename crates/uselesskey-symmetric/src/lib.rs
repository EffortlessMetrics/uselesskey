#![forbid(unsafe_code)]

//! Symmetric-key and AEAD vector fixtures for `uselesskey`.

use std::fmt;
use std::sync::Arc;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};
use thiserror::Error;
use uselesskey_core::Factory;
use uselesskey_core_kid::kid_from_bytes;
pub use uselesskey_core_symmetric_spec::{AadMode, AeadVectorSpec, NoncePolicy, PlaintextMode, SymmetricSpec};

/// Cache domain for symmetric key fixtures.
pub const DOMAIN_SYMMETRIC_FIXTURE: &str = "uselesskey:symmetric:fixture";
/// Cache domain for AEAD vector fixtures.
pub const DOMAIN_AEAD_VECTOR_FIXTURE: &str = "uselesskey:symmetric:aead-vector";

/// Errors raised when generating AEAD vectors.
#[derive(Debug, Error, Clone)]
pub enum SymmetricError {
    /// Encryption failed for the selected algorithm.
    #[error("AEAD encryption failed for algorithm {algorithm}")]
    EncryptFailed {
        /// Algorithm name.
        algorithm: &'static str,
    },
    /// The explicit nonce length does not match the algorithm requirement.
    #[error("explicit nonce length {actual} does not match expected {expected}")]
    InvalidNonceLen {
        /// Observed nonce length.
        actual: usize,
        /// Required nonce length.
        expected: usize,
    },
}

/// Symmetric fixture output.
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
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// Deterministic AEAD test vector fixture.
#[derive(Clone, Debug)]
pub struct AeadVectorFixture {
    /// Algorithm used for vector generation.
    pub algorithm: SymmetricSpec,
    /// Plaintext bytes fed into encryption.
    pub plaintext: Arc<[u8]>,
    /// AAD bytes fed into encryption.
    pub aad: Arc<[u8]>,
    /// Ciphertext bytes (excluding tag).
    pub ciphertext: Arc<[u8]>,
    /// Authentication tag bytes.
    pub tag: Arc<[u8]>,
    /// Nonce bytes used for encryption.
    pub nonce: Arc<[u8]>,
}

/// Extension trait that adds symmetric fixture helpers to [`Factory`].
pub trait SymmetricFactoryExt {
    /// Create (or retrieve) a symmetric key fixture.
    fn symmetric(&self, label: impl AsRef<str>, spec: SymmetricSpec) -> SymmetricFixture;

    /// Create (or retrieve) a deterministic AEAD vector fixture.
    fn aead_vector(
        &self,
        label: impl AsRef<str>,
        spec: AeadVectorSpec,
    ) -> Result<AeadVectorFixture, SymmetricError>;
}

impl SymmetricFactoryExt for Factory {
    fn symmetric(&self, label: impl AsRef<str>, spec: SymmetricSpec) -> SymmetricFixture {
        let spec_bytes = spec.stable_bytes();
        let inner = self.get_or_init(
            DOMAIN_SYMMETRIC_FIXTURE,
            label.as_ref(),
            &spec_bytes,
            "good",
            |seed| {
                let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
                let mut key = vec![0u8; spec.key_len()];
                let mut nonce = vec![0u8; spec.nonce_len()];
                rng.fill_bytes(&mut key);
                rng.fill_bytes(&mut nonce);
                let kid = kid_from_bytes(&key);
                SymmetricFixture {
                    algorithm: spec,
                    key_bytes: Arc::from(key),
                    nonce_bytes: Arc::from(nonce),
                    kid: Some(kid),
                }
            },
        );
        (*inner).clone()
    }

    fn aead_vector(
        &self,
        label: impl AsRef<str>,
        spec: AeadVectorSpec,
    ) -> Result<AeadVectorFixture, SymmetricError> {
        let key_material = self
            .symmetric(label.as_ref(), spec.algorithm)
            .key_bytes()
            .to_vec();
        let spec_bytes = spec.stable_bytes();
        let maybe = self.get_or_init(
            DOMAIN_AEAD_VECTOR_FIXTURE,
            label.as_ref(),
            &spec_bytes,
            "good",
            |seed| build_vector(seed.bytes(), &spec, &key_material),
        );
        match maybe.as_ref() {
            Ok(v) => Ok(v.clone()),
            Err(e) => Err(e.clone()),
        }
    }
}

impl SymmetricFixture {
    /// Algorithm selected for this fixture.
    pub fn algorithm(&self) -> SymmetricSpec {
        self.algorithm
    }

    /// Symmetric key bytes.
    pub fn key_bytes(&self) -> &[u8] {
        &self.key_bytes
    }

    /// Fixture nonce bytes.
    pub fn nonce_bytes(&self) -> &[u8] {
        &self.nonce_bytes
    }

    /// Optional key identifier.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

fn build_vector(
    seed: &[u8; 32],
    spec: &AeadVectorSpec,
    key_material: &[u8],
) -> Result<AeadVectorFixture, SymmetricError> {
    let mut rng = ChaCha20Rng::from_seed(*seed);

    let nonce = match &spec.nonce_policy {
        NoncePolicy::Derived => {
            let mut nonce = vec![0u8; spec.algorithm.nonce_len()];
            rng.fill_bytes(&mut nonce);
            nonce
        }
        NoncePolicy::Explicit(bytes) => {
            if bytes.len() != spec.algorithm.nonce_len() {
                return Err(SymmetricError::InvalidNonceLen {
                    actual: bytes.len(),
                    expected: spec.algorithm.nonce_len(),
                });
            }
            bytes.clone()
        }
    };

    let plaintext = match spec.plaintext_mode {
        PlaintextMode::FixedBytes => b"uselesskey:aead:fixed".to_vec(),
        PlaintextMode::JsonBody => serde_json::to_vec(&serde_json::json!({
            "sub": "fixture-user",
            "scope": ["read", "write"],
            "ok": true
        }))
        .expect("json body serialization should succeed"),
        PlaintextMode::RandomShape => {
            let len = 24 + (rng.next_u32() % 24) as usize;
            let mut bytes = vec![0u8; len];
            rng.fill_bytes(&mut bytes);
            bytes
        }
    };

    let aad = match spec.aad_mode {
        AadMode::None => Vec::new(),
        AadMode::FixedBytes => b"uselesskey:aad:fixed".to_vec(),
        AadMode::RandomShape => {
            let len = 8 + (rng.next_u32() % 16) as usize;
            let mut bytes = vec![0u8; len];
            rng.fill_bytes(&mut bytes);
            bytes
        }
    };

    let mut buffer = plaintext.clone();
    let tag = match spec.algorithm {
        SymmetricSpec::Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(key_material).expect("valid key len");
            cipher
                .encrypt_in_place_detached(AesNonce::from_slice(&nonce), &aad, &mut buffer)
                .map_err(|_| SymmetricError::EncryptFailed {
                    algorithm: spec.algorithm.algorithm_name(),
                })?
                .to_vec()
        }
        SymmetricSpec::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key_material).expect("valid key len");
            cipher
                .encrypt_in_place_detached(AesNonce::from_slice(&nonce), &aad, &mut buffer)
                .map_err(|_| SymmetricError::EncryptFailed {
                    algorithm: spec.algorithm.algorithm_name(),
                })?
                .to_vec()
        }
        SymmetricSpec::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key_material).expect("valid key len");
            cipher
                .encrypt_in_place_detached(ChaNonce::from_slice(&nonce), &aad, &mut buffer)
                .map_err(|_| SymmetricError::EncryptFailed {
                    algorithm: spec.algorithm.algorithm_name(),
                })?
                .to_vec()
        }
    };

    Ok(AeadVectorFixture {
        algorithm: spec.algorithm,
        plaintext: Arc::from(plaintext),
        aad: Arc::from(aad),
        ciphertext: Arc::from(buffer),
        tag: Arc::from(tag),
        nonce: Arc::from(nonce),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use uselesskey_core::{Factory, Seed};

    #[test]
    fn deterministic_symmetric_key_and_nonce_are_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("sym-seed").expect("seed"));
        let a = fx.symmetric("issuer", SymmetricSpec::aes256_gcm());
        let b = fx.symmetric("issuer", SymmetricSpec::aes256_gcm());
        assert_eq!(a.key_bytes(), b.key_bytes());
        assert_eq!(a.nonce_bytes(), b.nonce_bytes());
        assert_eq!(a.algorithm(), SymmetricSpec::aes256_gcm());
        assert!(a.kid().is_some());
    }

    #[test]
    fn aead_roundtrip_works_for_all_algorithms() {
        let fx = Factory::deterministic(Seed::from_env_value("aead-seed").expect("seed"));

        for algorithm in [
            SymmetricSpec::aes128_gcm(),
            SymmetricSpec::aes256_gcm(),
            SymmetricSpec::chacha20_poly1305(),
        ] {
            let spec = AeadVectorSpec::new(
                algorithm,
                PlaintextMode::JsonBody,
                AadMode::FixedBytes,
                NoncePolicy::Derived,
            );
            let vector = fx.aead_vector("enc", spec).expect("vector generation");

            let mut combined = vector.ciphertext.to_vec();
            combined.extend_from_slice(&vector.tag);

            let decrypted = match algorithm {
                SymmetricSpec::Aes128Gcm => {
                    let key = fx.symmetric("enc", algorithm);
                    let cipher = Aes128Gcm::new_from_slice(key.key_bytes()).expect("key len");
                    cipher
                        .decrypt(
                            AesNonce::from_slice(&vector.nonce),
                            aes_gcm::aead::Payload {
                                msg: &combined,
                                aad: &vector.aad,
                            },
                        )
                        .expect("decrypt")
                }
                SymmetricSpec::Aes256Gcm => {
                    let key = fx.symmetric("enc", algorithm);
                    let cipher = Aes256Gcm::new_from_slice(key.key_bytes()).expect("key len");
                    cipher
                        .decrypt(
                            AesNonce::from_slice(&vector.nonce),
                            aes_gcm::aead::Payload {
                                msg: &combined,
                                aad: &vector.aad,
                            },
                        )
                        .expect("decrypt")
                }
                SymmetricSpec::ChaCha20Poly1305 => {
                    let key = fx.symmetric("enc", algorithm);
                    let cipher = ChaCha20Poly1305::new_from_slice(key.key_bytes()).expect("key len");
                    cipher
                        .decrypt(
                            ChaNonce::from_slice(&vector.nonce),
                            chacha20poly1305::aead::Payload {
                                msg: &combined,
                                aad: &vector.aad,
                            },
                        )
                        .expect("decrypt")
                }
            };
            assert_eq!(decrypted, vector.plaintext.as_ref());
        }
    }
}
