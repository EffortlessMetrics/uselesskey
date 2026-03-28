use std::sync::Arc;

use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};
use uselesskey_core::Factory;
use uselesskey_core_kid::kid_from_bytes;

use crate::{AadMode, AeadVectorSpec, NoncePolicy, PlaintextMode, SymmetricSpec};

pub const DOMAIN_SYMMETRIC: &str = "uselesskey:symmetric:key";
pub const DOMAIN_AEAD_VECTOR: &str = "uselesskey:symmetric:aead-vector";

#[derive(Clone, Debug)]
pub struct SymmetricFixture {
    key_bytes: Arc<[u8]>,
    nonce_bytes: Arc<[u8]>,
    algorithm: SymmetricSpec,
    kid: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AeadVectorFixture {
    pub plaintext: Arc<[u8]>,
    pub aad: Arc<[u8]>,
    pub ciphertext: Arc<[u8]>,
    pub tag: Arc<[u8]>,
    pub nonce: Arc<[u8]>,
}

pub trait SymmetricFactoryExt {
    fn symmetric(&self, label: impl AsRef<str>, spec: SymmetricSpec) -> SymmetricFixture;
    fn aead_vector(
        &self,
        label: impl AsRef<str>,
        symmetric_spec: SymmetricSpec,
        vector_spec: AeadVectorSpec,
    ) -> AeadVectorFixture;
}

impl SymmetricFactoryExt for Factory {
    fn symmetric(&self, label: impl AsRef<str>, spec: SymmetricSpec) -> SymmetricFixture {
        load_symmetric_fixture(self, label.as_ref(), spec)
    }

    fn aead_vector(
        &self,
        label: impl AsRef<str>,
        symmetric_spec: SymmetricSpec,
        vector_spec: AeadVectorSpec,
    ) -> AeadVectorFixture {
        load_aead_vector(self, label.as_ref(), symmetric_spec, vector_spec)
    }
}

impl SymmetricFixture {
    pub fn key_bytes(&self) -> &[u8] {
        &self.key_bytes
    }

    pub fn nonce_bytes(&self) -> &[u8] {
        &self.nonce_bytes
    }

    pub fn algorithm(&self) -> SymmetricSpec {
        self.algorithm
    }

    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

fn load_symmetric_fixture(factory: &Factory, label: &str, spec: SymmetricSpec) -> SymmetricFixture {
    let spec_bytes = spec.stable_bytes();
    factory
        .get_or_init(DOMAIN_SYMMETRIC, label, &spec_bytes, "key-nonce", |seed| {
            let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
            let mut key = vec![0_u8; spec.key_len()];
            let mut nonce = vec![0_u8; 12];
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut nonce);

            let kid = kid_from_bytes(&key);

            SymmetricFixture {
                key_bytes: Arc::from(key),
                nonce_bytes: Arc::from(nonce),
                algorithm: spec,
                kid: Some(kid),
            }
        })
        .as_ref()
        .clone()
}

fn load_aead_vector(
    factory: &Factory,
    label: &str,
    symmetric_spec: SymmetricSpec,
    vector_spec: AeadVectorSpec,
) -> AeadVectorFixture {
    let mut spec_bytes = Vec::with_capacity(10);
    spec_bytes.extend_from_slice(&symmetric_spec.stable_bytes());
    spec_bytes.extend_from_slice(&vector_spec.stable_bytes());

    factory
        .get_or_init(DOMAIN_AEAD_VECTOR, label, &spec_bytes, "good", |seed| {
            let mut rng = ChaCha20Rng::from_seed(*seed.bytes());

            let mut explicit_nonce = [0_u8; 12];
            rng.fill_bytes(&mut explicit_nonce);

            let key_fixture = load_symmetric_fixture(factory, label, symmetric_spec);
            let nonce = match vector_spec.nonce_policy {
                NoncePolicy::Derived => Arc::from(key_fixture.nonce_bytes().to_vec()),
                NoncePolicy::Explicit => Arc::from(explicit_nonce.to_vec()),
            };

            let plaintext: Arc<[u8]> = Arc::from(match vector_spec.plaintext_mode {
                PlaintextMode::FixedBytes => b"uselesskey:aead:fixed:plaintext".to_vec(),
                PlaintextMode::JsonBody => {
                    format!(
                        "{{\"iss\":\"{}\",\"scope\":\"fixture\",\"mode\":\"json\"}}",
                        label
                    )
                    .into_bytes()
                }
                PlaintextMode::RandomShape => {
                    let mut out = vec![0_u8; 64];
                    rng.fill_bytes(&mut out);
                    out
                }
            });

            let aad: Arc<[u8]> = Arc::from(match vector_spec.aad_mode {
                AadMode::None => Vec::new(),
                AadMode::FixedBytes => b"uselesskey:aead:fixed:aad".to_vec(),
                AadMode::RandomShape => {
                    let mut out = vec![0_u8; 24];
                    rng.fill_bytes(&mut out);
                    out
                }
            });

            let (ciphertext, tag) =
                encrypt_vector(symmetric_spec, key_fixture.key_bytes(), &nonce, &plaintext, &aad);

            AeadVectorFixture {
                plaintext,
                aad,
                ciphertext: Arc::from(ciphertext),
                tag: Arc::from(tag),
                nonce,
            }
        })
        .as_ref()
        .clone()
}

fn encrypt_vector(
    spec: SymmetricSpec,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    use aes_gcm::{
        Aes128Gcm, Aes256Gcm,
        aead::{AeadInPlace, KeyInit},
    };
    use chacha20poly1305::ChaCha20Poly1305;

    let mut buffer = plaintext.to_vec();

    let tag = match spec {
        SymmetricSpec::Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(key).expect("valid key length");
            let nonce_arr: [u8; 12] = nonce.try_into().expect("nonce must be 12 bytes");
            cipher
                .encrypt_in_place_detached(&nonce_arr.into(), aad, &mut buffer)
                .expect("encryption should succeed")
        }
        SymmetricSpec::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).expect("valid key length");
            let nonce_arr: [u8; 12] = nonce.try_into().expect("nonce must be 12 bytes");
            cipher
                .encrypt_in_place_detached(&nonce_arr.into(), aad, &mut buffer)
                .expect("encryption should succeed")
        }
        SymmetricSpec::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).expect("valid key length");
            let nonce_arr: [u8; 12] = nonce.try_into().expect("nonce must be 12 bytes");
            cipher
                .encrypt_in_place_detached(&nonce_arr.into(), aad, &mut buffer)
                .expect("encryption should succeed")
        }
    };

    (buffer, tag.to_vec())
}
