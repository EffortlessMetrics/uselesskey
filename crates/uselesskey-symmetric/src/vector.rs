use std::sync::Arc;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};
use serde_json::json;
use uselesskey_core::Factory;
use uselesskey_core_symmetric_spec::{AadMode, AeadVectorSpec, NoncePolicy, PlaintextMode, SymmetricSpec};

use crate::fixture::SymmetricFactoryExt;

/// Cache domain for deterministic AEAD vectors.
pub const DOMAIN_AEAD_VECTOR: &str = "uselesskey:symmetric:aead-vector";

/// Deterministic AEAD vector fixture.
#[derive(Clone, Debug)]
pub struct AeadVectorFixture {
    pub plaintext: Arc<[u8]>,
    pub aad: Arc<[u8]>,
    pub ciphertext: Arc<[u8]>,
    pub tag: Arc<[u8]>,
    pub nonce: Arc<[u8]>,
    pub algorithm: &'static str,
}

/// Extension trait for AEAD vector generation.
pub trait AeadVectorFactoryExt {
    /// Generate deterministic AEAD vector fixtures.
    fn aead_vector(
        &self,
        label: impl AsRef<str>,
        symmetric_spec: SymmetricSpec,
        vector_spec: AeadVectorSpec,
    ) -> AeadVectorFixture;
}

impl AeadVectorFactoryExt for Factory {
    fn aead_vector(
        &self,
        label: impl AsRef<str>,
        symmetric_spec: SymmetricSpec,
        vector_spec: AeadVectorSpec,
    ) -> AeadVectorFixture {
        let label = label.as_ref();
        let sym = self.symmetric(label, symmetric_spec);
        let mut spec_fp = Vec::with_capacity(64);
        spec_fp.extend_from_slice(&symmetric_spec.stable_bytes());
        spec_fp.extend_from_slice(&vector_spec.stable_bytes());

        let fixture = self.get_or_init(DOMAIN_AEAD_VECTOR, label, &spec_fp, "good", |seed| {
            let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
            let plaintext = derive_plaintext(&mut rng, label, &vector_spec);
            let aad = derive_aad(label, &vector_spec);
            let nonce = derive_nonce(&vector_spec, sym.nonce_bytes());
            let (ciphertext, tag) = encrypt_in_place(
                symmetric_spec,
                sym.key_bytes(),
                &nonce,
                &aad,
                &plaintext,
            );

            AeadVectorFixture {
                plaintext: Arc::from(plaintext),
                aad: Arc::from(aad),
                ciphertext: Arc::from(ciphertext),
                tag: Arc::from(tag),
                nonce: Arc::from(nonce),
                algorithm: symmetric_spec.algorithm_name(),
            }
        });

        fixture.as_ref().clone()
    }
}

fn derive_plaintext(rng: &mut ChaCha20Rng, label: &str, spec: &AeadVectorSpec) -> Vec<u8> {
    match spec.plaintext_mode {
        PlaintextMode::FixedBytes => format!("uk:pt:{label}:fixed:v1").into_bytes(),
        PlaintextMode::JsonBody => {
            let v = json!({"sub": label, "scope": "test", "v": 1});
            serde_json::to_vec(&v).expect("json serializable")
        }
        PlaintextMode::RandomShape => {
            let mut len = [0u8; 1];
            rng.fill_bytes(&mut len);
            let len = 24 + (len[0] as usize % 40);
            let mut out = vec![0u8; len];
            rng.fill_bytes(&mut out);
            out
        }
    }
}

fn derive_aad(label: &str, spec: &AeadVectorSpec) -> Vec<u8> {
    match spec.aad_mode {
        AadMode::None => Vec::new(),
        AadMode::FixedBytes => format!("uk:aad:{label}:v1").into_bytes(),
        AadMode::JsonBody => {
            let v = json!({"aud": "fixture", "label": label, "v": 1});
            serde_json::to_vec(&v).expect("json serializable")
        }
    }
}

fn derive_nonce(spec: &AeadVectorSpec, derived_nonce: &[u8]) -> Vec<u8> {
    match spec.nonce_policy {
        NoncePolicy::Derived => derived_nonce.to_vec(),
        NoncePolicy::Explicit => spec.explicit_nonce.clone().unwrap_or_else(|| derived_nonce.to_vec()),
    }
}

fn encrypt_in_place(
    spec: SymmetricSpec,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut buf = plaintext.to_vec();
    let nonce_arr: [u8; 12] = nonce.try_into().expect("nonce length must be 12 bytes");
    match spec {
        SymmetricSpec::Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(key).expect("valid key size");
            let tag = cipher
                .encrypt_in_place_detached((&nonce_arr).into(), aad, &mut buf)
                .expect("aead encrypt");
            let tag: [u8; 16] = tag.into();
            (buf, tag.to_vec())
        }
        SymmetricSpec::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).expect("valid key size");
            let tag = cipher
                .encrypt_in_place_detached((&nonce_arr).into(), aad, &mut buf)
                .expect("aead encrypt");
            let tag: [u8; 16] = tag.into();
            (buf, tag.to_vec())
        }
        SymmetricSpec::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key).expect("valid key size");
            let tag = cipher
                .encrypt_in_place_detached((&nonce_arr).into(), aad, &mut buf)
                .expect("aead encrypt");
            let tag: [u8; 16] = tag.into();
            (buf, tag.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::aead::AeadInPlace;
    use uselesskey_core::Seed;

    use super::*;
    use crate::DOMAIN_SYMMETRIC_FIXTURE;

    #[test]
    fn deterministic_vector_is_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("aead-vector-stable").unwrap());
        let spec = AeadVectorSpec::baseline();

        let a = fx.aead_vector("issuer", SymmetricSpec::aes256_gcm(), spec.clone());
        let b = fx.aead_vector("issuer", SymmetricSpec::aes256_gcm(), spec);

        assert_eq!(a.plaintext, b.plaintext);
        assert_eq!(a.aad, b.aad);
        assert_eq!(a.ciphertext, b.ciphertext);
        assert_eq!(a.tag, b.tag);
        assert_eq!(a.nonce, b.nonce);
    }

    #[test]
    fn aead_round_trip_with_rustcrypto() {
        let fx = Factory::deterministic(Seed::from_env_value("aead-roundtrip").unwrap());
        let spec = AeadVectorSpec {
            plaintext_mode: PlaintextMode::JsonBody,
            aad_mode: AadMode::JsonBody,
            nonce_policy: NoncePolicy::Derived,
            explicit_nonce: None,
        };

        let vec = fx.aead_vector("svc", SymmetricSpec::chacha20_poly1305(), spec.clone());
        let sym = fx.symmetric("svc", SymmetricSpec::chacha20_poly1305());

        let cipher = ChaCha20Poly1305::new_from_slice(sym.key_bytes()).unwrap();
        let mut combined = vec.ciphertext.to_vec();
        combined.extend_from_slice(&vec.tag);

        let mut out = combined;
        let nonce_arr: [u8; 12] = vec.nonce.as_ref().try_into().expect("nonce length");
        cipher
            .decrypt_in_place(
                (&nonce_arr).into(),
                &vec.aad,
                &mut out,
            )
            .unwrap();

        assert_eq!(&out, vec.plaintext.as_ref());
    }

    #[test]
    fn explicit_nonce_is_honored() {
        let fx = Factory::deterministic(Seed::from_env_value("aead-explicit-nonce").unwrap());
        let explicit = vec![7u8; 12];
        let spec = AeadVectorSpec {
            plaintext_mode: PlaintextMode::FixedBytes,
            aad_mode: AadMode::None,
            nonce_policy: NoncePolicy::Explicit,
            explicit_nonce: Some(explicit.clone()),
        };

        let vec = fx.aead_vector("svc", SymmetricSpec::aes128_gcm(), spec);
        assert_eq!(vec.nonce.as_ref(), explicit.as_slice());
    }

    #[test]
    fn vector_domain_is_distinct_from_symmetric_domain() {
        assert_ne!(DOMAIN_AEAD_VECTOR, DOMAIN_SYMMETRIC_FIXTURE);
    }
}
