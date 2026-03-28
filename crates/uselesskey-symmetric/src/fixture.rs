use std::fmt;
use std::sync::Arc;

use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};
use uselesskey_core::Factory;
use uselesskey_core_kid::kid_from_bytes;
use uselesskey_core_symmetric_spec::SymmetricSpec;

/// Cache domain for symmetric key fixtures.
pub const DOMAIN_SYMMETRIC_FIXTURE: &str = "uselesskey:symmetric:fixture";

/// Symmetric key fixture.
#[derive(Clone)]
pub struct SymmetricFixture {
    label: String,
    spec: SymmetricSpec,
    inner: Arc<Inner>,
}

struct Inner {
    key: Arc<[u8]>,
    nonce: Arc<[u8]>,
    kid: String,
}

impl fmt::Debug for SymmetricFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymmetricFixture")
            .field("label", &self.label)
            .field("algorithm", &self.spec.algorithm_name())
            .field("key_len", &self.inner.key.len())
            .field("nonce_len", &self.inner.nonce.len())
            .finish_non_exhaustive()
    }
}

/// Extension trait that adds symmetric fixture generation to [`Factory`].
pub trait SymmetricFactoryExt {
    /// Generate or load a deterministic symmetric fixture.
    fn symmetric(&self, label: impl AsRef<str>, spec: SymmetricSpec) -> SymmetricFixture;
}

impl SymmetricFactoryExt for Factory {
    fn symmetric(&self, label: impl AsRef<str>, spec: SymmetricSpec) -> SymmetricFixture {
        let label = label.as_ref();
        let spec_bytes = spec.stable_bytes();
        let inner = self.get_or_init(DOMAIN_SYMMETRIC_FIXTURE, label, &spec_bytes, "good", |seed| {
            let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
            let mut key = vec![0u8; spec.key_len()];
            let mut nonce = vec![0u8; spec.nonce_len()];
            rng.fill_bytes(&mut key);
            rng.fill_bytes(&mut nonce);
            Inner {
                kid: kid_from_bytes(&key),
                key: Arc::from(key),
                nonce: Arc::from(nonce),
            }
        });

        SymmetricFixture {
            label: label.to_string(),
            spec,
            inner,
        }
    }
}

impl SymmetricFixture {
    /// Fixture label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Algorithm spec.
    pub fn spec(&self) -> SymmetricSpec {
        self.spec
    }

    /// Algorithm name.
    pub fn algorithm(&self) -> &'static str {
        self.spec.algorithm_name()
    }

    /// Key bytes.
    pub fn key_bytes(&self) -> &[u8] {
        &self.inner.key
    }

    /// Nonce bytes.
    pub fn nonce_bytes(&self) -> &[u8] {
        &self.inner.nonce
    }

    /// Stable key-id derived from key bytes.
    pub fn kid(&self) -> &str {
        &self.inner.kid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core::Seed;

    #[test]
    fn deterministic_key_and_nonce_generation() {
        let fx = Factory::deterministic(Seed::from_env_value("symmetric-seed").unwrap());
        let a = fx.symmetric("svc", SymmetricSpec::aes256_gcm());
        let b = fx.symmetric("svc", SymmetricSpec::aes256_gcm());

        assert_eq!(a.key_bytes(), b.key_bytes());
        assert_eq!(a.nonce_bytes(), b.nonce_bytes());
        assert_eq!(a.kid(), b.kid());
    }

    #[test]
    fn different_specs_produce_different_key_material() {
        let fx = Factory::deterministic(Seed::from_env_value("symmetric-specs").unwrap());
        let aes = fx.symmetric("svc", SymmetricSpec::aes128_gcm());
        let c20p = fx.symmetric("svc", SymmetricSpec::chacha20_poly1305());

        assert_ne!(aes.key_bytes(), c20p.key_bytes());
    }
}
