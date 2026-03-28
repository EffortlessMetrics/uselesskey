use std::fmt;
use std::sync::Arc;

use rand_chacha10::ChaCha20Rng;
use rand_core10::{Rng, SeedableRng};
use uselesskey_core::Factory;

use crate::{PqcAlgorithm, PqcFixtureMode, PqcSecurityLevel, PqcSpec};

/// Cache domain for PQC fixtures.
pub const DOMAIN_PQC_FIXTURE: &str = "uselesskey:pqc:fixture";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqcError {
    RealModeBackendUnavailable { algorithm: PqcAlgorithm },
}

impl fmt::Display for PqcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RealModeBackendUnavailable { algorithm } => write!(
                f,
                "real PQC backend is not enabled for algorithm {algorithm:?}; use opaque mode"
            ),
        }
    }
}

impl std::error::Error for PqcError {}

/// Private key material strategy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateMaterial {
    Bytes(Arc<[u8]>),
    OpaqueHandle(String),
}

#[derive(Clone)]
pub struct PqcFixture {
    label: String,
    spec: PqcSpec,
    inner: Arc<Inner>,
}

struct Inner {
    public_bytes: Arc<[u8]>,
    private_material: PrivateMaterial,
    signature_bytes: Arc<[u8]>,
    ciphertext_bytes: Arc<[u8]>,
    kem_shared_secret: Arc<[u8]>,
}

impl fmt::Debug for PqcFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqcFixture")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .field("public_len", &self.inner.public_bytes.len())
            .field("signature_len", &self.inner.signature_bytes.len())
            .field("ciphertext_len", &self.inner.ciphertext_bytes.len())
            .finish_non_exhaustive()
    }
}

/// Negative vectors derived from a fixture.
#[derive(Clone, Debug)]
pub struct PqcNegativeFixture {
    pub truncated_public: Vec<u8>,
    pub truncated_signature: Vec<u8>,
    pub truncated_ciphertext: Vec<u8>,
    pub oversized_signature: Vec<u8>,
}

pub trait PqcFactoryExt {
    fn pqc(&self, label: impl AsRef<str>, spec: PqcSpec) -> Result<PqcFixture, PqcError>;
}

impl PqcFactoryExt for Factory {
    fn pqc(&self, label: impl AsRef<str>, spec: PqcSpec) -> Result<PqcFixture, PqcError> {
        PqcFixture::new(self, label.as_ref(), spec)
    }
}

impl PqcFixture {
    fn new(factory: &Factory, label: &str, spec: PqcSpec) -> Result<Self, PqcError> {
        if spec.fixture_mode == PqcFixtureMode::Real {
            return Err(PqcError::RealModeBackendUnavailable {
                algorithm: spec.algorithm,
            });
        }

        let inner = load_inner(factory, label, spec, "good");
        Ok(Self {
            label: label.to_owned(),
            spec,
            inner,
        })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn spec(&self) -> PqcSpec {
        self.spec
    }

    pub fn public_bytes(&self) -> &[u8] {
        &self.inner.public_bytes
    }

    pub fn private_material(&self) -> &PrivateMaterial {
        &self.inner.private_material
    }

    pub fn signature_bytes(&self) -> &[u8] {
        &self.inner.signature_bytes
    }

    pub fn ciphertext_bytes(&self) -> &[u8] {
        &self.inner.ciphertext_bytes
    }

    pub fn kem_shared_secret_bytes(&self) -> &[u8] {
        &self.inner.kem_shared_secret
    }

    pub fn malformed_size_vectors(&self) -> PqcNegativeFixture {
        let truncated_public = truncate(self.public_bytes(), 17);
        let truncated_signature = truncate(self.signature_bytes(), 29);
        let truncated_ciphertext = truncate(self.ciphertext_bytes(), 23);

        let mut oversized_signature = self.signature_bytes().to_vec();
        oversized_signature.extend([0xAA; 64]);

        PqcNegativeFixture {
            truncated_public,
            truncated_signature,
            truncated_ciphertext,
            oversized_signature,
        }
    }
}

fn load_inner(factory: &Factory, label: &str, spec: PqcSpec, variant: &str) -> Arc<Inner> {
    let spec_bytes = spec.stable_bytes();
    factory.get_or_init(DOMAIN_PQC_FIXTURE, label, &spec_bytes, variant, |seed| {
        let profile = size_profile(spec.algorithm, spec.security_level);
        let mut rng = ChaCha20Rng::from_seed(*seed.bytes());

        let mut public_bytes = vec![0u8; profile.public_len];
        let mut private_bytes = vec![0u8; profile.private_len];
        let mut signature_bytes = vec![0u8; profile.signature_len];
        let mut ciphertext_bytes = vec![0u8; profile.ciphertext_len];
        let mut kem_shared_secret = vec![0u8; profile.shared_secret_len];

        rng.fill_bytes(&mut public_bytes);
        rng.fill_bytes(&mut private_bytes);
        rng.fill_bytes(&mut signature_bytes);
        rng.fill_bytes(&mut ciphertext_bytes);
        rng.fill_bytes(&mut kem_shared_secret);

        let handle = make_handle(spec, &public_bytes, label);

        Inner {
            public_bytes: Arc::from(public_bytes),
            private_material: PrivateMaterial::OpaqueHandle(handle),
            signature_bytes: Arc::from(signature_bytes),
            ciphertext_bytes: Arc::from(ciphertext_bytes),
            kem_shared_secret: Arc::from(kem_shared_secret),
        }
    })
}

fn truncate(bytes: &[u8], drop_len: usize) -> Vec<u8> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let keep = bytes.len().saturating_sub(drop_len).max(1);
    bytes[..keep].to_vec()
}

fn make_handle(spec: PqcSpec, public_bytes: &[u8], label: &str) -> String {
    let digest = blake3::hash(public_bytes);
    let short = &digest.to_hex()[..12];
    format!(
        "pqc://{}/{}/{}:{}",
        spec.algorithm.as_tag(),
        spec.security_level.as_tag(),
        spec.fixture_mode.as_tag(),
        format_args!("{label}-{short}")
    )
}

#[derive(Clone, Copy)]
struct SizeProfile {
    public_len: usize,
    private_len: usize,
    signature_len: usize,
    ciphertext_len: usize,
    shared_secret_len: usize,
}

fn size_profile(algorithm: PqcAlgorithm, level: PqcSecurityLevel) -> SizeProfile {
    match (algorithm, level) {
        // ML-KEM-ish sizing buckets (opaque vectors only).
        (PqcAlgorithm::MlKem, PqcSecurityLevel::L1) => SizeProfile {
            public_len: 800,
            private_len: 1600,
            signature_len: 256,
            ciphertext_len: 768,
            shared_secret_len: 32,
        },
        (PqcAlgorithm::MlKem, PqcSecurityLevel::L3) => SizeProfile {
            public_len: 1184,
            private_len: 2400,
            signature_len: 320,
            ciphertext_len: 1088,
            shared_secret_len: 32,
        },
        (PqcAlgorithm::MlKem, PqcSecurityLevel::L5) => SizeProfile {
            public_len: 1568,
            private_len: 3168,
            signature_len: 384,
            ciphertext_len: 1568,
            shared_secret_len: 32,
        },
        // ML-DSA-ish sizing buckets (opaque vectors only).
        (PqcAlgorithm::MlDsa, PqcSecurityLevel::L1) => SizeProfile {
            public_len: 1312,
            private_len: 2528,
            signature_len: 2420,
            ciphertext_len: 0,
            shared_secret_len: 0,
        },
        (PqcAlgorithm::MlDsa, PqcSecurityLevel::L3) => SizeProfile {
            public_len: 1952,
            private_len: 4000,
            signature_len: 3293,
            ciphertext_len: 0,
            shared_secret_len: 0,
        },
        (PqcAlgorithm::MlDsa, PqcSecurityLevel::L5) => SizeProfile {
            public_len: 2592,
            private_len: 4864,
            signature_len: 4595,
            ciphertext_len: 0,
            shared_secret_len: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use uselesskey_core::Seed;

    use super::*;

    #[test]
    fn deterministic_opaque_fixture_is_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("pqc-seed").unwrap());
        let a = fx
            .pqc(
                "tls-prepare",
                PqcSpec::opaque(PqcAlgorithm::MlKem, PqcSecurityLevel::L3),
            )
            .unwrap();
        let b = fx
            .pqc(
                "tls-prepare",
                PqcSpec::opaque(PqcAlgorithm::MlKem, PqcSecurityLevel::L3),
            )
            .unwrap();

        assert_eq!(a.public_bytes(), b.public_bytes());
        assert_eq!(a.signature_bytes(), b.signature_bytes());
        assert_eq!(a.ciphertext_bytes(), b.ciphertext_bytes());
    }

    #[test]
    fn real_mode_is_not_available_yet() {
        let fx = Factory::random();
        let err = fx
            .pqc(
                "future-backend",
                PqcSpec::real(PqcAlgorithm::MlDsa, PqcSecurityLevel::L5),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            PqcError::RealModeBackendUnavailable {
                algorithm: PqcAlgorithm::MlDsa
            }
        ));
    }

    #[test]
    fn malformed_vectors_change_sizes() {
        let fx = Factory::random();
        let fixture = fx
            .pqc(
                "parser-neg",
                PqcSpec::opaque(PqcAlgorithm::MlDsa, PqcSecurityLevel::L1),
            )
            .unwrap();
        let bad = fixture.malformed_size_vectors();

        assert!(bad.truncated_public.len() < fixture.public_bytes().len());
        assert!(bad.truncated_signature.len() < fixture.signature_bytes().len());
        assert!(bad.oversized_signature.len() > fixture.signature_bytes().len());
    }
}
