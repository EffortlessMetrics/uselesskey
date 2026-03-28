#![forbid(unsafe_code)]

//! Experimental PQC-shaped fixtures for parser, buffer, and TLS-prep tests.
//!
//! This crate intentionally focuses on **shape-first** fixture generation and
//! deterministic regeneration. It is not a production PQC implementation.
//! Real algorithm backends are reserved for future work once ecosystem support
//! is mature enough.
//!
//! # Stability
//!
//! - This crate is experimental and currently not re-exported by `uselesskey`.
//! - API details may evolve before a stable facade integration.

use std::fmt;
use std::sync::Arc;

use uselesskey_core::Factory;

/// Cache domain for PQC fixtures.
pub const DOMAIN_PQC_FIXTURE: &str = "uselesskey:pqc:fixture";

/// PQC algorithm family selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PqcAlgorithm {
    /// NIST ML-KEM family.
    MlKem,
    /// NIST ML-DSA family.
    MlDsa,
}

impl PqcAlgorithm {
    const fn stable_byte(self) -> u8 {
        match self {
            Self::MlKem => 1,
            Self::MlDsa => 2,
        }
    }
}

/// Target security category.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PqcSecurityLevel {
    Level1,
    Level3,
    Level5,
}

impl PqcSecurityLevel {
    const fn stable_byte(self) -> u8 {
        match self {
            Self::Level1 => 1,
            Self::Level3 => 3,
            Self::Level5 => 5,
        }
    }
}

/// Fixture generation mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PqcFixtureMode {
    /// Generate deterministic opaque vectors tuned for parser/size tests.
    Opaque,
    /// Reserved for future real-algorithm fixtures (currently synthetic).
    Real,
}

impl PqcFixtureMode {
    const fn stable_byte(self) -> u8 {
        match self {
            Self::Opaque => 1,
            Self::Real => 2,
        }
    }
}

/// Specification for generating a PQC fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PqcSpec {
    pub algorithm: PqcAlgorithm,
    pub security_level: PqcSecurityLevel,
    pub mode: PqcFixtureMode,
}

impl PqcSpec {
    /// Canonical opaque ML-KEM spec.
    pub const fn ml_kem(level: PqcSecurityLevel) -> Self {
        Self {
            algorithm: PqcAlgorithm::MlKem,
            security_level: level,
            mode: PqcFixtureMode::Opaque,
        }
    }

    /// Canonical opaque ML-DSA spec.
    pub const fn ml_dsa(level: PqcSecurityLevel) -> Self {
        Self {
            algorithm: PqcAlgorithm::MlDsa,
            security_level: level,
            mode: PqcFixtureMode::Opaque,
        }
    }

    /// Return a real-mode spec for forward-compatible API exploration.
    pub const fn with_real_mode(mut self) -> Self {
        self.mode = PqcFixtureMode::Real;
        self
    }

    /// Stable encoding for deterministic derivation and cache keys.
    pub const fn stable_bytes(self) -> [u8; 3] {
        [
            self.algorithm.stable_byte(),
            self.security_level.stable_byte(),
            self.mode.stable_byte(),
        ]
    }

    const fn size_profile(self) -> SizeProfile {
        match (self.algorithm, self.security_level) {
            (PqcAlgorithm::MlKem, PqcSecurityLevel::Level1) => SizeProfile {
                public_len: 800,
                private_len: 1632,
                ciphertext_len: 768,
                signature_len: 0,
                vector_len: 32,
            },
            (PqcAlgorithm::MlKem, PqcSecurityLevel::Level3) => SizeProfile {
                public_len: 1184,
                private_len: 2400,
                ciphertext_len: 1088,
                signature_len: 0,
                vector_len: 48,
            },
            (PqcAlgorithm::MlKem, PqcSecurityLevel::Level5) => SizeProfile {
                public_len: 1568,
                private_len: 3168,
                ciphertext_len: 1568,
                signature_len: 0,
                vector_len: 64,
            },
            (PqcAlgorithm::MlDsa, PqcSecurityLevel::Level1) => SizeProfile {
                public_len: 1312,
                private_len: 2560,
                ciphertext_len: 0,
                signature_len: 2420,
                vector_len: 64,
            },
            (PqcAlgorithm::MlDsa, PqcSecurityLevel::Level3) => SizeProfile {
                public_len: 1952,
                private_len: 4032,
                ciphertext_len: 0,
                signature_len: 3309,
                vector_len: 64,
            },
            (PqcAlgorithm::MlDsa, PqcSecurityLevel::Level5) => SizeProfile {
                public_len: 2592,
                private_len: 4896,
                ciphertext_len: 0,
                signature_len: 4627,
                vector_len: 64,
            },
        }
    }
}

#[derive(Clone, Copy)]
struct SizeProfile {
    public_len: usize,
    private_len: usize,
    ciphertext_len: usize,
    signature_len: usize,
    vector_len: usize,
}

#[derive(Clone)]
pub struct PqcFixture {
    label: String,
    spec: PqcSpec,
    inner: Arc<Inner>,
}

#[derive(Clone)]
struct Inner {
    public_bytes: Vec<u8>,
    private_material: PqcPrivateMaterial,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
    test_vectors: Vec<Vec<u8>>,
}

/// Private material either as bytes or as an opaque handle marker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PqcPrivateMaterial {
    Bytes(Vec<u8>),
    OpaqueHandle(String),
}

impl fmt::Debug for PqcFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqcFixture")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .field("public_len", &self.inner.public_bytes.len())
            .field("ciphertext_len", &self.inner.ciphertext.len())
            .field("signature_len", &self.inner.signature.len())
            .finish()
    }
}

/// Extension trait to hang PQC helpers from [`Factory`].
pub trait PqcFactoryExt {
    fn pqc(&self, label: impl AsRef<str>, spec: PqcSpec) -> PqcFixture;
    fn pqc_with_variant(
        &self,
        label: impl AsRef<str>,
        spec: PqcSpec,
        variant: impl AsRef<str>,
    ) -> PqcFixture;
}

impl PqcFactoryExt for Factory {
    fn pqc(&self, label: impl AsRef<str>, spec: PqcSpec) -> PqcFixture {
        self.pqc_with_variant(label, spec, "good")
    }

    fn pqc_with_variant(
        &self,
        label: impl AsRef<str>,
        spec: PqcSpec,
        variant: impl AsRef<str>,
    ) -> PqcFixture {
        let label = label.as_ref();
        let variant = variant.as_ref();
        let spec_bytes = spec.stable_bytes();
        let inner = self.get_or_init(DOMAIN_PQC_FIXTURE, label, &spec_bytes, variant, |seed| {
            let profile = spec.size_profile();
            let mut public_bytes = fill_stream(seed.bytes(), "public", profile.public_len);
            let mut private_bytes = fill_stream(seed.bytes(), "private", profile.private_len);
            let mut ciphertext = fill_stream(seed.bytes(), "ciphertext", profile.ciphertext_len);
            let mut signature = fill_stream(seed.bytes(), "signature", profile.signature_len);
            let test_vectors = vec![
                fill_stream(seed.bytes(), "vector-a", profile.vector_len),
                fill_stream(seed.bytes(), "vector-b", profile.vector_len),
                fill_stream(seed.bytes(), "vector-c", profile.vector_len),
            ];

            apply_variant(
                variant,
                &mut public_bytes,
                &mut private_bytes,
                &mut ciphertext,
                &mut signature,
                seed.bytes(),
            );

            let private_material = match spec.mode {
                PqcFixtureMode::Opaque => {
                    PqcPrivateMaterial::OpaqueHandle(format!("opaque://pqc/{label}/{variant}"))
                }
                PqcFixtureMode::Real => PqcPrivateMaterial::Bytes(private_bytes),
            };

            Inner {
                public_bytes,
                private_material,
                ciphertext,
                signature,
                test_vectors,
            }
        });

        PqcFixture {
            label: label.to_string(),
            spec,
            inner,
        }
    }
}

impl PqcFixture {
    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn spec(&self) -> PqcSpec {
        self.spec
    }

    pub fn public_bytes(&self) -> &[u8] {
        &self.inner.public_bytes
    }

    pub fn private_material(&self) -> &PqcPrivateMaterial {
        &self.inner.private_material
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.inner.ciphertext
    }

    pub fn signature(&self) -> &[u8] {
        &self.inner.signature
    }

    pub fn test_vectors(&self) -> &[Vec<u8>] {
        &self.inner.test_vectors
    }

    /// Negative helper: return a truncated view of the selected payload.
    pub fn truncated_payload(&self, payload: PqcPayloadKind, keep: usize) -> Vec<u8> {
        let src = match payload {
            PqcPayloadKind::PublicKey => self.public_bytes(),
            PqcPayloadKind::Private => match self.private_material() {
                PqcPrivateMaterial::Bytes(bytes) => bytes.as_slice(),
                PqcPrivateMaterial::OpaqueHandle(_) => &[],
            },
            PqcPayloadKind::Ciphertext => self.ciphertext(),
            PqcPayloadKind::Signature => self.signature(),
        };

        src.iter().copied().take(keep).collect()
    }

    /// Negative helper: return payload with extra bytes appended.
    pub fn oversized_payload(
        &self,
        payload: PqcPayloadKind,
        extra: usize,
        marker: u8,
    ) -> Vec<u8> {
        let mut out = match payload {
            PqcPayloadKind::PublicKey => self.public_bytes().to_vec(),
            PqcPayloadKind::Private => match self.private_material() {
                PqcPrivateMaterial::Bytes(bytes) => bytes.clone(),
                PqcPrivateMaterial::OpaqueHandle(_) => Vec::new(),
            },
            PqcPayloadKind::Ciphertext => self.ciphertext().to_vec(),
            PqcPayloadKind::Signature => self.signature().to_vec(),
        };

        out.extend(std::iter::repeat_n(marker, extra));
        out
    }
}

/// Selectable payload segment for negative-fixture helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PqcPayloadKind {
    PublicKey,
    Private,
    Ciphertext,
    Signature,
}

fn fill_stream(seed: &[u8; 32], tag: &str, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    if len == 0 {
        return out;
    }

    let mut offset = 0usize;
    let mut ctr = 0u64;
    while offset < len {
        let mut hasher = blake3::Hasher::new_keyed(seed);
        hasher.update(tag.as_bytes());
        hasher.update(&ctr.to_le_bytes());
        let block = hasher.finalize();
        let bytes = block.as_bytes();
        let take = (len - offset).min(bytes.len());
        out[offset..offset + take].copy_from_slice(&bytes[..take]);
        offset += take;
        ctr = ctr.wrapping_add(1);
    }

    out
}

fn apply_variant(
    variant: &str,
    public_bytes: &mut Vec<u8>,
    private_bytes: &mut Vec<u8>,
    ciphertext: &mut Vec<u8>,
    signature: &mut Vec<u8>,
    seed: &[u8; 32],
) {
    let parts: Vec<&str> = variant.split(':').collect();
    if parts.len() != 3 {
        return;
    }

    let Some(amount) = parts[2].parse::<usize>().ok() else {
        return;
    };

    let target = match parts[1] {
        "public" => public_bytes,
        "private" => private_bytes,
        "ciphertext" => ciphertext,
        "signature" => signature,
        _ => return,
    };

    match parts[0] {
        "truncate" => {
            target.truncate(amount.min(target.len()));
        }
        "oversize" => {
            let extra = fill_stream(seed, variant, amount);
            target.extend(extra);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core::Seed;

    #[test]
    fn deterministic_regeneration_is_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("pqc-stable").unwrap());
        let a = fx.pqc("tls-kem", PqcSpec::ml_kem(PqcSecurityLevel::Level3));
        let b = fx.pqc("tls-kem", PqcSpec::ml_kem(PqcSecurityLevel::Level3));

        assert_eq!(a.public_bytes(), b.public_bytes());
        assert_eq!(a.ciphertext(), b.ciphertext());
        assert_eq!(a.signature(), b.signature());
    }

    #[test]
    fn opaque_mode_uses_handle_not_secret_bytes() {
        let fx = Factory::random();
        let fixture = fx.pqc("opaque", PqcSpec::ml_dsa(PqcSecurityLevel::Level5));
        assert!(matches!(
            fixture.private_material(),
            PqcPrivateMaterial::OpaqueHandle(_)
        ));
    }

    #[test]
    fn real_mode_exposes_private_bytes_for_future_interop_tests() {
        let fx = Factory::deterministic(Seed::from_env_value("pqc-real").unwrap());
        let fixture = fx.pqc(
            "real-preview",
            PqcSpec::ml_kem(PqcSecurityLevel::Level1).with_real_mode(),
        );
        match fixture.private_material() {
            PqcPrivateMaterial::Bytes(bytes) => assert_eq!(bytes.len(), 1632),
            PqcPrivateMaterial::OpaqueHandle(_) => panic!("expected bytes in real mode"),
        }
    }

    #[test]
    fn truncation_variant_supports_negative_size_cases() {
        let fx = Factory::deterministic(Seed::from_env_value("pqc-trunc").unwrap());
        let good = fx.pqc("sig", PqcSpec::ml_dsa(PqcSecurityLevel::Level1));
        let truncated = fx.pqc_with_variant(
            "sig",
            PqcSpec::ml_dsa(PqcSecurityLevel::Level1),
            "truncate:signature:120",
        );

        assert!(good.signature().len() > truncated.signature().len());
        assert_eq!(truncated.signature().len(), 120);
    }

    #[test]
    fn oversize_variant_supports_buffer_boundaries() {
        let fx = Factory::deterministic(Seed::from_env_value("pqc-over").unwrap());
        let good = fx.pqc("kem", PqcSpec::ml_kem(PqcSecurityLevel::Level5));
        let oversized = fx.pqc_with_variant(
            "kem",
            PqcSpec::ml_kem(PqcSecurityLevel::Level5),
            "oversize:ciphertext:37",
        );

        assert_eq!(oversized.ciphertext().len(), good.ciphertext().len() + 37);
    }

    #[test]
    fn helper_methods_enable_parser_size_tests() {
        let fx = Factory::deterministic(Seed::from_env_value("pqc-helper").unwrap());
        let fixture = fx.pqc("pk", PqcSpec::ml_kem(PqcSecurityLevel::Level1).with_real_mode());

        let short = fixture.truncated_payload(PqcPayloadKind::PublicKey, 12);
        assert_eq!(short.len(), 12);

        let bigger = fixture.oversized_payload(PqcPayloadKind::Signature, 9, 0xAA);
        assert_eq!(bigger.len(), 9);
        assert!(bigger.iter().all(|b| *b == 0xAA));
    }

    #[test]
    fn debug_redacts_material() {
        let fx = Factory::deterministic(Seed::from_env_value("pqc-debug").unwrap());
        let fixture = fx.pqc("dbg", PqcSpec::ml_kem(PqcSecurityLevel::Level3));
        let dbg = format!("{fixture:?}");

        assert!(dbg.contains("PqcFixture"));
        assert!(!dbg.contains("opaque://"));
    }
}
