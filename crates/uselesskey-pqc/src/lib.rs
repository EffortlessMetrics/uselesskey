#![forbid(unsafe_code)]

//! Experimental PQC fixture helpers for parser, buffer, and TLS-prep tests.
//!
//! This crate currently focuses on **opaque** test vectors and malformed-size
//! negatives. Real algorithm backends are intentionally deferred until the Rust
//! PQC ecosystem is stable enough for long-term maintenance.

use std::fmt;
use std::sync::Arc;

use thiserror::Error;
use uselesskey_core::Factory;

/// Cache domain for PQC fixtures.
///
/// Keep this stable: changing it changes deterministic outputs.
pub const DOMAIN_PQC_FIXTURE: &str = "uselesskey:pqc:fixture";

/// Supported PQC algorithm families for fixture shaping.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PqcAlgorithm {
    /// ML-KEM (KEM/ciphertext-shaped fixtures).
    MlKem,
    /// ML-DSA (signature-shaped fixtures).
    MlDsa,
}

/// Security level for fixture size profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PqcSecurityLevel {
    /// Low-ish profile (roughly NIST level 1 shape).
    L1,
    /// Medium profile (roughly NIST level 3 shape).
    L3,
    /// High profile (roughly NIST level 5 shape).
    L5,
}

/// Fixture generation mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PqcFixtureMode {
    /// Opaque deterministic vectors with realistic size envelopes.
    Opaque,
    /// Placeholder for future real PQC backend integration.
    Real,
}

/// Fixture request spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PqcSpec {
    algorithm: PqcAlgorithm,
    security_level: PqcSecurityLevel,
    fixture_mode: PqcFixtureMode,
}

impl PqcSpec {
    /// Build a custom spec.
    pub const fn new(
        algorithm: PqcAlgorithm,
        security_level: PqcSecurityLevel,
        fixture_mode: PqcFixtureMode,
    ) -> Self {
        Self {
            algorithm,
            security_level,
            fixture_mode,
        }
    }

    /// Convenience constructor for opaque ML-KEM fixtures.
    pub const fn opaque_ml_kem(security_level: PqcSecurityLevel) -> Self {
        Self::new(PqcAlgorithm::MlKem, security_level, PqcFixtureMode::Opaque)
    }

    /// Convenience constructor for opaque ML-DSA fixtures.
    pub const fn opaque_ml_dsa(security_level: PqcSecurityLevel) -> Self {
        Self::new(PqcAlgorithm::MlDsa, security_level, PqcFixtureMode::Opaque)
    }

    /// Algorithm family.
    pub const fn algorithm(&self) -> PqcAlgorithm {
        self.algorithm
    }

    /// Security level profile.
    pub const fn security_level(&self) -> PqcSecurityLevel {
        self.security_level
    }

    /// Fixture mode.
    pub const fn fixture_mode(&self) -> PqcFixtureMode {
        self.fixture_mode
    }

    /// Stable spec encoding for deterministic derivation and cache keys.
    pub const fn stable_bytes(&self) -> [u8; 3] {
        [
            match self.algorithm {
                PqcAlgorithm::MlKem => 1,
                PqcAlgorithm::MlDsa => 2,
            },
            match self.security_level {
                PqcSecurityLevel::L1 => 1,
                PqcSecurityLevel::L3 => 3,
                PqcSecurityLevel::L5 => 5,
            },
            match self.fixture_mode {
                PqcFixtureMode::Opaque => 0,
                PqcFixtureMode::Real => 1,
            },
        ]
    }
}

/// Error type for PQC fixture generation.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum PqcError {
    /// Real mode is intentionally not implemented yet.
    #[error("real PQC fixtures are not yet available; use fixture mode `Opaque`")]
    RealModeNotAvailable,
}

/// Private key material representation.
#[derive(Clone, Eq, PartialEq)]
pub enum PqcPrivateMaterial {
    /// Opaque byte vector; content is fixture-only and not real key material.
    OpaqueBytes(Vec<u8>),
    /// Handle-style placeholder for future backend-managed private keys.
    OpaqueHandle(String),
}

impl fmt::Debug for PqcPrivateMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpaqueBytes(bytes) => f
                .debug_struct("OpaqueBytes")
                .field("len", &bytes.len())
                .finish(),
            Self::OpaqueHandle(handle) => f
                .debug_struct("OpaqueHandle")
                .field("id", handle)
                .finish(),
        }
    }
}

/// Size-focused malformed vectors for parser and bounds testing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PqcMalformed {
    truncated_public: Vec<u8>,
    truncated_artifact: Vec<u8>,
    oversized_artifact: Vec<u8>,
}

impl PqcMalformed {
    /// Truncated public bytes (roughly half-size).
    pub fn truncated_public(&self) -> &[u8] {
        &self.truncated_public
    }

    /// Truncated primary artifact bytes.
    pub fn truncated_artifact(&self) -> &[u8] {
        &self.truncated_artifact
    }

    /// Oversized primary artifact bytes.
    pub fn oversized_artifact(&self) -> &[u8] {
        &self.oversized_artifact
    }
}

/// PQC test fixture payload.
#[derive(Clone)]
pub struct PqcFixture {
    label: String,
    spec: PqcSpec,
    inner: Arc<Inner>,
}

struct Inner {
    public_bytes: Vec<u8>,
    private_material: PqcPrivateMaterial,
    primary_artifact: Vec<u8>,
    test_vectors: Vec<Vec<u8>>,
    malformed: PqcMalformed,
}

impl fmt::Debug for PqcFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqcFixture")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .field("public_len", &self.inner.public_bytes.len())
            .field("artifact_len", &self.inner.primary_artifact.len())
            .finish_non_exhaustive()
    }
}

/// Extension trait to generate PQC-shaped fixtures from a core [`Factory`].
pub trait PqcFactoryExt {
    /// Generate a fixture with the default `"good"` variant.
    fn pqc(&self, label: impl AsRef<str>, spec: PqcSpec) -> Result<PqcFixture, PqcError>;

    /// Generate a fixture with an explicit deterministic variant.
    fn pqc_with_variant(
        &self,
        label: impl AsRef<str>,
        spec: PqcSpec,
        variant: impl AsRef<str>,
    ) -> Result<PqcFixture, PqcError>;
}

impl PqcFactoryExt for Factory {
    fn pqc(&self, label: impl AsRef<str>, spec: PqcSpec) -> Result<PqcFixture, PqcError> {
        self.pqc_with_variant(label, spec, "good")
    }

    fn pqc_with_variant(
        &self,
        label: impl AsRef<str>,
        spec: PqcSpec,
        variant: impl AsRef<str>,
    ) -> Result<PqcFixture, PqcError> {
        if spec.fixture_mode() == PqcFixtureMode::Real {
            return Err(PqcError::RealModeNotAvailable);
        }

        let label = label.as_ref();
        let variant = variant.as_ref();
        let inner = load_inner(self, label, spec, variant);

        Ok(PqcFixture {
            label: label.to_string(),
            spec,
            inner,
        })
    }
}

impl PqcFixture {
    /// Fixture label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Fixture spec.
    pub fn spec(&self) -> PqcSpec {
        self.spec
    }

    /// Public bytes.
    pub fn public_bytes(&self) -> &[u8] {
        &self.inner.public_bytes
    }

    /// Private bytes/handle representation.
    pub fn private_material(&self) -> &PqcPrivateMaterial {
        &self.inner.private_material
    }

    /// Primary artifact bytes (ciphertext for ML-KEM, signature for ML-DSA).
    pub fn primary_artifact(&self) -> &[u8] {
        &self.inner.primary_artifact
    }

    /// Kind name for the primary artifact.
    pub fn artifact_kind(&self) -> &'static str {
        match self.spec.algorithm() {
            PqcAlgorithm::MlKem => "ciphertext",
            PqcAlgorithm::MlDsa => "signature",
        }
    }

    /// Additional deterministic vectors useful for parser/buffer tests.
    pub fn test_vectors(&self) -> &[Vec<u8>] {
        &self.inner.test_vectors
    }

    /// Malformed size/truncation vectors.
    pub fn malformed(&self) -> &PqcMalformed {
        &self.inner.malformed
    }
}

fn load_inner(factory: &Factory, label: &str, spec: PqcSpec, variant: &str) -> Arc<Inner> {
    let mut spec_bytes = [0_u8; 4];
    let stable = spec.stable_bytes();
    spec_bytes[..3].copy_from_slice(&stable);
    spec_bytes[3] = 1;

    factory.get_or_init(DOMAIN_PQC_FIXTURE, label, &spec_bytes, variant, |seed| {
        let profile = SizeProfile::for_spec(spec);
        let mut seed = seed;

        let public_bytes = take(&mut seed, profile.public_len);
        let private_bytes = take(&mut seed, profile.private_len);
        let primary_artifact = take(&mut seed, profile.artifact_len);

        let test_vectors = vec![
            take(&mut seed, profile.vector_len),
            take(&mut seed, profile.vector_len + 17),
            take(&mut seed, profile.vector_len + 73),
        ];

        let malformed = PqcMalformed {
            truncated_public: truncate_half(&public_bytes),
            truncated_artifact: truncate_half(&primary_artifact),
            oversized_artifact: oversize(&primary_artifact, 33),
        };

        Inner {
            public_bytes,
            private_material: PqcPrivateMaterial::OpaqueBytes(private_bytes),
            primary_artifact,
            test_vectors,
            malformed,
        }
    })
}

fn take(seed: &mut uselesskey_core::Seed, len: usize) -> Vec<u8> {
    let mut out = vec![0_u8; len];
    seed.fill_bytes(&mut out);
    out
}

fn truncate_half(input: &[u8]) -> Vec<u8> {
    let len = (input.len() / 2).max(1);
    input[..len].to_vec()
}

fn oversize(input: &[u8], extra: usize) -> Vec<u8> {
    let mut out = input.to_vec();
    out.extend(std::iter::repeat_n(0xA5_u8, extra));
    out
}

#[derive(Clone, Copy)]
struct SizeProfile {
    public_len: usize,
    private_len: usize,
    artifact_len: usize,
    vector_len: usize,
}

impl SizeProfile {
    fn for_spec(spec: PqcSpec) -> Self {
        match (spec.algorithm(), spec.security_level()) {
            (PqcAlgorithm::MlKem, PqcSecurityLevel::L1) => Self {
                public_len: 1184,
                private_len: 2400,
                artifact_len: 1088,
                vector_len: 320,
            },
            (PqcAlgorithm::MlKem, PqcSecurityLevel::L3) => Self {
                public_len: 1568,
                private_len: 3168,
                artifact_len: 1568,
                vector_len: 512,
            },
            (PqcAlgorithm::MlKem, PqcSecurityLevel::L5) => Self {
                public_len: 1952,
                private_len: 3936,
                artifact_len: 1568,
                vector_len: 704,
            },
            (PqcAlgorithm::MlDsa, PqcSecurityLevel::L1) => Self {
                public_len: 1312,
                private_len: 2528,
                artifact_len: 2420,
                vector_len: 480,
            },
            (PqcAlgorithm::MlDsa, PqcSecurityLevel::L3) => Self {
                public_len: 1952,
                private_len: 4000,
                artifact_len: 3293,
                vector_len: 768,
            },
            (PqcAlgorithm::MlDsa, PqcSecurityLevel::L5) => Self {
                public_len: 2592,
                private_len: 4864,
                artifact_len: 4595,
                vector_len: 1024,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core::Seed;

    #[test]
    fn deterministic_regeneration_is_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("pqc-stable").unwrap());
        let spec = PqcSpec::opaque_ml_kem(PqcSecurityLevel::L3);

        let a = fx.pqc("tls-handshake", spec).expect("opaque fixture");
        let b = fx.pqc("tls-handshake", spec).expect("opaque fixture");

        assert_eq!(a.public_bytes(), b.public_bytes());
        assert_eq!(a.primary_artifact(), b.primary_artifact());
    }

    #[test]
    fn parser_size_bounds_are_large_and_consistent() {
        let fx = Factory::random();
        let spec = PqcSpec::opaque_ml_dsa(PqcSecurityLevel::L5);
        let fixture = fx.pqc("parser", spec).expect("opaque fixture");

        assert_eq!(fixture.artifact_kind(), "signature");
        assert!(fixture.public_bytes().len() >= 2500);
        assert!(fixture.primary_artifact().len() >= 4500);
        assert_eq!(fixture.test_vectors().len(), 3);
    }

    #[test]
    fn malformed_vectors_capture_truncation_and_oversize() {
        let fx = Factory::random();
        let fixture = fx
            .pqc("bounds", PqcSpec::opaque_ml_kem(PqcSecurityLevel::L1))
            .expect("opaque fixture");

        assert!(fixture.malformed().truncated_public().len() < fixture.public_bytes().len());
        assert!(
            fixture.malformed().truncated_artifact().len() < fixture.primary_artifact().len()
        );
        assert!(
            fixture.malformed().oversized_artifact().len() > fixture.primary_artifact().len()
        );
    }

    #[test]
    fn real_mode_is_explicitly_rejected() {
        let fx = Factory::random();
        let spec = PqcSpec::new(
            PqcAlgorithm::MlKem,
            PqcSecurityLevel::L3,
            PqcFixtureMode::Real,
        );

        let err = fx.pqc("interop", spec).expect_err("must reject real mode");
        assert_eq!(err, PqcError::RealModeNotAvailable);
    }

    #[test]
    fn stable_bytes_distinguish_specs() {
        let a = PqcSpec::opaque_ml_kem(PqcSecurityLevel::L1).stable_bytes();
        let b = PqcSpec::opaque_ml_dsa(PqcSecurityLevel::L1).stable_bytes();
        let c = PqcSpec::opaque_ml_kem(PqcSecurityLevel::L5).stable_bytes();

        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
