#![forbid(unsafe_code)]

//! Experimental PQC-shaped fixtures for parser and buffer testing.
//!
//! This crate is intentionally conservative:
//! - defaults to opaque, deterministic byte fixtures
//! - supports size/truncation negatives for robustness tests
//! - does not claim production-ready PQC support
//! - reserves real algorithm integration for future backend maturity

use std::sync::Arc;

use uselesskey_core::{ArtifactDomain, Factory};

/// Artifact domain for PQC fixture derivation and cache identity.
pub const DOMAIN_PQC_FIXTURE: ArtifactDomain = "pqc_fixture";

/// PQC algorithm family represented by fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PqcAlgorithm {
    /// NIST ML-KEM (Kyber lineage).
    MlKem,
    /// NIST ML-DSA (Dilithium lineage).
    MlDsa,
}

impl PqcAlgorithm {
    const fn stable_tag(self) -> u8 {
        match self {
            Self::MlKem => 1,
            Self::MlDsa => 2,
        }
    }
}

/// Security level grouping for PQC fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PqcSecurityLevel {
    /// NIST level 1 equivalent profile.
    Level1,
    /// NIST level 3 equivalent profile.
    Level3,
    /// NIST level 5 equivalent profile.
    Level5,
}

impl PqcSecurityLevel {
    const fn stable_tag(self) -> u8 {
        match self {
            Self::Level1 => 1,
            Self::Level3 => 3,
            Self::Level5 => 5,
        }
    }
}

/// Fixture generation mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FixtureMode {
    /// Deterministic opaque vectors for parser/size testing.
    Opaque,
    /// Reserved for future real ML-KEM/ML-DSA backends.
    Real,
}

impl FixtureMode {
    const fn stable_tag(self) -> u8 {
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
    pub fixture_mode: FixtureMode,
}

impl PqcSpec {
    pub const fn ml_kem_level1(fixture_mode: FixtureMode) -> Self {
        Self {
            algorithm: PqcAlgorithm::MlKem,
            security_level: PqcSecurityLevel::Level1,
            fixture_mode,
        }
    }

    pub const fn ml_kem_level3(fixture_mode: FixtureMode) -> Self {
        Self {
            algorithm: PqcAlgorithm::MlKem,
            security_level: PqcSecurityLevel::Level3,
            fixture_mode,
        }
    }

    pub const fn ml_kem_level5(fixture_mode: FixtureMode) -> Self {
        Self {
            algorithm: PqcAlgorithm::MlKem,
            security_level: PqcSecurityLevel::Level5,
            fixture_mode,
        }
    }

    pub const fn ml_dsa_level1(fixture_mode: FixtureMode) -> Self {
        Self {
            algorithm: PqcAlgorithm::MlDsa,
            security_level: PqcSecurityLevel::Level1,
            fixture_mode,
        }
    }

    pub const fn ml_dsa_level3(fixture_mode: FixtureMode) -> Self {
        Self {
            algorithm: PqcAlgorithm::MlDsa,
            security_level: PqcSecurityLevel::Level3,
            fixture_mode,
        }
    }

    pub const fn ml_dsa_level5(fixture_mode: FixtureMode) -> Self {
        Self {
            algorithm: PqcAlgorithm::MlDsa,
            security_level: PqcSecurityLevel::Level5,
            fixture_mode,
        }
    }

    /// Stable encoding for deterministic derivation and cache keys.
    pub const fn stable_bytes(self) -> [u8; 3] {
        [
            self.algorithm.stable_tag(),
            self.security_level.stable_tag(),
            self.fixture_mode.stable_tag(),
        ]
    }
}

/// Negative fixture variants for parser and bounds-check testing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PqcNegative {
    /// Truncate public key bytes to `len`.
    TruncatePublic { len: usize },
    /// Truncate private key bytes to `len`.
    TruncatePrivate { len: usize },
    /// Truncate signature bytes to `len`.
    TruncateSignature { len: usize },
    /// Truncate ciphertext bytes to `len`.
    TruncateCiphertext { len: usize },
    /// Force wrong-size signature by extending/shrinking with `delta`.
    WrongSizeSignature { delta: isize },
}

/// Private material representation for PQC fixtures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PqcPrivateMaterial {
    /// Raw private bytes for fixture-level parser tests.
    Bytes(Vec<u8>),
    /// Opaque handle for workflows that should avoid byte exposure.
    OpaqueHandle(String),
}

/// Output fixture with large-bytes artifacts and optional vectors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PqcFixture {
    pub algorithm: PqcAlgorithm,
    pub security_level: PqcSecurityLevel,
    pub fixture_mode: FixtureMode,
    pub public_bytes: Vec<u8>,
    pub private_material: PqcPrivateMaterial,
    pub ciphertext: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    /// Additional deterministic vectors to drive parser suites.
    pub test_vectors: Vec<Vec<u8>>,
}

/// Extension trait for generating PQC fixtures from [`Factory`].
pub trait PqcFactoryExt {
    /// Generate (and cache) a deterministic PQC fixture for `label + spec`.
    fn pqc(&self, label: &str, spec: PqcSpec) -> Arc<PqcFixture>;

    /// Generate a deterministic negative variant derived from `label + spec + negative`.
    fn pqc_negative(&self, label: &str, spec: PqcSpec, negative: PqcNegative) -> Arc<PqcFixture>;
}

impl PqcFactoryExt for Factory {
    fn pqc(&self, label: &str, spec: PqcSpec) -> Arc<PqcFixture> {
        self.get_or_init(
            DOMAIN_PQC_FIXTURE,
            label,
            &spec.stable_bytes(),
            "default",
            |seed| generate_fixture(seed.bytes(), spec),
        )
    }

    fn pqc_negative(&self, label: &str, spec: PqcSpec, negative: PqcNegative) -> Arc<PqcFixture> {
        let mut spec_bytes = Vec::from(spec.stable_bytes());
        spec_bytes.extend_from_slice(negative_variant_tag(negative).as_bytes());
        self.get_or_init(DOMAIN_PQC_FIXTURE, label, &spec_bytes, "negative", |seed| {
            let mut fixture = generate_fixture(seed.bytes(), spec);
            apply_negative(&mut fixture, negative);
            fixture
        })
    }
}

fn generate_fixture(seed: &[u8; 32], spec: PqcSpec) -> PqcFixture {
    // Sizes chosen to stress parser and buffer boundaries without claiming
    // exact conformance to production backend encodings.
    let sizes = size_profile(spec.algorithm, spec.security_level);
    let public_bytes = expand_bytes(seed, b"public", sizes.public_len);
    let private_bytes = expand_bytes(seed, b"private", sizes.private_len);
    let ciphertext = sizes
        .ciphertext_len
        .map(|len| expand_bytes(seed, b"ciphertext", len));
    let signature = sizes
        .signature_len
        .map(|len| expand_bytes(seed, b"signature", len));

    let private_material = match spec.fixture_mode {
        FixtureMode::Opaque => {
            let handle = blake3::keyed_hash(seed, b"opaque-private-handle");
            PqcPrivateMaterial::OpaqueHandle(format!("uk_pqc_{}", &handle.to_hex()[..24]))
        }
        FixtureMode::Real => {
            // Reserved mode for future algorithm-backed integrations.
            // Currently still deterministic pseudo-bytes.
            PqcPrivateMaterial::Bytes(private_bytes)
        }
    };

    let test_vectors = vec![
        expand_bytes(seed, b"vector-0", 64),
        expand_bytes(seed, b"vector-1", 128),
        expand_bytes(seed, b"vector-2", 192),
    ];

    PqcFixture {
        algorithm: spec.algorithm,
        security_level: spec.security_level,
        fixture_mode: spec.fixture_mode,
        public_bytes,
        private_material,
        ciphertext,
        signature,
        test_vectors,
    }
}

fn negative_variant_tag(negative: PqcNegative) -> String {
    match negative {
        PqcNegative::TruncatePublic { len } => format!("truncate_public:{len}"),
        PqcNegative::TruncatePrivate { len } => format!("truncate_private:{len}"),
        PqcNegative::TruncateSignature { len } => format!("truncate_signature:{len}"),
        PqcNegative::TruncateCiphertext { len } => format!("truncate_ciphertext:{len}"),
        PqcNegative::WrongSizeSignature { delta } => format!("wrong_sig_size:{delta}"),
    }
}

fn apply_negative(fixture: &mut PqcFixture, negative: PqcNegative) {
    match negative {
        PqcNegative::TruncatePublic { len } => {
            fixture.public_bytes.truncate(len);
        }
        PqcNegative::TruncatePrivate { len } => {
            if let PqcPrivateMaterial::Bytes(bytes) = &mut fixture.private_material {
                bytes.truncate(len);
            }
        }
        PqcNegative::TruncateSignature { len } => {
            if let Some(sig) = &mut fixture.signature {
                sig.truncate(len);
            }
        }
        PqcNegative::TruncateCiphertext { len } => {
            if let Some(ct) = &mut fixture.ciphertext {
                ct.truncate(len);
            }
        }
        PqcNegative::WrongSizeSignature { delta } => {
            if let Some(sig) = &mut fixture.signature {
                if delta.is_negative() {
                    sig.truncate(sig.len().saturating_sub(delta.unsigned_abs()));
                } else {
                    sig.resize(sig.len() + delta as usize, 0xA5);
                }
            }
        }
    }
}

struct SizeProfile {
    public_len: usize,
    private_len: usize,
    ciphertext_len: Option<usize>,
    signature_len: Option<usize>,
}

fn size_profile(algorithm: PqcAlgorithm, level: PqcSecurityLevel) -> SizeProfile {
    match (algorithm, level) {
        (PqcAlgorithm::MlKem, PqcSecurityLevel::Level1) => SizeProfile {
            public_len: 800,
            private_len: 1632,
            ciphertext_len: Some(768),
            signature_len: None,
        },
        (PqcAlgorithm::MlKem, PqcSecurityLevel::Level3) => SizeProfile {
            public_len: 1184,
            private_len: 2400,
            ciphertext_len: Some(1088),
            signature_len: None,
        },
        (PqcAlgorithm::MlKem, PqcSecurityLevel::Level5) => SizeProfile {
            public_len: 1568,
            private_len: 3168,
            ciphertext_len: Some(1568),
            signature_len: None,
        },
        (PqcAlgorithm::MlDsa, PqcSecurityLevel::Level1) => SizeProfile {
            public_len: 1312,
            private_len: 2528,
            ciphertext_len: None,
            signature_len: Some(2420),
        },
        (PqcAlgorithm::MlDsa, PqcSecurityLevel::Level3) => SizeProfile {
            public_len: 1952,
            private_len: 4000,
            ciphertext_len: None,
            signature_len: Some(3293),
        },
        (PqcAlgorithm::MlDsa, PqcSecurityLevel::Level5) => SizeProfile {
            public_len: 2592,
            private_len: 4864,
            ciphertext_len: None,
            signature_len: Some(4595),
        },
    }
}

fn expand_bytes(seed: &[u8; 32], namespace: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u32;

    while out.len() < len {
        let mut block_input = Vec::with_capacity(namespace.len() + 4);
        block_input.extend_from_slice(namespace);
        block_input.extend_from_slice(&counter.to_be_bytes());
        let block = blake3::keyed_hash(seed, &block_input);
        out.extend_from_slice(block.as_bytes());
        counter = counter.wrapping_add(1);
    }

    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core::Factory;

    #[test]
    fn deterministic_regeneration_is_stable_for_same_inputs() {
        let fx = Factory::deterministic_from_str("pqc-seed");
        let spec = PqcSpec::ml_kem_level3(FixtureMode::Opaque);

        let a = fx.pqc("server-kem", spec);
        let b = fx.pqc("server-kem", spec);

        assert_eq!(*a, *b);
    }

    #[test]
    fn parser_size_bounds_have_large_artifacts() {
        let fx = Factory::deterministic_from_str("size-bounds");

        let kem = fx.pqc("kem", PqcSpec::ml_kem_level5(FixtureMode::Opaque));
        assert!(kem.public_bytes.len() >= 1500);
        assert_eq!(kem.ciphertext.as_ref().map(Vec::len), Some(1568));

        let dsa = fx.pqc("sig", PqcSpec::ml_dsa_level5(FixtureMode::Real));
        assert!(dsa.public_bytes.len() >= 2500);
        assert_eq!(dsa.signature.as_ref().map(Vec::len), Some(4595));
    }

    #[test]
    fn truncation_negative_reduces_lengths() {
        let fx = Factory::deterministic_from_str("negatives");
        let spec = PqcSpec::ml_dsa_level3(FixtureMode::Real);

        let base = fx.pqc("signer", spec);
        let neg = fx.pqc_negative("signer", spec, PqcNegative::TruncateSignature { len: 64 });

        assert!(base.signature.as_ref().is_some_and(|v| v.len() > 64));
        assert_eq!(neg.signature.as_ref().map(Vec::len), Some(64));
    }

    #[test]
    fn wrong_size_signature_is_deterministic() {
        let fx = Factory::deterministic_from_str("wrong-size");
        let spec = PqcSpec::ml_dsa_level1(FixtureMode::Real);

        let a = fx.pqc_negative("sig", spec, PqcNegative::WrongSizeSignature { delta: 11 });
        let b = fx.pqc_negative("sig", spec, PqcNegative::WrongSizeSignature { delta: 11 });
        assert_eq!(
            a.signature.as_ref().map(Vec::len),
            b.signature.as_ref().map(Vec::len)
        );
    }

    #[test]
    fn size_profile_values_are_stable_for_planning() {
        let fx = Factory::deterministic_from_str("interop-planning");
        let kem = fx.pqc("kem", PqcSpec::ml_kem_level3(FixtureMode::Opaque));
        let dsa = fx.pqc("dsa", PqcSpec::ml_dsa_level3(FixtureMode::Real));

        assert_eq!(kem.public_bytes.len(), 1184);
        assert_eq!(kem.ciphertext.as_ref().map(Vec::len), Some(1088));
        assert_eq!(dsa.public_bytes.len(), 1952);
        assert_eq!(dsa.signature.as_ref().map(Vec::len), Some(3293));
    }
}
