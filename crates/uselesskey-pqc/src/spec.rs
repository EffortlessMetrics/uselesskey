use std::fmt;

/// Candidate algorithms for PQC fixture generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqcAlgorithm {
    /// Key encapsulation mechanism family.
    MlKem,
    /// Signature family.
    MlDsa,
}

impl PqcAlgorithm {
    pub(crate) const fn as_tag(self) -> &'static str {
        match self {
            Self::MlKem => "ml-kem",
            Self::MlDsa => "ml-dsa",
        }
    }
}

/// NIST-style security levels used for sizing fixture vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqcSecurityLevel {
    L1,
    L3,
    L5,
}

impl PqcSecurityLevel {
    pub(crate) const fn as_tag(self) -> &'static str {
        match self {
            Self::L1 => "1",
            Self::L3 => "3",
            Self::L5 => "5",
        }
    }
}

/// Fixture mode. Opaque is implemented first; real backends are intentionally gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PqcFixtureMode {
    Opaque,
    Real,
}

impl PqcFixtureMode {
    pub(crate) const fn as_tag(self) -> &'static str {
        match self {
            Self::Opaque => "opaque",
            Self::Real => "real",
        }
    }
}

/// Controls PQC fixture generation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PqcSpec {
    pub algorithm: PqcAlgorithm,
    pub security_level: PqcSecurityLevel,
    pub fixture_mode: PqcFixtureMode,
}

impl fmt::Debug for PqcSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqcSpec")
            .field("algorithm", &self.algorithm)
            .field("security_level", &self.security_level)
            .field("fixture_mode", &self.fixture_mode)
            .finish()
    }
}

impl PqcSpec {
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

    pub const fn opaque(algorithm: PqcAlgorithm, security_level: PqcSecurityLevel) -> Self {
        Self::new(algorithm, security_level, PqcFixtureMode::Opaque)
    }

    pub const fn real(algorithm: PqcAlgorithm, security_level: PqcSecurityLevel) -> Self {
        Self::new(algorithm, security_level, PqcFixtureMode::Real)
    }

    pub(crate) fn stable_bytes(self) -> [u8; 32] {
        *blake3::hash(
            format!(
                "pqc|alg={}|sec={}|mode={}",
                self.algorithm.as_tag(),
                self.security_level.as_tag(),
                self.fixture_mode.as_tag(),
            )
            .as_bytes(),
        )
        .as_bytes()
    }
}
