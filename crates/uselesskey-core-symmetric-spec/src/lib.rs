#![forbid(unsafe_code)]

//! Core symmetric fixture specification models.

/// Symmetric encryption algorithms supported by fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SymmetricSpec {
    /// AES-128-GCM
    Aes128Gcm,
    /// AES-256-GCM
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
}

impl SymmetricSpec {
    /// AES-128-GCM.
    pub fn aes128_gcm() -> Self {
        Self::Aes128Gcm
    }

    /// AES-256-GCM.
    pub fn aes256_gcm() -> Self {
        Self::Aes256Gcm
    }

    /// ChaCha20-Poly1305.
    pub fn chacha20_poly1305() -> Self {
        Self::ChaCha20Poly1305
    }

    /// JOSE-style algorithm name.
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::Aes128Gcm => "A128GCM",
            Self::Aes256Gcm => "A256GCM",
            Self::ChaCha20Poly1305 => "C20P",
        }
    }

    /// Symmetric key length in bytes.
    pub fn key_len(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    /// Nonce length in bytes used by all currently supported AEAD algorithms.
    pub fn nonce_len(&self) -> usize {
        12
    }

    /// Stable encoding for deterministic derivation and cache identity.
    pub fn stable_bytes(&self) -> [u8; 4] {
        match self {
            Self::Aes128Gcm => [0, 0, 0, 1],
            Self::Aes256Gcm => [0, 0, 0, 2],
            Self::ChaCha20Poly1305 => [0, 0, 0, 3],
        }
    }
}

/// Controls how plaintext is shaped for an AEAD vector fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PlaintextMode {
    /// Small fixed byte payload.
    FixedBytes,
    /// Stable JSON body payload.
    JsonBody,
    /// Deterministic pseudo-random byte payload.
    RandomShape,
}

impl PlaintextMode {
    fn stable_tag(self) -> u8 {
        match self {
            Self::FixedBytes => 1,
            Self::JsonBody => 2,
            Self::RandomShape => 3,
        }
    }
}

/// Controls how AEAD additional authenticated data is shaped.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AadMode {
    /// No AAD.
    None,
    /// Small fixed byte AAD.
    FixedBytes,
    /// Deterministic pseudo-random byte AAD.
    RandomShape,
}

impl AadMode {
    fn stable_tag(self) -> u8 {
        match self {
            Self::None => 0,
            Self::FixedBytes => 1,
            Self::RandomShape => 2,
        }
    }
}

/// Controls nonce selection for AEAD vector fixtures.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum NoncePolicy {
    /// Derive nonce deterministically from fixture identity.
    Derived,
    /// Use this explicit nonce value.
    Explicit(Vec<u8>),
}

impl NoncePolicy {
    fn stable_bytes(&self, out: &mut Vec<u8>) {
        match self {
            Self::Derived => out.extend_from_slice(&[0]),
            Self::Explicit(bytes) => {
                out.extend_from_slice(&[1, bytes.len() as u8]);
                out.extend_from_slice(bytes);
            }
        }
    }
}

/// Spec for deterministic AEAD vector fixtures.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AeadVectorSpec {
    /// The symmetric algorithm used for encryption.
    pub algorithm: SymmetricSpec,
    /// Plaintext shaping mode.
    pub plaintext_mode: PlaintextMode,
    /// AAD shaping mode.
    pub aad_mode: AadMode,
    /// Nonce derivation policy.
    pub nonce_policy: NoncePolicy,
}

impl AeadVectorSpec {
    /// Construct a new AEAD vector spec.
    pub fn new(
        algorithm: SymmetricSpec,
        plaintext_mode: PlaintextMode,
        aad_mode: AadMode,
        nonce_policy: NoncePolicy,
    ) -> Self {
        Self {
            algorithm,
            plaintext_mode,
            aad_mode,
            nonce_policy,
        }
    }

    /// Stable encoding for deterministic derivation and cache identity.
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(&self.algorithm.stable_bytes());
        out.push(self.plaintext_mode.stable_tag());
        out.push(self.aad_mode.stable_tag());
        self.nonce_policy.stable_bytes(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_specs_have_unique_stable_bytes() {
        assert_ne!(
            SymmetricSpec::aes128_gcm().stable_bytes(),
            SymmetricSpec::aes256_gcm().stable_bytes()
        );
        assert_ne!(
            SymmetricSpec::aes128_gcm().stable_bytes(),
            SymmetricSpec::chacha20_poly1305().stable_bytes()
        );
        assert_ne!(
            SymmetricSpec::aes256_gcm().stable_bytes(),
            SymmetricSpec::chacha20_poly1305().stable_bytes()
        );
    }

    #[test]
    fn aead_spec_fingerprint_changes_with_nonce_policy() {
        let derived = AeadVectorSpec::new(
            SymmetricSpec::aes256_gcm(),
            PlaintextMode::JsonBody,
            AadMode::FixedBytes,
            NoncePolicy::Derived,
        );
        let explicit = AeadVectorSpec::new(
            SymmetricSpec::aes256_gcm(),
            PlaintextMode::JsonBody,
            AadMode::FixedBytes,
            NoncePolicy::Explicit(vec![7u8; 12]),
        );
        assert_ne!(derived.stable_bytes(), explicit.stable_bytes());
    }
}
