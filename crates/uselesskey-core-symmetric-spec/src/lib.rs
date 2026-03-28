#![forbid(unsafe_code)]

//! Stable symmetric and AEAD vector specifications for deterministic fixtures.

extern crate alloc;

use alloc::vec::Vec;

/// Symmetric algorithm selection for fixture generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SymmetricSpec {
    /// AES-128-GCM (`A128GCM`).
    Aes128Gcm,
    /// AES-256-GCM (`A256GCM`).
    Aes256Gcm,
    /// ChaCha20-Poly1305 (`C20P`).
    ChaCha20Poly1305,
}

impl SymmetricSpec {
    /// AES-128-GCM.
    pub const fn aes128_gcm() -> Self {
        Self::Aes128Gcm
    }

    /// AES-256-GCM.
    pub const fn aes256_gcm() -> Self {
        Self::Aes256Gcm
    }

    /// ChaCha20-Poly1305.
    pub const fn chacha20_poly1305() -> Self {
        Self::ChaCha20Poly1305
    }

    /// JOSE `enc`/algorithm string used by this symmetric algorithm.
    pub const fn algorithm_name(&self) -> &'static str {
        match self {
            Self::Aes128Gcm => "A128GCM",
            Self::Aes256Gcm => "A256GCM",
            Self::ChaCha20Poly1305 => "C20P",
        }
    }

    /// Secret key length in bytes.
    pub const fn key_len(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    /// Nonce length in bytes.
    pub const fn nonce_len(&self) -> usize {
        12
    }

    /// Stable encoding for deterministic derivation/cache keys.
    pub const fn stable_bytes(&self) -> [u8; 4] {
        match self {
            Self::Aes128Gcm => [0, 0, 0, 1],
            Self::Aes256Gcm => [0, 0, 0, 2],
            Self::ChaCha20Poly1305 => [0, 0, 0, 3],
        }
    }
}

/// Controls how AEAD plaintext is generated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PlaintextMode {
    /// Use caller-provided bytes.
    FixedBytes,
    /// Deterministic JSON body generated from fixture identity.
    JsonBody,
    /// Random-shaped deterministic bytes.
    RandomShape,
}

impl PlaintextMode {
    pub const fn stable_byte(&self) -> u8 {
        match self {
            Self::FixedBytes => 1,
            Self::JsonBody => 2,
            Self::RandomShape => 3,
        }
    }
}

/// Controls how AEAD additional authenticated data is generated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AadMode {
    /// Empty AAD.
    None,
    /// Deterministic ASCII AAD.
    Standard,
    /// Use caller-provided bytes.
    FixedBytes,
}

impl AadMode {
    pub const fn stable_byte(&self) -> u8 {
        match self {
            Self::None => 1,
            Self::Standard => 2,
            Self::FixedBytes => 3,
        }
    }
}

/// Controls nonce selection for AEAD vectors.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum NoncePolicy {
    /// Derive nonce from artifact identity.
    Derived,
    /// Use exact nonce bytes.
    Explicit(Vec<u8>),
}

impl NoncePolicy {
    pub fn stable_bytes(&self) -> Vec<u8> {
        match self {
            Self::Derived => vec![1],
            Self::Explicit(nonce) => {
                let mut out = Vec::with_capacity(1 + 4 + nonce.len());
                out.push(2);
                out.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
                out.extend_from_slice(nonce);
                out
            }
        }
    }
}

/// Stable specification for generating deterministic AEAD vectors.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AeadVectorSpec {
    /// Symmetric algorithm used for encryption.
    pub algorithm: SymmetricSpec,
    /// Plaintext generation mode.
    pub plaintext_mode: PlaintextMode,
    /// AAD generation mode.
    pub aad_mode: AadMode,
    /// Nonce policy.
    pub nonce_policy: NoncePolicy,
    /// Optional fixed plaintext bytes used when `plaintext_mode` is `FixedBytes`.
    pub fixed_plaintext: Option<Vec<u8>>,
    /// Optional fixed AAD bytes used when `aad_mode` is `FixedBytes`.
    pub fixed_aad: Option<Vec<u8>>,
}

impl AeadVectorSpec {
    /// Create a new vector spec for `algorithm` with deterministic derived nonce.
    pub fn new(algorithm: SymmetricSpec) -> Self {
        Self {
            algorithm,
            plaintext_mode: PlaintextMode::RandomShape,
            aad_mode: AadMode::Standard,
            nonce_policy: NoncePolicy::Derived,
            fixed_plaintext: None,
            fixed_aad: None,
        }
    }

    /// Stable encoding for deterministic derivation/cache keys.
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.algorithm.stable_bytes());
        out.push(self.plaintext_mode.stable_byte());
        out.push(self.aad_mode.stable_byte());

        let nonce = self.nonce_policy.stable_bytes();
        out.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
        out.extend_from_slice(&nonce);

        encode_optional_bytes(&mut out, self.fixed_plaintext.as_deref());
        encode_optional_bytes(&mut out, self.fixed_aad.as_deref());
        out
    }
}

fn encode_optional_bytes(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(bytes) => {
            out.push(1);
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        None => out.push(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_spec_lengths_are_expected() {
        assert_eq!(SymmetricSpec::aes128_gcm().key_len(), 16);
        assert_eq!(SymmetricSpec::aes256_gcm().key_len(), 32);
        assert_eq!(SymmetricSpec::chacha20_poly1305().key_len(), 32);
        assert_eq!(SymmetricSpec::aes128_gcm().nonce_len(), 12);
    }

    #[test]
    fn symmetric_spec_stable_bytes_are_unique() {
        let a = SymmetricSpec::aes128_gcm().stable_bytes();
        let b = SymmetricSpec::aes256_gcm().stable_bytes();
        let c = SymmetricSpec::chacha20_poly1305().stable_bytes();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn aead_vector_stable_bytes_change_with_nonce_policy() {
        let mut derived = AeadVectorSpec::new(SymmetricSpec::aes256_gcm());
        derived.nonce_policy = NoncePolicy::Derived;

        let mut explicit = AeadVectorSpec::new(SymmetricSpec::aes256_gcm());
        explicit.nonce_policy = NoncePolicy::Explicit(vec![7; 12]);

        assert_ne!(derived.stable_bytes(), explicit.stable_bytes());
    }
}
