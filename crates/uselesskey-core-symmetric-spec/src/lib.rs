#![forbid(unsafe_code)]

//! Stable symmetric fixture specification models.
//!
//! These specs are consumed by fixture crates (for example `uselesskey-symmetric`)
//! and are designed to participate in deterministic cache fingerprints.

use serde_json::{Map, Value, json};

/// Supported symmetric AEAD algorithms for fixtures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SymmetricSpec {
    /// AES-128-GCM (`A128GCM`)
    Aes128Gcm,
    /// AES-256-GCM (`A256GCM`)
    Aes256Gcm,
    /// ChaCha20-Poly1305 (`C20P`)
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

    /// JOSE `enc`-like algorithm name.
    pub const fn algorithm_name(&self) -> &'static str {
        match self {
            Self::Aes128Gcm => "A128GCM",
            Self::Aes256Gcm => "A256GCM",
            Self::ChaCha20Poly1305 => "C20P",
        }
    }

    /// Symmetric key size in bytes.
    pub const fn key_len(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    /// Nonce size in bytes.
    pub const fn nonce_len(&self) -> usize {
        12
    }

    /// Stable encoding for deterministic derivation and cache keys.
    pub const fn stable_bytes(&self) -> [u8; 4] {
        match self {
            Self::Aes128Gcm => [0, 0, 0, 1],
            Self::Aes256Gcm => [0, 0, 0, 2],
            Self::ChaCha20Poly1305 => [0, 0, 0, 3],
        }
    }
}

/// Plaintext mode for AEAD vector generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PlaintextMode {
    /// Fixed deterministic bytes.
    FixedBytes,
    /// A deterministic JSON object serialized to UTF-8.
    JsonBody,
    /// Random bytes generated from the derived seed.
    RandomShape,
}

impl PlaintextMode {
    /// Stable single-byte ID for fingerprinting.
    pub const fn stable_byte(&self) -> u8 {
        match self {
            Self::FixedBytes => 1,
            Self::JsonBody => 2,
            Self::RandomShape => 3,
        }
    }
}

/// Additional authenticated data generation mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AadMode {
    /// No AAD.
    None,
    /// Deterministic fixed bytes.
    FixedBytes,
    /// Deterministic JSON bytes.
    JsonBody,
}

impl AadMode {
    /// Stable single-byte ID for fingerprinting.
    pub const fn stable_byte(&self) -> u8 {
        match self {
            Self::None => 1,
            Self::FixedBytes => 2,
            Self::JsonBody => 3,
        }
    }
}

/// Nonce source policy for AEAD vectors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum NoncePolicy {
    /// Derive nonce from fixture seed.
    Derived,
    /// Use explicit nonce provided by caller.
    Explicit,
}

impl NoncePolicy {
    /// Stable single-byte ID for fingerprinting.
    pub const fn stable_byte(&self) -> u8 {
        match self {
            Self::Derived => 1,
            Self::Explicit => 2,
        }
    }
}

/// AEAD vector generation spec.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AeadVectorSpec {
    /// Plaintext generation mode.
    pub plaintext_mode: PlaintextMode,
    /// AAD generation mode.
    pub aad_mode: AadMode,
    /// Nonce derivation policy.
    pub nonce_policy: NoncePolicy,
    /// Explicit nonce bytes when `nonce_policy` is [`NoncePolicy::Explicit`].
    pub explicit_nonce: Option<Vec<u8>>,
}

impl AeadVectorSpec {
    /// Baseline vector spec: fixed plaintext, no aad, derived nonce.
    pub fn baseline() -> Self {
        Self {
            plaintext_mode: PlaintextMode::FixedBytes,
            aad_mode: AadMode::None,
            nonce_policy: NoncePolicy::Derived,
            explicit_nonce: None,
        }
    }

    /// Stable fingerprint bytes for this vector spec.
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.explicit_nonce.as_ref().map_or(0, Vec::len));
        out.extend_from_slice(&[0, 0, 1, 0]);
        out.push(self.plaintext_mode.stable_byte());
        out.push(self.aad_mode.stable_byte());
        out.push(self.nonce_policy.stable_byte());
        if let Some(nonce) = &self.explicit_nonce {
            out.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
            out.extend_from_slice(nonce);
        } else {
            out.extend_from_slice(&0u32.to_be_bytes());
        }
        out
    }

    /// Deterministic metadata JSON used by fixture generators.
    pub fn metadata_json(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("plaintext_mode".to_string(), json!(format!("{:?}", self.plaintext_mode)));
        obj.insert("aad_mode".to_string(), json!(format!("{:?}", self.aad_mode)));
        obj.insert("nonce_policy".to_string(), json!(format!("{:?}", self.nonce_policy)));
        if let Some(nonce) = &self.explicit_nonce {
            obj.insert("explicit_nonce_len".to_string(), json!(nonce.len()));
        }
        Value::Object(obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_specs_have_unique_stable_bytes() {
        let a = SymmetricSpec::aes128_gcm().stable_bytes();
        let b = SymmetricSpec::aes256_gcm().stable_bytes();
        let c = SymmetricSpec::chacha20_poly1305().stable_bytes();

        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn vector_spec_fingerprint_includes_nonce_policy_and_explicit_bytes() {
        let derived = AeadVectorSpec::baseline();

        let explicit = AeadVectorSpec {
            nonce_policy: NoncePolicy::Explicit,
            explicit_nonce: Some(vec![1, 2, 3, 4]),
            ..AeadVectorSpec::baseline()
        };

        assert_ne!(derived.stable_bytes(), explicit.stable_bytes());
    }
}
