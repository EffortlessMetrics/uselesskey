#![forbid(unsafe_code)]

//! Stable specification models for symmetric-key and AEAD vector fixtures.

/// Supported symmetric AEAD key algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SymmetricSpec {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl SymmetricSpec {
    pub const fn aes128_gcm() -> Self {
        Self::Aes128Gcm
    }

    pub const fn aes256_gcm() -> Self {
        Self::Aes256Gcm
    }

    pub const fn chacha20_poly1305() -> Self {
        Self::ChaCha20Poly1305
    }

    pub const fn algorithm_name(&self) -> &'static str {
        match self {
            Self::Aes128Gcm => "A128GCM",
            Self::Aes256Gcm => "A256GCM",
            Self::ChaCha20Poly1305 => "C20P",
        }
    }

    pub const fn key_len(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    pub const fn stable_bytes(&self) -> [u8; 4] {
        match self {
            Self::Aes128Gcm => [0, 0, 0, 1],
            Self::Aes256Gcm => [0, 0, 0, 2],
            Self::ChaCha20Poly1305 => [0, 0, 0, 3],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PlaintextMode {
    FixedBytes,
    JsonBody,
    RandomShape,
}

impl PlaintextMode {
    pub const fn stable_bytes(&self) -> [u8; 2] {
        match self {
            Self::FixedBytes => [0, 1],
            Self::JsonBody => [0, 2],
            Self::RandomShape => [0, 3],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AadMode {
    None,
    FixedBytes,
    RandomShape,
}

impl AadMode {
    pub const fn stable_bytes(&self) -> [u8; 2] {
        match self {
            Self::None => [0, 1],
            Self::FixedBytes => [0, 2],
            Self::RandomShape => [0, 3],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum NoncePolicy {
    Derived,
    Explicit,
}

impl NoncePolicy {
    pub const fn stable_bytes(&self) -> [u8; 2] {
        match self {
            Self::Derived => [0, 1],
            Self::Explicit => [0, 2],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AeadVectorSpec {
    pub plaintext_mode: PlaintextMode,
    pub aad_mode: AadMode,
    pub nonce_policy: NoncePolicy,
}

impl AeadVectorSpec {
    pub const fn new(
        plaintext_mode: PlaintextMode,
        aad_mode: AadMode,
        nonce_policy: NoncePolicy,
    ) -> Self {
        Self {
            plaintext_mode,
            aad_mode,
            nonce_policy,
        }
    }

    pub const fn stable_bytes(&self) -> [u8; 6] {
        let p = self.plaintext_mode.stable_bytes();
        let a = self.aad_mode.stable_bytes();
        let n = self.nonce_policy.stable_bytes();
        [p[0], p[1], a[0], a[1], n[0], n[1]]
    }
}
