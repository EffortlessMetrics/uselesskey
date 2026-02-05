/// Specification for HMAC secret generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum HmacSpec {
    /// HS256 (HMAC-SHA256)
    Hs256,
    /// HS384 (HMAC-SHA384)
    Hs384,
    /// HS512 (HMAC-SHA512)
    Hs512,
}

impl HmacSpec {
    pub fn hs256() -> Self {
        Self::Hs256
    }

    pub fn hs384() -> Self {
        Self::Hs384
    }

    pub fn hs512() -> Self {
        Self::Hs512
    }

    pub fn alg_name(&self) -> &'static str {
        match self {
            Self::Hs256 => "HS256",
            Self::Hs384 => "HS384",
            Self::Hs512 => "HS512",
        }
    }

    pub fn byte_len(&self) -> usize {
        match self {
            Self::Hs256 => 32,
            Self::Hs384 => 48,
            Self::Hs512 => 64,
        }
    }

    /// Stable encoding for cache keys / deterministic derivation.
    ///
    /// If you change this, bump the derivation version in `uselesskey-core`.
    pub fn stable_bytes(&self) -> [u8; 4] {
        match self {
            Self::Hs256 => [0, 0, 0, 1],
            Self::Hs384 => [0, 0, 0, 2],
            Self::Hs512 => [0, 0, 0, 3],
        }
    }
}
