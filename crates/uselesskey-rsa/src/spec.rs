#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RsaSpec {
    pub bits: usize,
    pub exponent: u32,
}

impl RsaSpec {
    /// Spec suitable for RS256 JWT signing in most ecosystems.
    pub fn rs256() -> Self {
        Self {
            bits: 2048,
            exponent: 65537,
        }
    }

    pub fn new(bits: usize) -> Self {
        Self {
            bits,
            exponent: 65537,
        }
    }

    /// Stable encoding for cache keys / deterministic derivation.
    ///
    /// If you change this, bump the derivation version in `uselesskey-core`.
    pub fn stable_bytes(&self) -> [u8; 8] {
        let bits = u32::try_from(self.bits).unwrap_or(u32::MAX);
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&bits.to_be_bytes());
        out[4..].copy_from_slice(&self.exponent.to_be_bytes());
        out
    }
}
