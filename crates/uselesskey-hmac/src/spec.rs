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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alg_name_and_len_match_spec() {
        let hs256 = HmacSpec::hs256();
        assert_eq!(hs256.alg_name(), "HS256");
        assert_eq!(hs256.byte_len(), 32);

        let hs384 = HmacSpec::hs384();
        assert_eq!(hs384.alg_name(), "HS384");
        assert_eq!(hs384.byte_len(), 48);

        let hs512 = HmacSpec::hs512();
        assert_eq!(hs512.alg_name(), "HS512");
        assert_eq!(hs512.byte_len(), 64);
    }

    #[test]
    fn stable_bytes_are_unique() {
        let hs256 = HmacSpec::hs256().stable_bytes();
        let hs384 = HmacSpec::hs384().stable_bytes();
        let hs512 = HmacSpec::hs512().stable_bytes();

        assert_ne!(hs256, hs384);
        assert_ne!(hs256, hs512);
        assert_ne!(hs384, hs512);
    }
}
