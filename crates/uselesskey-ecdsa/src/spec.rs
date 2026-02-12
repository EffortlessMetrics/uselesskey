/// ECDSA algorithm specification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EcdsaSpec {
    /// P-256 / secp256r1 / prime256v1 (for ES256 JWT signing).
    Es256,
    /// P-384 / secp384r1 (for ES384 JWT signing).
    Es384,
}

impl EcdsaSpec {
    /// Spec suitable for ES256 JWT signing.
    pub fn es256() -> Self {
        Self::Es256
    }

    /// Spec suitable for ES384 JWT signing.
    pub fn es384() -> Self {
        Self::Es384
    }

    /// Returns the JWT algorithm name.
    pub fn alg_name(&self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
        }
    }

    /// Returns the curve name.
    pub fn curve_name(&self) -> &'static str {
        match self {
            Self::Es256 => "P-256",
            Self::Es384 => "P-384",
        }
    }

    /// Stable encoding for cache keys / deterministic derivation.
    ///
    /// If you change this, bump the derivation version in `uselesskey-core`.
    pub fn stable_bytes(&self) -> [u8; 4] {
        match self {
            Self::Es256 => [0, 0, 0, 1],
            Self::Es384 => [0, 0, 0, 2],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alg_and_curve_names_match_specs() {
        let es256 = EcdsaSpec::es256();
        assert_eq!(es256.alg_name(), "ES256");
        assert_eq!(es256.curve_name(), "P-256");

        let es384 = EcdsaSpec::es384();
        assert_eq!(es384.alg_name(), "ES384");
        assert_eq!(es384.curve_name(), "P-384");
    }

    #[test]
    fn stable_bytes_are_unique() {
        let es256 = EcdsaSpec::es256().stable_bytes();
        let es384 = EcdsaSpec::es384().stable_bytes();
        assert_ne!(es256, es384);
    }
}
