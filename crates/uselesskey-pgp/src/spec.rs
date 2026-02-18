/// Specification for OpenPGP fixture generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PgpSpec {
    /// RSA 2048-bit OpenPGP key.
    Rsa2048,
    /// RSA 3072-bit OpenPGP key.
    Rsa3072,
    /// Ed25519 OpenPGP key.
    Ed25519,
}

impl PgpSpec {
    pub fn rsa_2048() -> Self {
        Self::Rsa2048
    }

    pub fn rsa_3072() -> Self {
        Self::Rsa3072
    }

    pub fn ed25519() -> Self {
        Self::Ed25519
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Rsa2048 => "rsa2048",
            Self::Rsa3072 => "rsa3072",
            Self::Ed25519 => "ed25519",
        }
    }

    /// Stable encoding for cache keys / deterministic derivation.
    ///
    /// If you change this, bump the derivation version in `uselesskey-core`.
    pub fn stable_bytes(&self) -> [u8; 4] {
        match self {
            Self::Rsa2048 => [0, 0, 0, 1],
            Self::Rsa3072 => [0, 0, 0, 2],
            Self::Ed25519 => [0, 0, 0, 3],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_bytes_are_unique() {
        let rsa_2048 = PgpSpec::rsa_2048().stable_bytes();
        let rsa_3072 = PgpSpec::rsa_3072().stable_bytes();
        let ed25519 = PgpSpec::ed25519().stable_bytes();

        assert_ne!(rsa_2048, rsa_3072);
        assert_ne!(rsa_2048, ed25519);
        assert_ne!(rsa_3072, ed25519);
    }

    #[test]
    fn kind_names_are_stable() {
        assert_eq!(PgpSpec::rsa_2048().kind_name(), "rsa2048");
        assert_eq!(PgpSpec::rsa_3072().kind_name(), "rsa3072");
        assert_eq!(PgpSpec::ed25519().kind_name(), "ed25519");
    }
}
