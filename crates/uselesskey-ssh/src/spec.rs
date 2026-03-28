use core::fmt;

/// SSH key algorithm supported by this fixture crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SshAlgorithm {
    /// RSA with configurable bit-size.
    Rsa { bits: usize },
    /// Ed25519.
    Ed25519,
}

/// SSH key generation spec.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct SshSpec {
    alg: SshAlgorithm,
}

impl SshSpec {
    /// Build an Ed25519 key spec.
    pub const fn ed25519() -> Self {
        Self {
            alg: SshAlgorithm::Ed25519,
        }
    }

    /// Build an RSA key spec with custom modulus length.
    pub const fn rsa(bits: usize) -> Self {
        Self {
            alg: SshAlgorithm::Rsa { bits },
        }
    }

    /// Build a common RSA-2048 SSH spec.
    pub const fn rsa_2048() -> Self {
        Self::rsa(2_048)
    }

    /// Return the algorithm configuration.
    pub const fn algorithm(&self) -> SshAlgorithm {
        self.alg
    }

    pub(crate) fn fingerprint_bytes(&self) -> Vec<u8> {
        match self.alg {
            SshAlgorithm::Ed25519 => b"alg=ed25519".to_vec(),
            SshAlgorithm::Rsa { bits } => format!("alg=rsa;bits={bits}").into_bytes(),
        }
    }
}

impl Default for SshSpec {
    fn default() -> Self {
        Self::ed25519()
    }
}

impl fmt::Debug for SshSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshSpec").field("alg", &self.alg).finish()
    }
}
