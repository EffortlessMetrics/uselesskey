/// Supported SSH key algorithms for fixture generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SshSpec {
    /// Ed25519 keypair.
    Ed25519,
    /// RSA keypair.
    Rsa,
}

impl SshSpec {
    /// Ed25519 SSH key fixtures.
    pub fn ed25519() -> Self {
        Self::Ed25519
    }

    /// RSA SSH key fixtures with a given modulus size.
    pub fn rsa() -> Self {
        Self::Rsa
    }

    pub(crate) fn stable_bytes(&self) -> [u8; 9] {
        let mut out = [0u8; 9];
        match self {
            Self::Ed25519 => {
                out[0] = 1;
            }
            Self::Rsa => {
                out[0] = 2;
            }
        }
        out
    }
}

/// SSH certificate type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SshCertType {
    User,
    Host,
}

/// Certificate validity window as UNIX timestamps in seconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SshCertValidity {
    pub valid_after: u64,
    pub valid_before: u64,
}

impl SshCertValidity {
    pub fn new(valid_after: u64, valid_before: u64) -> Self {
        Self {
            valid_after,
            valid_before,
        }
    }
}

/// OpenSSH certificate generation spec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshCertSpec {
    pub principals: Vec<String>,
    pub validity: SshCertValidity,
    pub cert_type: SshCertType,
    pub critical_options: Vec<(String, String)>,
    pub extensions: Vec<(String, String)>,
    pub subject_key: SshSpec,
    pub ca_key: SshSpec,
}

impl SshCertSpec {
    /// User-certificate defaults with required principal and validity.
    pub fn user(principals: Vec<String>, validity: SshCertValidity) -> Self {
        Self {
            principals,
            validity,
            cert_type: SshCertType::User,
            critical_options: Vec::new(),
            extensions: Vec::new(),
            subject_key: SshSpec::ed25519(),
            ca_key: SshSpec::ed25519(),
        }
    }

    pub(crate) fn stable_bytes(&self) -> Vec<u8> {
        fn push_str(out: &mut Vec<u8>, s: &str) {
            let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        }

        let mut out = Vec::new();
        out.push(match self.cert_type {
            SshCertType::User => 1,
            SshCertType::Host => 2,
        });

        out.extend_from_slice(&self.validity.valid_after.to_be_bytes());
        out.extend_from_slice(&self.validity.valid_before.to_be_bytes());
        out.extend_from_slice(&self.subject_key.stable_bytes());
        out.extend_from_slice(&self.ca_key.stable_bytes());

        out.extend_from_slice(&(u32::try_from(self.principals.len()).unwrap_or(u32::MAX)).to_be_bytes());
        for p in &self.principals {
            push_str(&mut out, p);
        }

        out.extend_from_slice(
            &(u32::try_from(self.critical_options.len()).unwrap_or(u32::MAX)).to_be_bytes(),
        );
        for (k, v) in &self.critical_options {
            push_str(&mut out, k);
            push_str(&mut out, v);
        }

        out.extend_from_slice(&(u32::try_from(self.extensions.len()).unwrap_or(u32::MAX)).to_be_bytes());
        for (k, v) in &self.extensions {
            push_str(&mut out, k);
            push_str(&mut out, v);
        }

        out
    }
}
