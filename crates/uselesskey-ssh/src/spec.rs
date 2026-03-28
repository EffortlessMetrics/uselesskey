/// Specification for OpenSSH key fixture generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SshSpec {
    /// RSA key using the default size provided by `ssh-key`.
    Rsa,
    /// Ed25519 key.
    Ed25519,
}

impl SshSpec {
    pub fn rsa() -> Self {
        Self::Rsa
    }

    pub fn ed25519() -> Self {
        Self::Ed25519
    }

    pub fn stable_bytes(&self) -> [u8; 4] {
        match self {
            Self::Rsa => [0, 0, 0, 1],
            Self::Ed25519 => [0, 0, 0, 2],
        }
    }
}

impl From<SshSpec> for ssh_key::Algorithm {
    fn from(value: SshSpec) -> Self {
        match value {
            SshSpec::Rsa => ssh_key::Algorithm::Rsa { hash: None },
            SshSpec::Ed25519 => ssh_key::Algorithm::Ed25519,
        }
    }
}

/// OpenSSH certificate type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub enum SshCertType {
    /// User certificate.
    #[default]
    User,
    /// Host certificate.
    Host,
}

impl From<SshCertType> for ssh_key::certificate::CertType {
    fn from(value: SshCertType) -> Self {
        match value {
            SshCertType::User => ssh_key::certificate::CertType::User,
            SshCertType::Host => ssh_key::certificate::CertType::Host,
        }
    }
}

/// OpenSSH certificate validity window.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SshValidity {
    pub valid_after: u64,
    pub valid_before: u64,
}

/// Specification for OpenSSH certificate fixture generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshCertSpec {
    pub principals: Vec<String>,
    pub validity: SshValidity,
    pub cert_type: SshCertType,
}

impl SshCertSpec {
    pub fn with_critical_options(
        self,
        critical_options: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> SshCertSpecWithOptions {
        SshCertSpecWithOptions {
            spec: self,
            critical_options: critical_options
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
            extensions: Vec::new(),
        }
    }

    pub fn with_extensions(
        self,
        extensions: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> SshCertSpecWithOptions {
        SshCertSpecWithOptions {
            spec: self,
            critical_options: Vec::new(),
            extensions: extensions
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
        }
    }
}

/// Expanded certificate spec including critical options and extensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshCertSpecWithOptions {
    pub spec: SshCertSpec,
    pub critical_options: Vec<(String, String)>,
    pub extensions: Vec<(String, String)>,
}

impl From<SshCertSpec> for SshCertSpecWithOptions {
    fn from(spec: SshCertSpec) -> Self {
        Self {
            spec,
            critical_options: Vec::new(),
            extensions: Vec::new(),
        }
    }
}

impl SshCertSpecWithOptions {
    pub fn with_extensions(
        mut self,
        extensions: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.extensions = extensions
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect();
        self
    }

    pub fn with_critical_options(
        mut self,
        critical_options: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        self.critical_options = critical_options
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect();
        self
    }

    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0, 0, 0, cert_type_byte(self.spec.cert_type)]);
        out.extend_from_slice(&self.spec.validity.valid_after.to_be_bytes());
        out.extend_from_slice(&self.spec.validity.valid_before.to_be_bytes());
        encode_pairs(self.spec.principals.iter().map(|p| (p.as_str(), "")), &mut out);
        encode_pairs(
            self.critical_options
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str())),
            &mut out,
        );
        encode_pairs(
            self.extensions.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            &mut out,
        );
        out
    }
}

fn encode_pairs<'a, I>(pairs: I, out: &mut Vec<u8>)
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let collected = pairs.into_iter().collect::<Vec<_>>();
    out.extend_from_slice(&(collected.len() as u32).to_be_bytes());
    for (k, v) in collected {
        let kb = k.as_bytes();
        let vb = v.as_bytes();
        out.extend_from_slice(&(kb.len() as u32).to_be_bytes());
        out.extend_from_slice(kb);
        out.extend_from_slice(&(vb.len() as u32).to_be_bytes());
        out.extend_from_slice(vb);
    }
}

fn cert_type_byte(cert_type: SshCertType) -> u8 {
    match cert_type {
        SshCertType::User => 1,
        SshCertType::Host => 2,
    }
}
