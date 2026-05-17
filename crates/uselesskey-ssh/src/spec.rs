/// Supported SSH key algorithms for fixture generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub enum SshSpec {
    /// `ssh-ed25519`
    #[default]
    Ed25519,
    /// `ssh-rsa`
    Rsa,
}

impl SshSpec {
    pub fn ed25519() -> Self {
        Self::Ed25519
    }

    pub fn rsa() -> Self {
        Self::Rsa
    }

    pub fn stable_bytes(&self) -> [u8; 1] {
        match self {
            Self::Ed25519 => [1],
            Self::Rsa => [2],
        }
    }
}

/// SSH certificate type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub enum SshCertType {
    /// User cert (principal = username).
    #[default]
    User,
    /// Host cert (principal = hostname).
    Host,
}

impl SshCertType {
    pub fn stable_byte(&self) -> u8 {
        match self {
            Self::User => 1,
            Self::Host => 2,
        }
    }
}

/// Validity window (Unix seconds).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SshValidity {
    pub valid_after: u64,
    pub valid_before: u64,
}

impl SshValidity {
    pub fn new(valid_after: u64, valid_before: u64) -> Self {
        Self {
            valid_after,
            valid_before,
        }
    }
}

/// SSH certificate fixture specification.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SshCertSpec {
    pub principals: Vec<String>,
    pub validity: SshValidity,
    pub cert_type: SshCertType,
    pub critical_options: Vec<(String, String)>,
    pub extensions: Vec<(String, String)>,
}

impl SshCertSpec {
    pub fn user(
        principals: impl IntoIterator<Item = impl Into<String>>,
        validity: SshValidity,
    ) -> Self {
        Self {
            principals: principals.into_iter().map(Into::into).collect(),
            validity,
            cert_type: SshCertType::User,
            critical_options: Vec::new(),
            extensions: Vec::new(),
        }
    }

    pub fn host(
        principals: impl IntoIterator<Item = impl Into<String>>,
        validity: SshValidity,
    ) -> Self {
        Self {
            principals: principals.into_iter().map(Into::into).collect(),
            validity,
            cert_type: SshCertType::Host,
            critical_options: Vec::new(),
            extensions: Vec::new(),
        }
    }

    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.cert_type.stable_byte());
        out.extend_from_slice(&self.validity.valid_after.to_be_bytes());
        out.extend_from_slice(&self.validity.valid_before.to_be_bytes());
        push_strings(&mut out, &self.principals);
        push_string_pairs(&mut out, &self.critical_options);
        push_string_pairs(&mut out, &self.extensions);
        out
    }
}

fn push_strings(buf: &mut Vec<u8>, values: &[String]) {
    push_len(buf, values.len());
    for value in values {
        push_str(buf, value);
    }
}

fn push_string_pairs(buf: &mut Vec<u8>, values: &[(String, String)]) {
    push_len(buf, values.len());
    for (name, value) in values {
        push_str(buf, name);
        push_str(buf, value);
    }
}

fn push_str(buf: &mut Vec<u8>, value: &str) {
    push_len(buf, value.len());
    buf.extend_from_slice(value.as_bytes());
}

fn push_len(buf: &mut Vec<u8>, len: usize) {
    buf.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_spec_stable_bytes_are_unique() {
        assert_ne!(
            SshSpec::ed25519().stable_bytes(),
            SshSpec::rsa().stable_bytes()
        );
    }

    #[test]
    fn cert_spec_stable_bytes_change_with_principal() {
        let a = SshCertSpec::user(["alice"], SshValidity::new(1, 2)).stable_bytes();
        let b = SshCertSpec::user(["bob"], SshValidity::new(1, 2)).stable_bytes();
        assert_ne!(a, b);
    }
}
