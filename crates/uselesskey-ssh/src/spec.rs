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
        fn push_str(buf: &mut Vec<u8>, s: &str) {
            let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(s.as_bytes());
        }

        let mut out = Vec::new();
        out.push(self.cert_type.stable_byte());
        out.extend_from_slice(&self.validity.valid_after.to_be_bytes());
        out.extend_from_slice(&self.validity.valid_before.to_be_bytes());

        out.extend_from_slice(
            &u32::try_from(self.principals.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for principal in &self.principals {
            push_str(&mut out, principal);
        }

        out.extend_from_slice(
            &u32::try_from(self.critical_options.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for (name, value) in &self.critical_options {
            push_str(&mut out, name);
            push_str(&mut out, value);
        }

        out.extend_from_slice(
            &u32::try_from(self.extensions.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for (name, value) in &self.extensions {
            push_str(&mut out, name);
            push_str(&mut out, value);
        }

        out
    }
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

    #[test]
    fn ssh_spec_default_is_ed25519() {
        assert_eq!(SshSpec::default(), SshSpec::Ed25519);
    }

    #[test]
    fn ssh_spec_constructors_return_expected_variants() {
        assert_eq!(SshSpec::ed25519(), SshSpec::Ed25519);
        assert_eq!(SshSpec::rsa(), SshSpec::Rsa);
    }

    #[test]
    fn ssh_spec_stable_bytes_known_values() {
        assert_eq!(SshSpec::Ed25519.stable_bytes(), [1]);
        assert_eq!(SshSpec::Rsa.stable_bytes(), [2]);
    }

    #[test]
    fn ssh_cert_type_default_is_user() {
        assert_eq!(SshCertType::default(), SshCertType::User);
    }

    #[test]
    fn ssh_cert_type_stable_byte_known_values() {
        assert_eq!(SshCertType::User.stable_byte(), 1);
        assert_eq!(SshCertType::Host.stable_byte(), 2);
    }

    #[test]
    fn ssh_validity_new_assigns_fields() {
        let v = SshValidity::new(100, 200);
        assert_eq!(v.valid_after, 100);
        assert_eq!(v.valid_before, 200);
    }

    #[test]
    fn cert_spec_user_records_principals_and_type() {
        let spec = SshCertSpec::user(["alice"], SshValidity::new(0, 1));
        assert_eq!(spec.principals, vec!["alice".to_string()]);
        assert_eq!(spec.cert_type, SshCertType::User);
        assert!(spec.critical_options.is_empty());
        assert!(spec.extensions.is_empty());
    }

    #[test]
    fn cert_spec_user_accepts_empty_principals() {
        let spec = SshCertSpec::user(std::iter::empty::<&str>(), SshValidity::new(0, 1));
        assert!(spec.principals.is_empty());
        assert_eq!(spec.cert_type, SshCertType::User);
    }

    #[test]
    fn cert_spec_host_records_principals_and_type() {
        let spec = SshCertSpec::host(["h1", "h2"], SshValidity::new(0, 1));
        assert_eq!(spec.principals, vec!["h1".to_string(), "h2".to_string()]);
        assert_eq!(spec.cert_type, SshCertType::Host);
    }

    #[test]
    fn cert_spec_host_accepts_empty_principals() {
        let spec = SshCertSpec::host(std::iter::empty::<&str>(), SshValidity::new(0, 1));
        assert!(spec.principals.is_empty());
        assert_eq!(spec.cert_type, SshCertType::Host);
    }

    #[test]
    fn cert_spec_stable_bytes_change_with_cert_type() {
        let validity = SshValidity::new(1, 2);
        let user_bytes = SshCertSpec::user(["a"], validity).stable_bytes();
        let host_bytes = SshCertSpec::host(["a"], validity).stable_bytes();
        assert_ne!(user_bytes, host_bytes);
    }

    #[test]
    fn cert_spec_stable_bytes_change_with_validity() {
        let a = SshCertSpec::user(["x"], SshValidity::new(1, 2)).stable_bytes();
        let b = SshCertSpec::user(["x"], SshValidity::new(1, 3)).stable_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn cert_spec_stable_bytes_change_with_critical_options() {
        let mut a = SshCertSpec::user(["x"], SshValidity::new(1, 2));
        let mut b = SshCertSpec::user(["x"], SshValidity::new(1, 2));
        b.critical_options
            .push(("force-command".to_string(), "/bin/true".to_string()));
        assert_eq!(a.stable_bytes(), a.stable_bytes());
        assert_ne!(a.stable_bytes(), b.stable_bytes());
        a.critical_options
            .push(("force-command".to_string(), "/bin/true".to_string()));
        assert_eq!(a.stable_bytes(), b.stable_bytes());
    }

    #[test]
    fn cert_spec_stable_bytes_change_with_extensions() {
        let mut a = SshCertSpec::user(["x"], SshValidity::new(1, 2));
        let mut b = SshCertSpec::user(["x"], SshValidity::new(1, 2));
        b.extensions.push(("permit-pty".to_string(), String::new()));
        assert_ne!(a.stable_bytes(), b.stable_bytes());
        a.extensions.push(("permit-pty".to_string(), String::new()));
        assert_eq!(a.stable_bytes(), b.stable_bytes());
    }

    #[test]
    fn cert_spec_stable_bytes_with_no_collections_is_deterministic() {
        let spec = SshCertSpec::user(std::iter::empty::<&str>(), SshValidity::new(0, 1));
        assert_eq!(spec.stable_bytes(), spec.stable_bytes());
        assert!(!spec.stable_bytes().is_empty());
    }
}
