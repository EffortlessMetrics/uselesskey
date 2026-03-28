use std::collections::BTreeMap;

/// SSH certificate type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CertType {
    /// User certificate.
    User,
    /// Host certificate.
    Host,
}

/// Validity window for SSH certificates.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SshValidity {
    /// Unix timestamp seconds (inclusive).
    pub valid_after: u64,
    /// Unix timestamp seconds (inclusive upper bound in OpenSSH semantics).
    pub valid_before: u64,
}

impl SshValidity {
    /// Create a validity range.
    pub const fn new(valid_after: u64, valid_before: u64) -> Self {
        Self {
            valid_after,
            valid_before,
        }
    }
}

/// Spec for deterministic SSH certificates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshCertSpec {
    /// User or host certificate type.
    pub cert_type: CertType,
    /// Allowed principals.
    pub principals: Vec<String>,
    /// Validity window.
    pub validity: SshValidity,
    /// Critical options map.
    pub critical_options: BTreeMap<String, String>,
    /// Extension map.
    pub extensions: BTreeMap<String, String>,
}

impl SshCertSpec {
    /// Construct a certificate spec with required fields.
    pub fn new(cert_type: CertType, principals: impl Into<Vec<String>>, validity: SshValidity) -> Self {
        Self {
            cert_type,
            principals: principals.into(),
            validity,
            critical_options: BTreeMap::new(),
            extensions: BTreeMap::new(),
        }
    }

    pub(crate) fn fingerprint_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let cert_ty = match self.cert_type {
            CertType::User => "user",
            CertType::Host => "host",
        };
        out.extend_from_slice(format!("type={cert_ty};").as_bytes());
        out.extend_from_slice(format!("after={};before={};", self.validity.valid_after, self.validity.valid_before).as_bytes());
        out.extend_from_slice(b"principals=");
        for p in &self.principals {
            out.extend_from_slice(p.as_bytes());
            out.push(b',');
        }
        out.extend_from_slice(b";critical=");
        for (k, v) in &self.critical_options {
            out.extend_from_slice(k.as_bytes());
            out.push(b'=');
            out.extend_from_slice(v.as_bytes());
            out.push(b',');
        }
        out.extend_from_slice(b";extensions=");
        for (k, v) in &self.extensions {
            out.extend_from_slice(k.as_bytes());
            out.push(b'=');
            out.extend_from_slice(v.as_bytes());
            out.push(b',');
        }
        out
    }
}

/// Deterministic SSH certificate fixture.
#[derive(Clone, Debug)]
pub struct SshCertFixture {
    pub(crate) cert_line: String,
}

impl SshCertFixture {
    /// OpenSSH authorized-principals style certificate line.
    pub fn cert_line(&self) -> &str {
        &self.cert_line
    }
}
