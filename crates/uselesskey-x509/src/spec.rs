//! X.509 certificate specification.

use std::time::Duration;

/// Key usage flags for X.509 certificates.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct KeyUsage {
    /// Certificate can sign other certificates (CA).
    pub key_cert_sign: bool,
    /// Certificate can sign CRLs.
    pub crl_sign: bool,
    /// Certificate can be used for digital signatures.
    pub digital_signature: bool,
    /// Certificate can be used for key encipherment.
    pub key_encipherment: bool,
}

impl Default for KeyUsage {
    fn default() -> Self {
        Self::leaf()
    }
}

impl KeyUsage {
    /// Key usage for a leaf/end-entity certificate.
    pub fn leaf() -> Self {
        Self {
            key_cert_sign: false,
            crl_sign: false,
            digital_signature: true,
            key_encipherment: true,
        }
    }

    /// Key usage for a CA certificate.
    pub fn ca() -> Self {
        Self {
            key_cert_sign: true,
            crl_sign: true,
            digital_signature: true,
            key_encipherment: false,
        }
    }

    /// Stable byte representation for deterministic derivation.
    pub fn stable_bytes(&self) -> [u8; 4] {
        let mut out = [0u8; 4];
        out[0] = self.key_cert_sign as u8;
        out[1] = self.crl_sign as u8;
        out[2] = self.digital_signature as u8;
        out[3] = self.key_encipherment as u8;
        out
    }
}

/// Specification for generating an X.509 certificate.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct X509Spec {
    /// Common Name (CN) for the subject.
    pub subject_cn: String,
    /// Common Name (CN) for the issuer (same as subject for self-signed).
    pub issuer_cn: String,
    /// Duration before "now" for not_before (negative = in the past).
    /// Default: 1 day before "now".
    pub not_before_offset: NotBeforeOffset,
    /// Duration after "now" for not_after.
    /// Default: 365 days.
    pub validity_days: u32,
    /// Key usage flags.
    pub key_usage: KeyUsage,
    /// Whether this is a CA certificate.
    pub is_ca: bool,
    /// RSA key size in bits.
    pub rsa_bits: usize,
}

/// Offset for the not_before field.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum NotBeforeOffset {
    /// Certificate is valid starting from this many days in the past.
    DaysAgo(u32),
    /// Certificate is valid starting from this many days in the future.
    DaysFromNow(u32),
}

impl Default for NotBeforeOffset {
    fn default() -> Self {
        NotBeforeOffset::DaysAgo(1)
    }
}

impl Default for X509Spec {
    fn default() -> Self {
        Self {
            subject_cn: "Test Certificate".to_string(),
            issuer_cn: "Test Certificate".to_string(),
            not_before_offset: NotBeforeOffset::default(),
            validity_days: 365,
            key_usage: KeyUsage::leaf(),
            is_ca: false,
            rsa_bits: 2048,
        }
    }
}

impl X509Spec {
    /// Create a spec for a self-signed leaf certificate.
    pub fn self_signed(cn: impl Into<String>) -> Self {
        let cn = cn.into();
        Self {
            subject_cn: cn.clone(),
            issuer_cn: cn,
            ..Default::default()
        }
    }

    /// Create a spec for a self-signed CA certificate.
    pub fn self_signed_ca(cn: impl Into<String>) -> Self {
        let cn = cn.into();
        Self {
            subject_cn: cn.clone(),
            issuer_cn: cn,
            key_usage: KeyUsage::ca(),
            is_ca: true,
            ..Default::default()
        }
    }

    /// Set the validity period in days.
    pub fn with_validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    /// Set the not_before offset.
    pub fn with_not_before(mut self, offset: NotBeforeOffset) -> Self {
        self.not_before_offset = offset;
        self
    }

    /// Set the RSA key size.
    pub fn with_rsa_bits(mut self, bits: usize) -> Self {
        self.rsa_bits = bits;
        self
    }

    /// Set key usage flags.
    pub fn with_key_usage(mut self, key_usage: KeyUsage) -> Self {
        self.key_usage = key_usage;
        self
    }

    /// Set whether this is a CA certificate.
    pub fn with_is_ca(mut self, is_ca: bool) -> Self {
        self.is_ca = is_ca;
        self
    }

    /// Stable encoding for cache keys / deterministic derivation.
    ///
    /// If you change this, bump the derivation version in `uselesskey-core`.
    pub fn stable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Version prefix to allow deterministic derivation changes without affecting other crates.
        // Bump this if X.509 derivation inputs change.
        out.push(2);

        // Subject CN length + bytes
        let subject_bytes = self.subject_cn.as_bytes();
        out.extend_from_slice(&(subject_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(subject_bytes);

        // Issuer CN length + bytes
        let issuer_bytes = self.issuer_cn.as_bytes();
        out.extend_from_slice(&(issuer_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(issuer_bytes);

        // not_before_offset
        match self.not_before_offset {
            NotBeforeOffset::DaysAgo(d) => {
                out.push(0);
                out.extend_from_slice(&d.to_be_bytes());
            }
            NotBeforeOffset::DaysFromNow(d) => {
                out.push(1);
                out.extend_from_slice(&d.to_be_bytes());
            }
        }

        // validity_days
        out.extend_from_slice(&self.validity_days.to_be_bytes());

        // key_usage
        out.extend_from_slice(&self.key_usage.stable_bytes());

        // is_ca
        out.push(self.is_ca as u8);

        // rsa_bits
        out.extend_from_slice(&(self.rsa_bits as u32).to_be_bytes());

        out
    }

    /// Compute the not_before duration from a reference time.
    pub fn not_before_duration(&self) -> Duration {
        match self.not_before_offset {
            NotBeforeOffset::DaysAgo(d) => Duration::from_secs(d as u64 * 24 * 60 * 60),
            NotBeforeOffset::DaysFromNow(_) => Duration::ZERO,
        }
    }

    /// Compute the not_after duration from a reference time.
    pub fn not_after_duration(&self) -> Duration {
        let base = match self.not_before_offset {
            NotBeforeOffset::DaysAgo(_) => Duration::ZERO,
            NotBeforeOffset::DaysFromNow(d) => Duration::from_secs(d as u64 * 24 * 60 * 60),
        };
        base + Duration::from_secs(self.validity_days as u64 * 24 * 60 * 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_spec() {
        let spec = X509Spec::default();
        assert_eq!(spec.subject_cn, "Test Certificate");
        assert_eq!(spec.validity_days, 365);
        assert!(!spec.is_ca);
    }

    #[test]
    fn test_self_signed_spec() {
        let spec = X509Spec::self_signed("example.com");
        assert_eq!(spec.subject_cn, "example.com");
        assert_eq!(spec.issuer_cn, "example.com");
        assert!(!spec.is_ca);
    }

    #[test]
    fn test_ca_spec() {
        let spec = X509Spec::self_signed_ca("My CA");
        assert!(spec.is_ca);
        assert!(spec.key_usage.key_cert_sign);
    }

    #[test]
    fn test_stable_bytes_determinism() {
        let spec1 = X509Spec::self_signed("test");
        let spec2 = X509Spec::self_signed("test");
        assert_eq!(spec1.stable_bytes(), spec2.stable_bytes());

        let spec3 = X509Spec::self_signed("different");
        assert_ne!(spec1.stable_bytes(), spec3.stable_bytes());
    }
}
