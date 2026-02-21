//! X.509 negative fixture types.
//!
//! These types represent intentionally invalid certificates for testing error handling.

use crate::spec::{KeyUsage, NotBeforeOffset, X509Spec};

/// Types of invalid X.509 certificates for negative testing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum X509Negative {
    /// Certificate with not_after in the past (expired).
    Expired,
    /// Certificate with not_before in the future (not yet valid).
    NotYetValid,
    /// Certificate marked as CA but without proper key usage flags.
    WrongKeyUsage,
    /// Self-signed certificate that claims to be a CA but has conflicting extensions.
    SelfSignedButClaimsCA,
}

impl X509Negative {
    /// Modify a spec to produce the negative fixture variant.
    pub fn apply_to_spec(&self, base_spec: &X509Spec) -> X509Spec {
        let mut spec = base_spec.clone();

        match self {
            X509Negative::Expired => {
                // Certificate expired 30 days ago
                // not_before was 395 days ago, valid for 365 days = expired 30 days ago
                spec.not_before_offset = NotBeforeOffset::DaysAgo(395);
                spec.validity_days = 365;
            }
            X509Negative::NotYetValid => {
                // Certificate valid starting 30 days from now
                spec.not_before_offset = NotBeforeOffset::DaysFromNow(30);
                spec.validity_days = 365;
            }
            X509Negative::WrongKeyUsage => {
                // Marked as CA but without key_cert_sign
                spec.is_ca = true;
                spec.key_usage = KeyUsage {
                    key_cert_sign: false, // Wrong! CA should have this
                    crl_sign: false,
                    digital_signature: true,
                    key_encipherment: true,
                };
            }
            X509Negative::SelfSignedButClaimsCA => {
                // Self-signed but claims to be CA with path length constraint
                // This creates a "CA" that can't actually sign anything valid
                spec.is_ca = true;
                spec.key_usage = KeyUsage::ca();
                // The certificate will be self-signed but marked as CA
                // with no actual chain - this is suspicious in production
            }
        }

        spec
    }

    /// Human-readable description of this negative fixture.
    pub fn description(&self) -> &'static str {
        match self {
            X509Negative::Expired => "Certificate with not_after in the past (expired)",
            X509Negative::NotYetValid => {
                "Certificate with not_before in the future (not yet valid)"
            }
            X509Negative::WrongKeyUsage => {
                "Certificate marked as CA but without keyCertSign key usage"
            }
            X509Negative::SelfSignedButClaimsCA => "Self-signed certificate that claims to be a CA",
        }
    }

    /// Variant name for cache keys.
    pub fn variant_name(&self) -> &'static str {
        match self {
            X509Negative::Expired => "expired",
            X509Negative::NotYetValid => "not_yet_valid",
            X509Negative::WrongKeyUsage => "wrong_key_usage",
            X509Negative::SelfSignedButClaimsCA => "self_signed_ca",
        }
    }
}

/// Corrupt a PEM-encoded certificate.
///
/// Delegates to the core negative fixture helpers.
pub fn corrupt_cert_pem(pem: &str, how: uselesskey_core::negative::CorruptPem) -> String {
    uselesskey_core::negative::corrupt_pem(pem, how)
}

/// Corrupt a PEM-encoded certificate using a deterministic variant string.
pub fn corrupt_cert_pem_deterministic(pem: &str, variant: &str) -> String {
    uselesskey_core::negative::corrupt_pem_deterministic(pem, variant)
}

/// Truncate a DER-encoded certificate.
///
/// Delegates to the core negative fixture helpers.
pub fn truncate_cert_der(der: &[u8], len: usize) -> Vec<u8> {
    uselesskey_core::negative::truncate_der(der, len)
}

/// Corrupt a DER-encoded certificate using a deterministic variant string.
pub fn corrupt_cert_der_deterministic(der: &[u8], variant: &str) -> Vec<u8> {
    uselesskey_core::negative::corrupt_der_deterministic(der, variant)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expired_exact_values() {
        let base = X509Spec::self_signed("test");
        let modified = X509Negative::Expired.apply_to_spec(&base);

        assert_eq!(modified.not_before_offset, NotBeforeOffset::DaysAgo(395));
        assert_eq!(modified.validity_days, 365);
        assert!(!modified.is_ca);
        assert_eq!(modified.key_usage, KeyUsage::leaf());
    }

    #[test]
    fn test_not_yet_valid_exact_values() {
        let base = X509Spec::self_signed("test");
        let modified = X509Negative::NotYetValid.apply_to_spec(&base);

        assert_eq!(modified.not_before_offset, NotBeforeOffset::DaysFromNow(30));
        assert_eq!(modified.validity_days, 365);
    }

    #[test]
    fn test_wrong_key_usage_exact_values() {
        let base = X509Spec::self_signed("test");
        let modified = X509Negative::WrongKeyUsage.apply_to_spec(&base);

        assert!(modified.is_ca);
        assert_eq!(
            modified.key_usage,
            KeyUsage {
                key_cert_sign: false,
                crl_sign: false,
                digital_signature: true,
                key_encipherment: true,
            }
        );
    }

    #[test]
    fn test_self_signed_ca_exact_values() {
        let base = X509Spec::self_signed("test");
        let modified = X509Negative::SelfSignedButClaimsCA.apply_to_spec(&base);

        assert!(modified.is_ca);
        assert_eq!(modified.key_usage, KeyUsage::ca());
    }

    #[test]
    fn test_variant_name_exact_values() {
        assert_eq!(X509Negative::Expired.variant_name(), "expired");
        assert_eq!(X509Negative::NotYetValid.variant_name(), "not_yet_valid");
        assert_eq!(
            X509Negative::WrongKeyUsage.variant_name(),
            "wrong_key_usage"
        );
        assert_eq!(
            X509Negative::SelfSignedButClaimsCA.variant_name(),
            "self_signed_ca"
        );
    }

    #[test]
    fn test_description_covers_all() {
        let variants = [
            X509Negative::Expired,
            X509Negative::NotYetValid,
            X509Negative::WrongKeyUsage,
            X509Negative::SelfSignedButClaimsCA,
        ];

        for variant in &variants {
            assert!(!variant.description().is_empty());
        }

        assert!(X509Negative::Expired.description().contains("expired"));
        assert!(
            X509Negative::NotYetValid
                .description()
                .contains("not yet valid")
        );
        assert!(
            X509Negative::WrongKeyUsage
                .description()
                .contains("keyCertSign")
        );
        assert!(
            X509Negative::SelfSignedButClaimsCA
                .description()
                .contains("CA")
        );
    }

    #[test]
    fn test_corrupt_cert_pem_bad_header_changes_pem() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAA=\n-----END CERTIFICATE-----\n";
        let corrupted = corrupt_cert_pem(pem, uselesskey_core::negative::CorruptPem::BadHeader);
        assert_ne!(corrupted, pem, "BadHeader must alter the PEM");
    }

    #[test]
    fn test_corrupt_cert_pem_deterministic_changes_pem() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAA=\n-----END CERTIFICATE-----\n";
        let corrupted = corrupt_cert_pem_deterministic(pem, "corrupt:v1");
        assert_ne!(
            corrupted, pem,
            "deterministic corruption must alter the PEM"
        );

        // Stability
        let corrupted2 = corrupt_cert_pem_deterministic(pem, "corrupt:v1");
        assert_eq!(
            corrupted, corrupted2,
            "same variant must produce same result"
        );
    }

    #[test]
    fn test_truncate_cert_der_returns_exact_prefix() {
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        let truncated = truncate_cert_der(&der, 2);
        assert_eq!(
            truncated,
            &der[..2],
            "truncate_cert_der must return exact prefix"
        );
    }

    #[test]
    fn test_corrupt_cert_der_deterministic_changes_der() {
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x01];
        let corrupted = corrupt_cert_der_deterministic(&der, "corrupt:v1");
        assert_ne!(
            corrupted, der,
            "deterministic corruption must alter the DER"
        );

        // Stability
        let corrupted2 = corrupt_cert_der_deterministic(&der, "corrupt:v1");
        assert_eq!(
            corrupted, corrupted2,
            "same variant must produce same result"
        );
    }
}
