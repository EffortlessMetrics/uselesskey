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
    fn test_expired_modifies_spec() {
        let base = X509Spec::self_signed("test");
        let modified = X509Negative::Expired.apply_to_spec(&base);

        // Should have not_before far in the past
        assert!(matches!(
            modified.not_before_offset,
            NotBeforeOffset::DaysAgo(d) if d > 365
        ));
    }

    #[test]
    fn test_not_yet_valid_modifies_spec() {
        let base = X509Spec::self_signed("test");
        let modified = X509Negative::NotYetValid.apply_to_spec(&base);

        assert!(matches!(
            modified.not_before_offset,
            NotBeforeOffset::DaysFromNow(d) if d > 0
        ));
    }

    #[test]
    fn test_wrong_key_usage_modifies_spec() {
        let base = X509Spec::self_signed("test");
        let modified = X509Negative::WrongKeyUsage.apply_to_spec(&base);

        assert!(modified.is_ca);
        assert!(!modified.key_usage.key_cert_sign);
    }

    #[test]
    fn test_self_signed_ca_variant_modifies_spec() {
        let base = X509Spec::self_signed("test");
        let modified = X509Negative::SelfSignedButClaimsCA.apply_to_spec(&base);

        assert!(modified.is_ca);
        assert!(modified.key_usage.key_cert_sign);
        assert!(modified.key_usage.crl_sign);
    }

    #[test]
    fn test_description_and_variant_name_cover_all() {
        let variants = [
            X509Negative::Expired,
            X509Negative::NotYetValid,
            X509Negative::WrongKeyUsage,
            X509Negative::SelfSignedButClaimsCA,
        ];

        for variant in &variants {
            assert!(!variant.description().is_empty());
            assert!(!variant.variant_name().is_empty());
        }

        assert_eq!(
            X509Negative::SelfSignedButClaimsCA.variant_name(),
            "self_signed_ca"
        );
    }

    #[test]
    fn deterministic_corruption_helpers_are_stable() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAA=\n-----END CERTIFICATE-----\n";
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x01];

        let pem_a = corrupt_cert_pem_deterministic(pem, "corrupt:v1");
        let pem_b = corrupt_cert_pem_deterministic(pem, "corrupt:v1");
        assert_eq!(pem_a, pem_b);

        let der_a = corrupt_cert_der_deterministic(&der, "corrupt:v1");
        let der_b = corrupt_cert_der_deterministic(&der, "corrupt:v1");
        assert_eq!(der_a, der_b);
    }
}
