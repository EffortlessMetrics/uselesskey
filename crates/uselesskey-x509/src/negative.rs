//! X.509 negative-fixture helpers.
//!
//! Policy enums and spec mutations are defined in `uselesskey-core-x509`
//! and re-exported by this crate.

pub use uselesskey_core_x509::X509Negative;

/// Corrupt a PEM-encoded certificate.
///
/// Delegates to the core negative fixture helpers.
///
/// # Examples
///
/// ```
/// use uselesskey_core::negative::CorruptPem;
/// use uselesskey_x509::negative::corrupt_cert_pem;
///
/// let pem = "-----BEGIN CERTIFICATE-----\nAAA=\n-----END CERTIFICATE-----\n";
/// let corrupted = corrupt_cert_pem(pem, CorruptPem::BadHeader);
/// assert_ne!(corrupted, pem);
/// ```
pub fn corrupt_cert_pem(pem: &str, how: uselesskey_core::negative::CorruptPem) -> String {
    uselesskey_core::negative::corrupt_pem(pem, how)
}

/// Corrupt a PEM-encoded certificate using a deterministic variant string.
///
/// # Examples
///
/// ```
/// use uselesskey_x509::negative::corrupt_cert_pem_deterministic;
///
/// let pem = "-----BEGIN CERTIFICATE-----\nAAA=\n-----END CERTIFICATE-----\n";
/// let corrupted = corrupt_cert_pem_deterministic(pem, "corrupt:v1");
/// assert_ne!(corrupted, pem);
/// // Same variant always produces the same result
/// assert_eq!(corrupted, corrupt_cert_pem_deterministic(pem, "corrupt:v1"));
/// ```
pub fn corrupt_cert_pem_deterministic(pem: &str, variant: &str) -> String {
    uselesskey_core::negative::corrupt_pem_deterministic(pem, variant)
}

/// Truncate a DER-encoded certificate.
///
/// Delegates to the core negative fixture helpers.
///
/// # Examples
///
/// ```
/// use uselesskey_x509::negative::truncate_cert_der;
///
/// let der = vec![0x30, 0x03, 0x02, 0x01, 0x01];
/// let truncated = truncate_cert_der(&der, 2);
/// assert_eq!(truncated.len(), 2);
/// ```
pub fn truncate_cert_der(der: &[u8], len: usize) -> Vec<u8> {
    uselesskey_core::negative::truncate_der(der, len)
}

/// Corrupt a DER-encoded certificate using a deterministic variant string.
///
/// # Examples
///
/// ```
/// use uselesskey_x509::negative::corrupt_cert_der_deterministic;
///
/// let der = vec![0x30, 0x03, 0x02, 0x01, 0x01];
/// let corrupted = corrupt_cert_der_deterministic(&der, "corrupt:v1");
/// assert_ne!(corrupted, der);
/// // Same variant always produces the same result
/// assert_eq!(corrupted, corrupt_cert_der_deterministic(&der, "corrupt:v1"));
/// ```
pub fn corrupt_cert_der_deterministic(der: &[u8], variant: &str) -> Vec<u8> {
    uselesskey_core::negative::corrupt_der_deterministic(der, variant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core_x509::{KeyUsage, NotBeforeOffset, X509Spec};

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

        // Stability.
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

        // Stability.
        let corrupted2 = corrupt_cert_der_deterministic(&der, "corrupt:v1");
        assert_eq!(
            corrupted, corrupted2,
            "same variant must produce same result"
        );
    }
}
