#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

//! X.509 negative-fixture policy helpers.
//!
//! # Examples
//!
//! Apply a negative policy to a base X.509 spec:
//!
//! ```
//! use uselesskey_core_x509_negative::X509Negative;
//! use uselesskey_core_x509_spec::{NotBeforeOffset, X509Spec};
//!
//! let base = X509Spec::self_signed("test.example.com");
//! let expired = X509Negative::Expired.apply_to_spec(&base);
//! assert_eq!(expired.not_before_offset, NotBeforeOffset::DaysAgo(395));
//! ```

use uselesskey_core_x509_spec::{KeyUsage, NotBeforeOffset, X509Spec};

pub use uselesskey_core_x509_chain_negative::ChainNegative;

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
                // Certificate expired 30 days ago.
                // not_before was 395 days ago, valid for 365 days = expired 30 days ago.
                spec.not_before_offset = NotBeforeOffset::DaysAgo(395);
                spec.validity_days = 365;
            }
            X509Negative::NotYetValid => {
                // Certificate valid starting 30 days from now.
                spec.not_before_offset = NotBeforeOffset::DaysFromNow(30);
                spec.validity_days = 365;
            }
            X509Negative::WrongKeyUsage => {
                // Marked as CA but without key_cert_sign.
                spec.is_ca = true;
                spec.key_usage = KeyUsage {
                    key_cert_sign: false, // Wrong! CA should have this.
                    crl_sign: false,
                    digital_signature: true,
                    key_encipherment: true,
                };
            }
            X509Negative::SelfSignedButClaimsCA => {
                // Self-signed but claims to be CA with no real chain context.
                spec.is_ca = true;
                spec.key_usage = KeyUsage::ca();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x509_negative_expired_exact_values() {
        let base = X509Spec::self_signed("test");
        let modified = X509Negative::Expired.apply_to_spec(&base);

        assert_eq!(modified.not_before_offset, NotBeforeOffset::DaysAgo(395));
        assert_eq!(modified.validity_days, 365);
        assert!(!modified.is_ca);
        assert_eq!(modified.key_usage, KeyUsage::leaf());
    }

    #[test]
    fn x509_negative_not_yet_valid_exact_values() {
        let base = X509Spec::self_signed("test");
        let modified = X509Negative::NotYetValid.apply_to_spec(&base);

        assert_eq!(modified.not_before_offset, NotBeforeOffset::DaysFromNow(30));
        assert_eq!(modified.validity_days, 365);
    }

    #[test]
    fn x509_negative_wrong_key_usage_exact_values() {
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
    fn x509_negative_self_signed_ca_exact_values() {
        let base = X509Spec::self_signed("test");
        let modified = X509Negative::SelfSignedButClaimsCA.apply_to_spec(&base);

        assert!(modified.is_ca);
        assert_eq!(modified.key_usage, KeyUsage::ca());
    }

    #[test]
    fn x509_negative_variant_names_are_stable() {
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
    fn x509_negative_descriptions_are_stable() {
        assert_eq!(
            X509Negative::Expired.description(),
            "Certificate with not_after in the past (expired)"
        );
        assert_eq!(
            X509Negative::NotYetValid.description(),
            "Certificate with not_before in the future (not yet valid)"
        );
        assert_eq!(
            X509Negative::WrongKeyUsage.description(),
            "Certificate marked as CA but without keyCertSign key usage"
        );
        assert_eq!(
            X509Negative::SelfSignedButClaimsCA.description(),
            "Self-signed certificate that claims to be a CA"
        );
    }
}
