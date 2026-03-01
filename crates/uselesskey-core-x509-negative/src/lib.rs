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
//! use uselesskey_core_x509_spec::{X509Spec, NotBeforeOffset};
//!
//! let base = X509Spec::self_signed("test.example.com");
//! let expired = X509Negative::Expired.apply_to_spec(&base);
//! assert_eq!(expired.not_before_offset, NotBeforeOffset::DaysAgo(395));
//! ```
//!
//! Chain-level negative fixtures:
//!
//! ```
//! use uselesskey_core_x509_negative::ChainNegative;
//! use uselesskey_core_x509_spec::ChainSpec;
//!
//! let base = ChainSpec::new("api.example.com");
//! let neg = ChainNegative::UnknownCa;
//! let modified = neg.apply_to_spec(&base);
//! assert!(modified.root_cn.contains("Unknown"));
//! ```

extern crate alloc;

use alloc::string::{String, ToString};
use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset, X509Spec};

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

/// Types of invalid certificate chains for negative testing.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ChainNegative {
    /// Leaf cert has a SAN that doesn't match the expected hostname.
    HostnameMismatch {
        /// The wrong hostname to put in the leaf SAN.
        wrong_hostname: String,
    },
    /// Chain is anchored to a different (unknown) root certificate identity.
    /// This variant intentionally reuses the same underlying RSA key material
    /// and changes certificate-level identity fields for the root certificate.
    UnknownCa,
    /// Leaf certificate is expired.
    ExpiredLeaf,
    /// Intermediate certificate is expired.
    ExpiredIntermediate,
    /// Leaf certificate is listed as revoked in a CRL signed by the intermediate CA.
    RevokedLeaf,
}

impl ChainNegative {
    /// Variant name for cache keys.
    pub fn variant_name(&self) -> String {
        match self {
            ChainNegative::HostnameMismatch { wrong_hostname } => {
                format!("hostname_mismatch:{wrong_hostname}")
            }
            ChainNegative::UnknownCa => "unknown_ca".to_string(),
            ChainNegative::ExpiredLeaf => "expired_leaf".to_string(),
            ChainNegative::ExpiredIntermediate => "expired_intermediate".to_string(),
            ChainNegative::RevokedLeaf => "revoked_leaf".to_string(),
        }
    }

    /// Apply this negative variant to a chain spec.
    pub fn apply_to_spec(&self, base_spec: &ChainSpec) -> ChainSpec {
        let mut spec = base_spec.clone();
        match self {
            ChainNegative::HostnameMismatch { wrong_hostname } => {
                spec.leaf_cn = wrong_hostname.clone();
                spec.leaf_sans = vec![wrong_hostname.clone()];
            }
            ChainNegative::UnknownCa => {
                // Use a different root CA CN so the chain anchors to a different root.
                spec.root_cn = format!("{} Unknown Root CA", spec.leaf_cn);
            }
            ChainNegative::ExpiredLeaf => {
                // Push not_before 730 days into the past with 1-day validity,
                // so not_after = base_time - 729 days - unambiguously expired.
                spec.leaf_validity_days = 1;
                spec.leaf_not_before_offset_days = Some(730);
            }
            ChainNegative::ExpiredIntermediate => {
                spec.intermediate_validity_days = 1;
                spec.intermediate_not_before_offset_days = Some(730);
            }
            ChainNegative::RevokedLeaf => {
                // No spec changes needed. The chain is structurally valid;
                // the CRL listing the leaf as revoked is generated as a side-effect
                // by the X.509 fixture producer for this variant.
            }
        }
        spec
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

    #[test]
    fn chain_negative_variant_names_are_stable() {
        let neg = ChainNegative::HostnameMismatch {
            wrong_hostname: "wrong.example.com".to_string(),
        };
        assert_eq!(neg.variant_name(), "hostname_mismatch:wrong.example.com");
        assert_eq!(ChainNegative::UnknownCa.variant_name(), "unknown_ca");
        assert_eq!(ChainNegative::ExpiredLeaf.variant_name(), "expired_leaf");
        assert_eq!(
            ChainNegative::ExpiredIntermediate.variant_name(),
            "expired_intermediate"
        );
        assert_eq!(ChainNegative::RevokedLeaf.variant_name(), "revoked_leaf");
    }

    #[test]
    fn chain_negative_apply_to_spec_all_variants() {
        let base = ChainSpec::new("neg-test.example.com");

        let hostname_neg = ChainNegative::HostnameMismatch {
            wrong_hostname: "wrong.example.com".to_string(),
        };
        let modified = hostname_neg.apply_to_spec(&base);
        assert_eq!(modified.leaf_cn, "wrong.example.com");
        assert_eq!(modified.leaf_sans, vec!["wrong.example.com".to_string()]);

        let unknown_neg = ChainNegative::UnknownCa;
        let modified = unknown_neg.apply_to_spec(&base);
        assert!(
            modified.root_cn.contains("Unknown"),
            "UnknownCa should modify root_cn"
        );

        let expired_leaf_neg = ChainNegative::ExpiredLeaf;
        let modified = expired_leaf_neg.apply_to_spec(&base);
        assert_eq!(modified.leaf_validity_days, 1);
        assert_eq!(modified.leaf_not_before_offset_days, Some(730));

        let expired_int_neg = ChainNegative::ExpiredIntermediate;
        let modified = expired_int_neg.apply_to_spec(&base);
        assert_eq!(modified.intermediate_validity_days, 1);
        assert_eq!(modified.intermediate_not_before_offset_days, Some(730));

        let revoked_neg = ChainNegative::RevokedLeaf;
        let modified = revoked_neg.apply_to_spec(&base);
        assert_eq!(modified.leaf_cn, base.leaf_cn);
        assert_eq!(modified.leaf_validity_days, base.leaf_validity_days);
    }
}
