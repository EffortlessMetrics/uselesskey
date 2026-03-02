//! X.509 chain-level negative-fixture policy helpers.
//!
//! Defines [`ChainNegative`] variants (hostname mismatch, unknown CA,
//! expired leaf/intermediate, revoked leaf) and provides
//! [`ChainNegative::apply_to_spec`] to derive a modified [`ChainSpec`]
//! for each scenario. Used by `uselesskey-x509` to produce invalid
//! certificate chains for TLS error-handling tests.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::{String, ToString};
use uselesskey_core_x509_spec::ChainSpec;

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
    use uselesskey_core_x509_spec::ChainSpec;

    #[test]
    fn variant_names_are_stable() {
        assert_eq!(
            ChainNegative::HostnameMismatch {
                wrong_hostname: "evil.test".to_string(),
            }
            .variant_name(),
            "hostname_mismatch:evil.test"
        );
        assert_eq!(ChainNegative::UnknownCa.variant_name(), "unknown_ca");
        assert_eq!(ChainNegative::ExpiredLeaf.variant_name(), "expired_leaf");
        assert_eq!(
            ChainNegative::ExpiredIntermediate.variant_name(),
            "expired_intermediate"
        );
        assert_eq!(ChainNegative::RevokedLeaf.variant_name(), "revoked_leaf");
    }

    #[test]
    fn variant_names_are_distinguishable() {
        let variants: [ChainNegative; 5] = [
            ChainNegative::HostnameMismatch {
                wrong_hostname: "evil.test".to_string(),
            },
            ChainNegative::UnknownCa,
            ChainNegative::ExpiredLeaf,
            ChainNegative::ExpiredIntermediate,
            ChainNegative::RevokedLeaf,
        ];
        let names: Vec<String> = variants.iter().map(|v| v.variant_name()).collect();
        for (i, a) in names.iter().enumerate() {
            for b in &names[i + 1..] {
                assert_ne!(a, b, "variant names must be unique");
            }
        }
    }

    #[test]
    fn hostname_mismatch_variant_name_includes_hostname() {
        let v = ChainNegative::HostnameMismatch {
            wrong_hostname: "attacker.example.com".to_string(),
        };
        let name = v.variant_name();
        assert!(
            name.contains("attacker.example.com"),
            "variant name must include the hostname: {name}"
        );
    }

    #[test]
    fn debug_variants_are_distinguishable() {
        let variants: [ChainNegative; 5] = [
            ChainNegative::HostnameMismatch {
                wrong_hostname: "evil.test".to_string(),
            },
            ChainNegative::UnknownCa,
            ChainNegative::ExpiredLeaf,
            ChainNegative::ExpiredIntermediate,
            ChainNegative::RevokedLeaf,
        ];
        let debug_strs: Vec<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        for (i, a) in debug_strs.iter().enumerate() {
            for b in &debug_strs[i + 1..] {
                assert_ne!(a, b, "Debug output must be unique per variant");
            }
        }
    }

    #[test]
    fn apply_hostname_mismatch_changes_leaf_cn_and_sans() {
        let base = ChainSpec::new("good.example.com");
        let neg = ChainNegative::HostnameMismatch {
            wrong_hostname: "evil.example.com".to_string(),
        };
        let modified = neg.apply_to_spec(&base);
        assert_eq!(modified.leaf_cn, "evil.example.com");
        assert_eq!(modified.leaf_sans, ["evil.example.com"]);
        // Root and intermediate must be unchanged.
        assert_eq!(modified.root_cn, base.root_cn);
        assert_eq!(modified.intermediate_cn, base.intermediate_cn);
    }

    #[test]
    fn apply_unknown_ca_changes_root_cn() {
        let base = ChainSpec::new("app.example.com");
        let modified = ChainNegative::UnknownCa.apply_to_spec(&base);
        assert!(
            modified.root_cn.contains("Unknown Root CA"),
            "root_cn must indicate unknown CA: {}",
            modified.root_cn
        );
        assert_ne!(modified.root_cn, base.root_cn);
        // Leaf must be unchanged.
        assert_eq!(modified.leaf_cn, base.leaf_cn);
    }

    #[test]
    fn apply_expired_leaf_sets_past_validity() {
        let base = ChainSpec::new("app.example.com");
        let modified = ChainNegative::ExpiredLeaf.apply_to_spec(&base);
        assert_eq!(modified.leaf_validity_days, 1);
        assert_eq!(modified.leaf_not_before_offset_days, Some(730));
    }

    #[test]
    fn apply_expired_intermediate_sets_past_validity() {
        let base = ChainSpec::new("app.example.com");
        let modified = ChainNegative::ExpiredIntermediate.apply_to_spec(&base);
        assert_eq!(modified.intermediate_validity_days, 1);
        assert_eq!(modified.intermediate_not_before_offset_days, Some(730));
    }

    #[test]
    fn apply_revoked_leaf_does_not_change_spec() {
        let base = ChainSpec::new("app.example.com");
        let modified = ChainNegative::RevokedLeaf.apply_to_spec(&base);
        assert_eq!(modified, base);
    }

    #[test]
    fn different_wrong_hostnames_produce_different_variant_names() {
        let a = ChainNegative::HostnameMismatch {
            wrong_hostname: "a.test".to_string(),
        };
        let b = ChainNegative::HostnameMismatch {
            wrong_hostname: "b.test".to_string(),
        };
        assert_ne!(a.variant_name(), b.variant_name());
    }
}
