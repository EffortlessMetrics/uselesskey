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
use uselesskey_core_x509_spec::{ChainSpec, KeyUsage, NotBeforeOffset};

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
    /// Leaf certificate is not yet valid.
    NotYetValidLeaf,
    /// Intermediate certificate is expired.
    ExpiredIntermediate,
    /// Intermediate certificate is not yet valid.
    NotYetValidIntermediate,
    /// Intermediate certificate no longer claims CA status.
    IntermediateNotCa,
    /// Intermediate certificate claims CA status but lacks CA signing usage.
    IntermediateWrongKeyUsage,
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
            ChainNegative::NotYetValidLeaf => "not_yet_valid_leaf".to_string(),
            ChainNegative::ExpiredIntermediate => "expired_intermediate".to_string(),
            ChainNegative::NotYetValidIntermediate => "not_yet_valid_intermediate".to_string(),
            ChainNegative::IntermediateNotCa => "intermediate_not_ca".to_string(),
            ChainNegative::IntermediateWrongKeyUsage => "intermediate_wrong_key_usage".to_string(),
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
                spec.leaf_not_before = Some(NotBeforeOffset::DaysAgo(730));
            }
            ChainNegative::NotYetValidLeaf => {
                spec.leaf_not_before = Some(NotBeforeOffset::DaysFromNow(730));
            }
            ChainNegative::ExpiredIntermediate => {
                spec.intermediate_validity_days = 1;
                spec.intermediate_not_before = Some(NotBeforeOffset::DaysAgo(730));
            }
            ChainNegative::NotYetValidIntermediate => {
                spec.intermediate_not_before = Some(NotBeforeOffset::DaysFromNow(730));
            }
            ChainNegative::IntermediateNotCa => {
                spec.intermediate_is_ca = Some(false);
            }
            ChainNegative::IntermediateWrongKeyUsage => {
                spec.intermediate_is_ca = Some(true);
                spec.intermediate_key_usage = Some(KeyUsage {
                    key_cert_sign: false,
                    crl_sign: false,
                    digital_signature: true,
                    key_encipherment: false,
                });
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
