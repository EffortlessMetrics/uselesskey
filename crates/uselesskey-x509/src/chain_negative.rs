//! Negative fixtures for X.509 certificate chains.

use crate::chain::X509Chain;
use crate::chain_spec::ChainSpec;

/// Types of invalid certificate chains for negative testing.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ChainNegative {
    /// Leaf cert has a SAN that doesn't match the expected hostname.
    HostnameMismatch {
        /// The wrong hostname to put in the leaf SAN.
        wrong_hostname: String,
    },
    /// Chain is signed by a different (unknown) root CA.
    UnknownCa,
    /// Leaf certificate is expired.
    ExpiredLeaf,
    /// Intermediate certificate is expired.
    ExpiredIntermediate,
}

impl ChainNegative {
    /// Variant name for cache keys.
    pub fn variant_name(&self) -> String {
        match self {
            ChainNegative::HostnameMismatch { wrong_hostname } => {
                format!("hostname_mismatch:{}", wrong_hostname)
            }
            ChainNegative::UnknownCa => "unknown_ca".to_string(),
            ChainNegative::ExpiredLeaf => "expired_leaf".to_string(),
            ChainNegative::ExpiredIntermediate => "expired_intermediate".to_string(),
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
                // Use a different root CA CN so the root cert is issued by an unrecognized authority
                spec.root_cn = format!("{} Unknown Root CA", spec.leaf_cn);
            }
            ChainNegative::ExpiredLeaf => {
                // Push not_before 730 days into the past with 1-day validity,
                // so not_after = base_time - 729 days — unambiguously expired
                // regardless of where base_time lands (2025–2026).
                spec.leaf_validity_days = 1;
                spec.leaf_not_before_offset_days = Some(730);
            }
            ChainNegative::ExpiredIntermediate => {
                spec.intermediate_validity_days = 1;
                spec.intermediate_not_before_offset_days = Some(730);
            }
        }
        spec
    }
}

impl X509Chain {
    /// Generate a negative fixture variant of this chain.
    ///
    /// The variant is cached separately from the valid chain.
    pub fn negative(&self, neg: ChainNegative) -> X509Chain {
        let modified_spec = neg.apply_to_spec(self.spec());
        let variant = neg.variant_name();
        X509Chain::with_variant(
            self.factory().clone(),
            self.label(),
            modified_spec,
            &variant,
        )
    }

    /// Get a chain where the leaf cert has a hostname mismatch.
    pub fn hostname_mismatch(&self, hostname: impl Into<String>) -> X509Chain {
        self.negative(ChainNegative::HostnameMismatch {
            wrong_hostname: hostname.into(),
        })
    }

    /// Get a chain signed by a different (unknown) root CA.
    pub fn unknown_ca(&self) -> X509Chain {
        self.negative(ChainNegative::UnknownCa)
    }

    /// Get a chain where the leaf certificate has a very short validity period.
    pub fn expired_leaf(&self) -> X509Chain {
        self.negative(ChainNegative::ExpiredLeaf)
    }

    /// Get a chain where the intermediate certificate has a very short validity period.
    pub fn expired_intermediate(&self) -> X509Chain {
        self.negative(ChainNegative::ExpiredIntermediate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core::Factory;

    #[test]
    fn test_hostname_mismatch() {
        let factory = Factory::random();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        let mismatched = chain.hostname_mismatch("wrong.example.com");
        assert_ne!(chain.leaf_cert_der(), mismatched.leaf_cert_der());

        // Root and intermediate should use the same spec (different variant though)
        // but the leaf CN should differ
        use x509_parser::prelude::*;
        let (_, leaf) = X509Certificate::from_der(mismatched.leaf_cert_der()).expect("parse leaf");
        let cn = leaf
            .subject()
            .iter_common_name()
            .next()
            .expect("leaf should have CN");
        let cn_str = cn.as_str().expect("CN should be string");
        assert_eq!(cn_str, "wrong.example.com");
    }

    #[test]
    fn test_unknown_ca() {
        let factory = Factory::random();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        let unknown = chain.unknown_ca();
        // Root cert should be different (different CA)
        assert_ne!(chain.root_cert_der(), unknown.root_cert_der());
    }

    #[test]
    fn test_expired_leaf() {
        let factory = Factory::random();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        let expired = chain.expired_leaf();
        assert_ne!(chain.leaf_cert_der(), expired.leaf_cert_der());

        // Verify the leaf is unambiguously expired: not_after should be in the past
        use x509_parser::prelude::*;
        let (_, leaf) = X509Certificate::from_der(expired.leaf_cert_der()).expect("parse leaf");
        let validity = leaf.validity();
        let not_before = validity.not_before.timestamp();
        let not_after = validity.not_after.timestamp();
        let diff_days = (not_after - not_before) / 86400;
        assert!(diff_days <= 1, "validity period should be 1 day");

        // not_after should be well in the past (at least 365 days ago)
        let now = ::time::OffsetDateTime::now_utc().unix_timestamp();
        assert!(
            not_after < now - 86400 * 365,
            "expired leaf not_after ({not_after}) should be >365 days before now ({now})"
        );
    }

    #[test]
    fn test_expired_intermediate() {
        let factory = Factory::random();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        let expired = chain.expired_intermediate();
        assert_ne!(
            chain.intermediate_cert_der(),
            expired.intermediate_cert_der()
        );

        // Verify the intermediate is unambiguously expired
        use x509_parser::prelude::*;
        let (_, int) =
            X509Certificate::from_der(expired.intermediate_cert_der()).expect("parse intermediate");
        let not_after = int.validity().not_after.timestamp();
        let now = ::time::OffsetDateTime::now_utc().unix_timestamp();
        assert!(
            not_after < now - 86400 * 365,
            "expired intermediate not_after ({not_after}) should be >365 days before now ({now})"
        );
    }

    #[test]
    fn test_negative_variants_reuse_keys() {
        let factory = Factory::random();
        let spec = ChainSpec::new("test.example.com");
        let good = X509Chain::new(factory.clone(), "test", spec);

        let variants: Vec<X509Chain> = vec![
            good.expired_leaf(),
            good.expired_intermediate(),
            good.unknown_ca(),
            good.hostname_mismatch("wrong.example.com"),
        ];

        for variant in &variants {
            // Keys should match the good chain (same underlying RSA keys)
            assert_eq!(
                good.leaf_private_key_pkcs8_der(),
                variant.leaf_private_key_pkcs8_der(),
                "leaf key should be reused"
            );
            // But certs should differ (different cert-level parameters)
            assert_ne!(
                good.leaf_cert_der(),
                variant.leaf_cert_der(),
                "leaf cert should differ"
            );
        }
    }

    #[test]
    fn test_variant_name() {
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
    }
}
