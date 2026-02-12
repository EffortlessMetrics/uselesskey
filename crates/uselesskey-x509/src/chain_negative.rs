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
    /// Chain is anchored to a different (unknown) root certificate identity.
    ///
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
                format!("hostname_mismatch:{}", wrong_hostname)
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
                // Use a different root CA CN so the chain anchors to a different root
                // certificate identity (a different trust anchor). Keys are reused
                // across variants; only cert-level identity/validity/SANs change.
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
            ChainNegative::RevokedLeaf => {
                // No spec changes needed. The chain is structurally valid;
                // the CRL listing the leaf as revoked is generated as a side-effect
                // in load_chain_inner when variant == "revoked_leaf".
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

    /// Get a chain anchored to a different (unknown) root certificate identity.
    ///
    /// This keeps key material stable and changes root certificate identity fields.
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

    /// Get a chain with a CRL listing the leaf certificate as revoked.
    ///
    /// The chain itself is structurally valid. The CRL is signed by the
    /// intermediate CA and lists the leaf serial as revoked with reason
    /// `KeyCompromise`.
    pub fn revoked_leaf(&self) -> X509Chain {
        self.negative(ChainNegative::RevokedLeaf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::fx;
    use uselesskey_core::Factory;

    #[test]
    fn test_hostname_mismatch() {
        let factory = fx();
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
        use x509_parser::prelude::*;

        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        let unknown = chain.unknown_ca();
        // Root cert should be different (different CA)
        assert_ne!(chain.root_cert_der(), unknown.root_cert_der());

        let (_, good_root) = X509Certificate::from_der(chain.root_cert_der()).expect("parse root");
        let (_, unknown_root) =
            X509Certificate::from_der(unknown.root_cert_der()).expect("parse unknown root");
        let (_, unknown_int) = X509Certificate::from_der(unknown.intermediate_cert_der())
            .expect("parse unknown intermediate");

        // UnknownCa changes root certificate identity, not key material.
        assert_ne!(good_root.subject(), unknown_root.subject());
        assert_eq!(unknown_int.issuer(), unknown_root.subject());
        assert_ne!(unknown_int.issuer(), good_root.subject());
        assert_eq!(
            chain.root_private_key_pkcs8_der(),
            unknown.root_private_key_pkcs8_der()
        );
    }

    #[test]
    fn test_expired_leaf() {
        let factory = fx();
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
        assert!(not_after < now - 86400 * 365);
    }

    #[test]
    fn test_expired_intermediate() {
        let factory = fx();
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
        assert!(not_after < now - 86400 * 365);
    }

    #[test]
    fn test_negative_variants_reuse_keys() {
        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let good = X509Chain::new(factory.clone(), "test", spec);

        let variants: Vec<X509Chain> = vec![
            good.expired_leaf(),
            good.expired_intermediate(),
            good.unknown_ca(),
            good.hostname_mismatch("wrong.example.com"),
            good.revoked_leaf(),
        ];

        for variant in &variants {
            // Keys should match the good chain (same underlying RSA keys)
            assert_eq!(
                good.leaf_private_key_pkcs8_der(),
                variant.leaf_private_key_pkcs8_der()
            );
            // But certs should differ (different cert-level parameters)
            assert_ne!(good.leaf_cert_der(), variant.leaf_cert_der());
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
        assert_eq!(ChainNegative::RevokedLeaf.variant_name(), "revoked_leaf");
    }

    #[test]
    fn test_revoked_leaf_crl_present() {
        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let good = X509Chain::new(factory, "test", spec);

        // Good chain should have no CRL
        assert!(good.crl_der().is_none());
        assert!(good.crl_pem().is_none());

        // Revoked leaf chain should have a CRL
        let revoked = good.revoked_leaf();
        assert!(revoked.crl_der().is_some());
        assert!(revoked.crl_pem().is_some());
        let crl_pem = revoked.crl_pem().unwrap();
        assert!(crl_pem.contains("-----BEGIN X509 CRL-----"));
    }

    #[test]
    fn test_revoked_leaf_crl_contains_leaf_serial() {
        use x509_parser::prelude::*;

        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let good = X509Chain::new(factory, "test", spec);
        let revoked = good.revoked_leaf();

        // Parse the leaf cert to get its serial number
        let (_, leaf) =
            X509Certificate::from_der(revoked.leaf_cert_der()).expect("parse leaf cert");
        let leaf_serial = &leaf.serial;

        // Parse the CRL and verify it lists the leaf serial
        let crl_der = revoked.crl_der().expect("CRL should be present");
        let (_, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(crl_der)
            .expect("parse CRL");

        let revoked_certs: Vec<_> = crl.iter_revoked_certificates().collect();
        assert_eq!(revoked_certs.len(), 1);
        assert_eq!(revoked_certs[0].raw_serial(), leaf_serial.to_bytes_be());
    }

    #[test]
    fn test_revoked_leaf_determinism() {
        use uselesskey_core::Seed;

        let seed = Seed::from_env_value("test-seed").unwrap();
        let factory = Factory::deterministic(seed);
        let spec = ChainSpec::new("test.example.com");
        let good = X509Chain::new(factory.clone(), "test", spec.clone());
        let revoked1 = good.revoked_leaf();

        factory.clear_cache();
        let good2 = X509Chain::new(factory, "test", spec);
        let revoked2 = good2.revoked_leaf();

        assert_eq!(revoked1.crl_der().unwrap(), revoked2.crl_der().unwrap());
        assert_eq!(revoked1.crl_pem().unwrap(), revoked2.crl_pem().unwrap());
    }

    #[test]
    fn test_revoked_leaf_crl_tempfile() {
        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let good = X509Chain::new(factory, "test", spec);

        // Good chain should return None for CRL tempfiles
        assert!(good.write_crl_pem().is_none());
        assert!(good.write_crl_der().is_none());

        // Revoked leaf chain should write CRL tempfiles
        let revoked = good.revoked_leaf();
        let crl_pem_file = revoked.write_crl_pem().unwrap().unwrap();
        assert!(crl_pem_file.path().exists());

        let crl_der_file = revoked.write_crl_der().unwrap().unwrap();
        assert!(crl_der_file.path().exists());
    }
}
