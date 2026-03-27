//! Negative fixtures for X.509 certificate chains.

use uselesskey_core_x509::ChainNegative;

use crate::chain::X509Chain;

impl X509Chain {
    /// Generate a negative fixture variant of this chain.
    ///
    /// The variant is cached separately from the valid chain.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// use uselesskey_core_x509::ChainNegative;
    ///
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// let expired = chain.negative(ChainNegative::ExpiredLeaf);
    /// assert_ne!(chain.leaf_cert_der(), expired.leaf_cert_der());
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// let wrong = chain.hostname_mismatch("wrong.example.com");
    /// assert_ne!(chain.leaf_cert_der(), wrong.leaf_cert_der());
    /// ```
    pub fn hostname_mismatch(&self, hostname: impl Into<String>) -> X509Chain {
        self.negative(ChainNegative::HostnameMismatch {
            wrong_hostname: hostname.into(),
        })
    }

    /// Get a chain anchored to a different (unknown) root certificate identity.
    ///
    /// This keeps key material stable and changes root certificate identity fields.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// let untrusted = chain.unknown_ca();
    /// assert_ne!(chain.root_cert_der(), untrusted.root_cert_der());
    /// ```
    pub fn unknown_ca(&self) -> X509Chain {
        self.negative(ChainNegative::UnknownCa)
    }

    /// Get a chain where the leaf certificate has a very short validity period.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// let expired = chain.expired_leaf();
    /// assert_ne!(chain.leaf_cert_der(), expired.leaf_cert_der());
    /// ```
    pub fn expired_leaf(&self) -> X509Chain {
        self.negative(ChainNegative::ExpiredLeaf)
    }

    /// Get a chain where the leaf certificate is not yet valid.
    pub fn not_yet_valid_leaf(&self) -> X509Chain {
        self.negative(ChainNegative::NotYetValidLeaf)
    }

    /// Get a chain where the intermediate certificate has a very short validity period.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// let expired = chain.expired_intermediate();
    /// assert_ne!(chain.intermediate_cert_der(), expired.intermediate_cert_der());
    /// ```
    pub fn expired_intermediate(&self) -> X509Chain {
        self.negative(ChainNegative::ExpiredIntermediate)
    }

    /// Get a chain where the intermediate certificate is not yet valid.
    pub fn not_yet_valid_intermediate(&self) -> X509Chain {
        self.negative(ChainNegative::NotYetValidIntermediate)
    }

    /// Get a chain where the intermediate no longer claims CA status.
    pub fn intermediate_not_ca(&self) -> X509Chain {
        self.negative(ChainNegative::IntermediateNotCa)
    }

    /// Get a chain where the intermediate claims CA but lacks CA signing usage.
    pub fn intermediate_wrong_key_usage(&self) -> X509Chain {
        self.negative(ChainNegative::IntermediateWrongKeyUsage)
    }

    /// Get a chain with a CRL listing the leaf certificate as revoked.
    ///
    /// The chain itself is structurally valid. The CRL is signed by the
    /// intermediate CA and lists the leaf serial as revoked with reason
    /// `KeyCompromise`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// let revoked = chain.revoked_leaf();
    /// assert!(revoked.crl_der().is_some());
    /// ```
    pub fn revoked_leaf(&self) -> X509Chain {
        self.negative(ChainNegative::RevokedLeaf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::fx;
    use uselesskey_core::Factory;
    use uselesskey_core_x509::ChainSpec;

    #[test]
    fn test_hostname_mismatch() {
        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        let mismatched = chain.hostname_mismatch("wrong.example.com");
        assert_ne!(chain.leaf_cert_der(), mismatched.leaf_cert_der());

        // Root and intermediate should use the same spec (different variant though)
        // but the leaf CN should differ.
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
        // Root cert should be different (different CA).
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

        // Verify the leaf is unambiguously expired: not_after should be in the past.
        use x509_parser::prelude::*;
        let (_, leaf) = X509Certificate::from_der(expired.leaf_cert_der()).expect("parse leaf");
        let validity = leaf.validity();
        let not_before = validity.not_before.timestamp();
        let not_after = validity.not_after.timestamp();
        let diff_days = (not_after - not_before) / 86400;
        assert!(diff_days <= 1, "validity period should be 1 day");

        // not_after should be well in the past (at least 365 days ago).
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

        // Verify the intermediate is unambiguously expired.
        use x509_parser::prelude::*;
        let (_, int) =
            X509Certificate::from_der(expired.intermediate_cert_der()).expect("parse intermediate");
        let not_after = int.validity().not_after.timestamp();
        let now = ::time::OffsetDateTime::now_utc().unix_timestamp();
        assert!(not_after < now - 86400 * 365);
    }

    #[test]
    fn test_not_yet_valid_leaf() {
        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        let future = chain.not_yet_valid_leaf();
        assert_ne!(chain.leaf_cert_der(), future.leaf_cert_der());

        use x509_parser::prelude::*;
        let (_, leaf) =
            X509Certificate::from_der(future.leaf_cert_der()).expect("parse future leaf");
        let not_before = leaf.validity().not_before.timestamp();
        let now = ::time::OffsetDateTime::now_utc().unix_timestamp();
        assert!(not_before > now, "not_before should be in the future");
    }

    #[test]
    fn test_not_yet_valid_intermediate() {
        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        let future = chain.not_yet_valid_intermediate();
        assert_ne!(
            chain.intermediate_cert_der(),
            future.intermediate_cert_der()
        );

        use x509_parser::prelude::*;
        let (_, int) = X509Certificate::from_der(future.intermediate_cert_der())
            .expect("parse future intermediate");
        let not_before = int.validity().not_before.timestamp();
        let now = ::time::OffsetDateTime::now_utc().unix_timestamp();
        assert!(not_before > now, "not_before should be in the future");
    }

    #[test]
    fn test_intermediate_not_ca() {
        use x509_parser::prelude::*;

        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        let bad = chain.intermediate_not_ca();
        assert_ne!(chain.intermediate_cert_der(), bad.intermediate_cert_der());

        let (_, int) =
            X509Certificate::from_der(bad.intermediate_cert_der()).expect("parse intermediate");
        assert!(!int.is_ca(), "intermediate should not claim CA");
    }

    #[test]
    fn test_intermediate_wrong_key_usage() {
        use x509_parser::extensions::ParsedExtension;
        use x509_parser::prelude::*;

        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        let bad = chain.intermediate_wrong_key_usage();
        assert_ne!(chain.intermediate_cert_der(), bad.intermediate_cert_der());

        let (_, int) =
            X509Certificate::from_der(bad.intermediate_cert_der()).expect("parse intermediate");
        assert!(int.is_ca(), "intermediate should still claim CA");

        let key_usage = int
            .extensions()
            .iter()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::KeyUsage(ku) => Some(ku),
                _ => None,
            })
            .expect("key usage extension");
        assert!(
            !key_usage.key_cert_sign(),
            "intermediate should be missing keyCertSign"
        );
    }

    #[test]
    fn test_negative_variants_reuse_keys() {
        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let good = X509Chain::new(factory.clone(), "test", spec);

        let variants: Vec<X509Chain> = vec![
            good.expired_leaf(),
            good.not_yet_valid_leaf(),
            good.expired_intermediate(),
            good.not_yet_valid_intermediate(),
            good.unknown_ca(),
            good.hostname_mismatch("wrong.example.com"),
            good.intermediate_not_ca(),
            good.intermediate_wrong_key_usage(),
            good.revoked_leaf(),
        ];

        for variant in &variants {
            // Keys should match the good chain (same underlying RSA keys).
            assert_eq!(
                good.leaf_private_key_pkcs8_der(),
                variant.leaf_private_key_pkcs8_der()
            );
            // But certs should differ (different cert-level parameters).
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
            ChainNegative::NotYetValidLeaf.variant_name(),
            "not_yet_valid_leaf"
        );
        assert_eq!(
            ChainNegative::ExpiredIntermediate.variant_name(),
            "expired_intermediate"
        );
        assert_eq!(
            ChainNegative::NotYetValidIntermediate.variant_name(),
            "not_yet_valid_intermediate"
        );
        assert_eq!(
            ChainNegative::IntermediateNotCa.variant_name(),
            "intermediate_not_ca"
        );
        assert_eq!(
            ChainNegative::IntermediateWrongKeyUsage.variant_name(),
            "intermediate_wrong_key_usage"
        );
        assert_eq!(ChainNegative::RevokedLeaf.variant_name(), "revoked_leaf");
    }

    #[test]
    fn test_revoked_leaf_crl_present() {
        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let good = X509Chain::new(factory, "test", spec);

        // Good chain should have no CRL.
        assert!(good.crl_der().is_none());
        assert!(good.crl_pem().is_none());

        // Revoked leaf chain should have a CRL.
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

        // Parse the leaf cert to get its serial number.
        let (_, leaf) =
            X509Certificate::from_der(revoked.leaf_cert_der()).expect("parse leaf cert");
        let leaf_serial = &leaf.serial;

        // Parse the CRL and verify it lists the leaf serial.
        let crl_der = revoked.crl_der().expect("CRL should be present");
        let (_, crl) = x509_parser::revocation_list::CertificateRevocationList::from_der(crl_der)
            .expect("parse CRL");

        let revoked_certs: Vec<_> = crl.iter_revoked_certificates().collect();
        assert_eq!(revoked_certs.len(), 1);
        assert_eq!(revoked_certs[0].raw_serial(), leaf_serial.to_bytes_be());

        // CRL next_update must be after this_update.
        let this_update = crl.last_update().timestamp();
        let next_update = crl.next_update().expect("next_update").timestamp();
        assert!(
            next_update > this_update,
            "CRL next_update must be after this_update"
        );
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

        // Good chain should return None for CRL tempfiles.
        assert!(good.write_crl_pem().is_none());
        assert!(good.write_crl_der().is_none());

        // Revoked leaf chain should write CRL tempfiles.
        let revoked = good.revoked_leaf();
        let crl_pem_file = revoked.write_crl_pem().unwrap().unwrap();
        assert!(crl_pem_file.path().exists());

        let crl_der_file = revoked.write_crl_der().unwrap().unwrap();
        assert!(crl_der_file.path().exists());
    }
}
