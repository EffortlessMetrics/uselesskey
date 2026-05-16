//! X.509 certificate generation and output.

mod material;
mod negative;
mod output;

use std::fmt;
use std::sync::Arc;

use uselesskey_core::Factory;

use self::material::Inner;
use crate::chain::X509Chain;
use crate::srp::spec::{ChainSpec, X509Spec};

/// Cache domain for X.509 certificate fixtures.
///
/// Keep this stable: changing it changes deterministic outputs.
pub const DOMAIN_X509_CERT: &str = "uselesskey:x509:cert";

/// An X.509 certificate fixture.
///
/// Created via [`X509FactoryExt::x509_self_signed()`]. Provides access to:
/// - Certificate in PEM and DER formats
/// - Private key in PKCS#8 PEM and DER formats
/// - Combined identity PEM (cert + key)
/// - Negative fixtures (expired, not-yet-valid, wrong key usage, corrupt PEM)
///
/// # Examples
///
/// ```no_run
/// # use uselesskey_core::{Factory, Seed};
/// # use uselesskey_x509::{X509FactoryExt, X509Spec};
/// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
/// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
///
/// assert!(cert.cert_pem().contains("-----BEGIN CERTIFICATE-----"));
/// assert!(cert.private_key_pkcs8_pem().contains("-----BEGIN PRIVATE KEY-----"));
/// ```
#[derive(Clone)]
pub struct X509Cert {
    factory: Factory,
    label: String,
    spec: X509Spec,
    inner: Arc<Inner>,
}

impl fmt::Debug for X509Cert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X509Cert")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

/// Extension trait to add X.509 certificate generation to [`Factory`].
pub trait X509FactoryExt {
    /// Generate a self-signed X.509 certificate.
    ///
    /// The certificate is cached by `(label, spec)` and will be reused on subsequent calls
    /// with the same parameters.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let spec = X509Spec::self_signed("test.example.com");
    /// let cert = fx.x509_self_signed("my-service", spec);
    /// assert!(cert.cert_pem().contains("-----BEGIN CERTIFICATE-----"));
    /// ```
    fn x509_self_signed(&self, label: impl AsRef<str>, spec: X509Spec) -> X509Cert;

    /// Generate a three-level X.509 certificate chain (root CA → intermediate CA → leaf).
    ///
    /// The chain is cached by `(label, spec)` and will be reused on subsequent calls
    /// with the same parameters.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("my-service", ChainSpec::new("test.example.com"));
    /// assert!(chain.leaf_cert_pem().contains("-----BEGIN CERTIFICATE-----"));
    /// ```
    fn x509_chain(&self, label: impl AsRef<str>, spec: ChainSpec) -> X509Chain;
}

impl X509FactoryExt for Factory {
    fn x509_self_signed(&self, label: impl AsRef<str>, spec: X509Spec) -> X509Cert {
        X509Cert::new(self.clone(), label.as_ref(), spec)
    }

    fn x509_chain(&self, label: impl AsRef<str>, spec: ChainSpec) -> X509Chain {
        X509Chain::new(self.clone(), label.as_ref(), spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srp::spec::NotBeforeOffset;
    use crate::testutil::fx;
    use uselesskey_core::Seed;
    use uselesskey_core::negative::CorruptPem;

    #[test]
    fn test_self_signed_cert_generation() {
        let factory = fx();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        assert!(cert.cert_der().len() > 1);
        assert!(cert.cert_pem().contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert.private_key_pkcs8_der().len() > 1);
        assert!(
            cert.private_key_pkcs8_pem()
                .contains("-----BEGIN PRIVATE KEY-----")
        );

        // Verify CN and leaf-not-CA
        use x509_parser::prelude::*;
        let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse cert");
        let cn = parsed.subject().iter_common_name().next().expect("CN");
        assert_eq!(cn.as_str().unwrap(), "test.example.com");
        assert!(!parsed.is_ca(), "leaf cert must not be CA");
    }

    #[test]
    fn test_deterministic_cert_generation() {
        let seed = Seed::from_env_value("test-seed").unwrap();
        let factory = Factory::deterministic(seed);
        let spec = X509Spec::self_signed("test.example.com");

        let cert1 = factory.x509_self_signed("test", spec.clone());
        factory.clear_cache();
        let cert2 = factory.x509_self_signed("test", spec);

        assert_eq!(cert1.cert_pem(), cert2.cert_pem());
        assert_eq!(cert1.private_key_pkcs8_pem(), cert2.private_key_pkcs8_pem());
    }

    #[test]
    fn test_identity_pem() {
        let factory = fx();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        let identity = cert.identity_pem();
        assert!(identity.contains("-----BEGIN CERTIFICATE-----"));
        assert!(identity.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_good_cert_not_expired_within_five_years() {
        use x509_parser::prelude::*;

        let factory = fx();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse cert");
        let not_before = parsed.validity().not_before.timestamp();
        let not_after = parsed.validity().not_after.timestamp();
        let validity_days = (not_after - not_before) / 86400;
        assert!(validity_days >= 365 * 5);
    }

    #[test]
    fn test_expired_cert() {
        let factory = fx();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        let expired = cert.expired();
        // The expired cert should have a different DER (different validity)
        assert_ne!(cert.cert_der(), expired.cert_der());
    }

    #[test]
    fn test_not_yet_valid_cert() {
        let factory = fx();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        let not_valid = cert.not_yet_valid();
        assert_ne!(cert.cert_der(), not_valid.cert_der());
    }

    #[test]
    fn test_corrupt_cert_pem() {
        let factory = fx();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        let corrupted = cert.corrupt_cert_pem(CorruptPem::BadHeader);
        assert!(corrupted.contains("-----BEGIN CORRUPTED KEY-----"));
    }

    #[test]
    fn test_truncate_cert_der() {
        let factory = fx();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        let truncated = cert.truncate_cert_der(10);
        assert_eq!(truncated.len(), 10);
    }

    #[test]
    fn test_deterministic_corrupt_helpers() {
        let factory = fx();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        let pem_a = cert.corrupt_cert_pem_deterministic("corrupt:v1");
        let pem_b = cert.corrupt_cert_pem_deterministic("corrupt:v1");
        assert_eq!(pem_a, pem_b);

        let der_a = cert.corrupt_cert_der_deterministic("corrupt:v1");
        let der_b = cert.corrupt_cert_der_deterministic("corrupt:v1");
        assert_eq!(der_a, der_b);

        assert!(!pem_a.is_empty());
        assert_ne!(pem_a, "xyzzy");
        assert!(der_a.len() > 1);
    }

    #[test]
    fn test_tempfile_outputs() {
        let factory = fx();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        let cert_file = cert.write_cert_pem().unwrap();
        assert!(cert_file.path().exists());

        let cert_der_file = cert.write_cert_der().unwrap();
        assert!(cert_der_file.path().exists());

        let key_file = cert.write_private_key_pem().unwrap();
        assert!(key_file.path().exists());

        let identity_file = cert.write_identity_pem().unwrap();
        assert!(identity_file.path().exists());
    }

    #[test]
    fn test_debug_includes_label_and_spec() {
        let factory = fx();
        let spec = X509Spec::self_signed("debug.example.com");
        let cert = factory.x509_self_signed("debug-label", spec);

        let dbg = format!("{:?}", cert);
        assert!(dbg.contains("X509Cert"));
        assert!(dbg.contains("debug-label"));
    }

    #[test]
    fn test_factory_chain_extension_works() {
        let factory = fx();
        let chain = factory.x509_chain("test-chain", ChainSpec::new("test.example.com"));
        assert!(!chain.leaf_cert_der().is_empty());
    }

    #[test]
    fn test_load_variant_generates_distinct_cert() {
        let factory = Factory::deterministic(Seed::from_env_value("variant-seed").unwrap());
        let spec = X509Spec::self_signed("variant.example.com");
        let cert = factory.x509_self_signed("variant", spec);

        let other = cert.load_variant("alt");
        assert_ne!(cert.cert_der(), other.cert_der.as_ref());
    }

    #[test]
    fn test_wrong_key_usage_variant_updates_spec() {
        let factory = fx();
        let spec = X509Spec::self_signed("badku.example.com");
        let cert = factory.x509_self_signed("badku", spec);

        let wrong = cert.wrong_key_usage();
        assert!(wrong.spec().is_ca);
        assert!(!wrong.spec().key_usage.key_cert_sign);
        assert_eq!(wrong.label(), "badku");
    }

    #[test]
    fn test_not_before_offset_affects_cert_time() {
        use x509_parser::prelude::*;

        let factory = fx();

        let spec_ago = X509Spec::self_signed("offset.example.com")
            .with_not_before(NotBeforeOffset::DaysAgo(30));
        let cert_ago = factory.x509_self_signed("offset", spec_ago);

        let spec_future = X509Spec::self_signed("offset.example.com")
            .with_not_before(NotBeforeOffset::DaysFromNow(30));
        let cert_future = factory.x509_self_signed("offset", spec_future);

        let (_, parsed_ago) =
            X509Certificate::from_der(cert_ago.cert_der()).expect("parse ago cert");
        let (_, parsed_future) =
            X509Certificate::from_der(cert_future.cert_der()).expect("parse future cert");

        // DaysFromNow cert must have a later not_before than DaysAgo cert
        assert!(
            parsed_future.validity().not_before.timestamp()
                > parsed_ago.validity().not_before.timestamp()
        );
    }

    #[test]
    fn test_leaf_cert_has_eku() {
        use x509_parser::prelude::*;

        let factory = fx();
        let spec = X509Spec::self_signed("eku.example.com");
        let cert = factory.x509_self_signed("eku", spec);

        let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse cert");

        // Leaf cert (is_ca=false) should have Extended Key Usage
        let eku_ext = parsed
            .extensions()
            .iter()
            .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE)
            .expect("leaf cert should have EKU extension");

        let eku = match eku_ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(eku) => eku,
            other => panic!("expected ExtendedKeyUsage, got {:?}", other),
        };

        assert!(eku.server_auth, "leaf EKU must include ServerAuth");
        assert!(eku.client_auth, "leaf EKU must include ClientAuth");
    }

    #[test]
    fn test_self_signed_ca_executes_ca_branches() {
        use x509_parser::prelude::*;

        let factory = fx();
        let spec = X509Spec::self_signed_ca("ca.example.com");
        let cert = factory.x509_self_signed("ca", spec);

        let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse cert");
        assert!(parsed.is_ca());

        // CA cert must NOT have EKU extension
        let eku = parsed
            .extensions()
            .iter()
            .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE);
        assert!(eku.is_none(), "CA cert should not have EKU");
    }

    #[test]
    fn test_leaf_key_usage_bits() {
        use x509_parser::prelude::*;

        let factory = fx();
        let spec = X509Spec::self_signed("ku-leaf.example.com");
        let cert = factory.x509_self_signed("ku-leaf", spec);

        let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse cert");

        let ku_ext = parsed
            .extensions()
            .iter()
            .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE)
            .expect("leaf cert should have KeyUsage extension");

        let ku = match ku_ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::KeyUsage(ku) => ku,
            other => panic!("expected KeyUsage, got {:?}", other),
        };

        // Leaf defaults: digital_signature=true, key_encipherment=true,
        //                key_cert_sign=false, crl_sign=false
        assert!(ku.digital_signature(), "leaf must have DigitalSignature");
        assert!(ku.key_encipherment(), "leaf must have KeyEncipherment");
        assert!(!ku.key_cert_sign(), "leaf must NOT have KeyCertSign");
        assert!(!ku.crl_sign(), "leaf must NOT have CrlSign");
    }

    #[test]
    fn test_ca_key_usage_bits() {
        use x509_parser::prelude::*;

        let factory = fx();
        let spec = X509Spec::self_signed_ca("ku-ca.example.com");
        let cert = factory.x509_self_signed("ku-ca", spec);

        let (_, parsed) = X509Certificate::from_der(cert.cert_der()).expect("parse cert");

        let ku_ext = parsed
            .extensions()
            .iter()
            .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_KEY_USAGE)
            .expect("CA cert should have KeyUsage extension");

        let ku = match ku_ext.parsed_extension() {
            x509_parser::extensions::ParsedExtension::KeyUsage(ku) => ku,
            other => panic!("expected KeyUsage, got {:?}", other),
        };

        // CA defaults: digital_signature=true, key_encipherment=false,
        //              key_cert_sign=true, crl_sign=true
        assert!(ku.digital_signature(), "CA must have DigitalSignature");
        assert!(!ku.key_encipherment(), "CA must NOT have KeyEncipherment");
        assert!(ku.key_cert_sign(), "CA must have KeyCertSign");
        assert!(ku.crl_sign(), "CA must have CrlSign");
    }
}
