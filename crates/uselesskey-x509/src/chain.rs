//! X.509 certificate chain generation and output.

use std::fmt;
use std::sync::Arc;

use crate::srp::spec::ChainSpec;
use uselesskey_core::sink::TempArtifact;
use uselesskey_core::{Error, Factory};

/// Cache domain for X.509 certificate chain fixtures.
///
/// Keep this stable: changing it changes deterministic outputs.
pub const DOMAIN_X509_CHAIN: &str = "uselesskey:x509:chain";

/// A three-level X.509 certificate chain (root CA → intermediate CA → leaf).
#[derive(Clone)]
pub struct X509Chain {
    factory: Factory,
    label: String,
    spec: ChainSpec,
    inner: Arc<ChainInner>,
}

pub(crate) struct ChainInner {
    pub(crate) root_cert_der: Arc<[u8]>,
    pub(crate) root_cert_pem: String,
    pub(crate) root_key_pkcs8_der: Arc<[u8]>,
    pub(crate) root_key_pkcs8_pem: String,

    pub(crate) intermediate_cert_der: Arc<[u8]>,
    pub(crate) intermediate_cert_pem: String,
    pub(crate) intermediate_key_pkcs8_der: Arc<[u8]>,
    pub(crate) intermediate_key_pkcs8_pem: String,

    pub(crate) leaf_cert_der: Arc<[u8]>,
    pub(crate) leaf_cert_pem: String,
    pub(crate) leaf_key_pkcs8_der: Arc<[u8]>,
    pub(crate) leaf_key_pkcs8_pem: String,

    pub(crate) crl_der: Option<Arc<[u8]>>,
    pub(crate) crl_pem: Option<String>,
}

impl fmt::Debug for X509Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X509Chain")
            .field("label", &self.label)
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

impl X509Chain {
    pub(crate) fn new(factory: Factory, label: &str, spec: ChainSpec) -> Self {
        let inner = load_chain_inner(&factory, label, &spec, "good");
        Self {
            factory,
            label: label.to_string(),
            spec,
            inner,
        }
    }

    pub(crate) fn with_variant(
        factory: Factory,
        label: &str,
        spec: ChainSpec,
        variant: &str,
    ) -> Self {
        let inner = load_chain_inner(&factory, label, &spec, variant);
        Self {
            factory,
            label: label.to_string(),
            spec,
            inner,
        }
    }

    // =========================================================================
    // Root CA outputs
    // =========================================================================

    /// DER-encoded root CA certificate bytes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert!(!chain.root_cert_der().is_empty());
    /// ```
    pub fn root_cert_der(&self) -> &[u8] {
        &self.inner.root_cert_der
    }

    /// PEM-encoded root CA certificate.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert!(chain.root_cert_pem().contains("BEGIN CERTIFICATE"));
    /// ```
    pub fn root_cert_pem(&self) -> &str {
        &self.inner.root_cert_pem
    }

    /// DER-encoded root CA PKCS#8 private key bytes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert!(!chain.root_private_key_pkcs8_der().is_empty());
    /// ```
    pub fn root_private_key_pkcs8_der(&self) -> &[u8] {
        &self.inner.root_key_pkcs8_der
    }

    /// PEM-encoded root CA PKCS#8 private key.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert!(chain.root_private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    /// ```
    pub fn root_private_key_pkcs8_pem(&self) -> &str {
        &self.inner.root_key_pkcs8_pem
    }

    // =========================================================================
    // Intermediate CA outputs
    // =========================================================================

    /// DER-encoded intermediate CA certificate bytes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert!(!chain.intermediate_cert_der().is_empty());
    /// ```
    pub fn intermediate_cert_der(&self) -> &[u8] {
        &self.inner.intermediate_cert_der
    }

    /// PEM-encoded intermediate CA certificate.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert!(chain.intermediate_cert_pem().contains("BEGIN CERTIFICATE"));
    /// ```
    pub fn intermediate_cert_pem(&self) -> &str {
        &self.inner.intermediate_cert_pem
    }

    /// DER-encoded intermediate CA PKCS#8 private key bytes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert!(!chain.intermediate_private_key_pkcs8_der().is_empty());
    /// ```
    pub fn intermediate_private_key_pkcs8_der(&self) -> &[u8] {
        &self.inner.intermediate_key_pkcs8_der
    }

    /// PEM-encoded intermediate CA PKCS#8 private key.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert!(chain.intermediate_private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    /// ```
    pub fn intermediate_private_key_pkcs8_pem(&self) -> &str {
        &self.inner.intermediate_key_pkcs8_pem
    }

    // =========================================================================
    // Leaf certificate outputs
    // =========================================================================

    /// DER-encoded leaf certificate bytes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert!(!chain.leaf_cert_der().is_empty());
    /// ```
    pub fn leaf_cert_der(&self) -> &[u8] {
        &self.inner.leaf_cert_der
    }

    /// PEM-encoded leaf certificate.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert!(chain.leaf_cert_pem().contains("BEGIN CERTIFICATE"));
    /// ```
    pub fn leaf_cert_pem(&self) -> &str {
        &self.inner.leaf_cert_pem
    }

    /// DER-encoded leaf PKCS#8 private key bytes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert!(!chain.leaf_private_key_pkcs8_der().is_empty());
    /// ```
    pub fn leaf_private_key_pkcs8_der(&self) -> &[u8] {
        &self.inner.leaf_key_pkcs8_der
    }

    /// PEM-encoded leaf PKCS#8 private key.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert!(chain.leaf_private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    /// ```
    pub fn leaf_private_key_pkcs8_pem(&self) -> &str {
        &self.inner.leaf_key_pkcs8_pem
    }

    // =========================================================================
    // Combined chain outputs
    // =========================================================================

    /// Certificate chain PEM in standard TLS order: leaf + intermediate (no root).
    ///
    /// This is the format expected by most TLS servers.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// let pem = chain.chain_pem();
    /// // Contains leaf and intermediate certificates
    /// assert!(pem.matches("BEGIN CERTIFICATE").count() >= 2);
    /// ```
    pub fn chain_pem(&self) -> String {
        format!(
            "{}\n{}",
            self.inner.leaf_cert_pem, self.inner.intermediate_cert_pem
        )
    }

    /// Full certificate chain PEM: leaf + intermediate + root.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// let pem = chain.full_chain_pem();
    /// // Contains leaf, intermediate, and root certificates
    /// assert!(pem.matches("BEGIN CERTIFICATE").count() >= 3);
    /// ```
    pub fn full_chain_pem(&self) -> String {
        format!(
            "{}\n{}\n{}",
            self.inner.leaf_cert_pem, self.inner.intermediate_cert_pem, self.inner.root_cert_pem
        )
    }

    // =========================================================================
    // Tempfile outputs
    // =========================================================================

    /// Write the leaf PEM certificate to a tempfile.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// let temp = chain.write_leaf_cert_pem().unwrap();
    /// assert!(temp.path().exists());
    /// ```
    pub fn write_leaf_cert_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".leaf.crt.pem", self.leaf_cert_pem())
    }

    /// Write the leaf DER certificate to a tempfile.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// let temp = chain.write_leaf_cert_der().unwrap();
    /// assert!(temp.path().exists());
    /// ```
    pub fn write_leaf_cert_der(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_bytes("uselesskey-", ".leaf.crt.der", self.leaf_cert_der())
    }

    /// Write the leaf PEM private key to a tempfile.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// let temp = chain.write_leaf_private_key_pem().unwrap();
    /// assert!(temp.path().exists());
    /// ```
    pub fn write_leaf_private_key_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string(
            "uselesskey-",
            ".leaf.key.pem",
            self.leaf_private_key_pkcs8_pem(),
        )
    }

    /// Write the chain PEM (leaf + intermediate) to a tempfile.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// let temp = chain.write_chain_pem().unwrap();
    /// assert!(temp.path().exists());
    /// ```
    pub fn write_chain_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".chain.pem", &self.chain_pem())
    }

    /// Write the full chain PEM (leaf + intermediate + root) to a tempfile.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// let temp = chain.write_full_chain_pem().unwrap();
    /// assert!(temp.path().exists());
    /// ```
    pub fn write_full_chain_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".fullchain.pem", &self.full_chain_pem())
    }

    /// Write the root CA PEM certificate to a tempfile.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// let temp = chain.write_root_cert_pem().unwrap();
    /// assert!(temp.path().exists());
    /// ```
    pub fn write_root_cert_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".root.crt.pem", self.root_cert_pem())
    }

    // =========================================================================
    // CRL outputs (only present for RevokedLeaf variant)
    // =========================================================================

    /// DER-encoded CRL bytes, if this chain was generated with the `RevokedLeaf` variant.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// // Good chain has no CRL
    /// assert!(chain.crl_der().is_none());
    /// // Revoked leaf chain has a CRL
    /// let revoked = chain.revoked_leaf();
    /// assert!(revoked.crl_der().is_some());
    /// ```
    pub fn crl_der(&self) -> Option<&[u8]> {
        self.inner.crl_der.as_deref()
    }

    /// PEM-encoded CRL, if this chain was generated with the `RevokedLeaf` variant.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert!(chain.crl_pem().is_none());
    /// ```
    pub fn crl_pem(&self) -> Option<&str> {
        self.inner.crl_pem.as_deref()
    }

    /// Write the CRL PEM to a tempfile. Returns `None` if no CRL is present.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert!(chain.write_crl_pem().is_none());
    /// ```
    pub fn write_crl_pem(&self) -> Option<Result<TempArtifact, Error>> {
        self.inner
            .crl_pem
            .as_deref()
            .map(|pem| TempArtifact::new_string("uselesskey-", ".crl.pem", pem))
    }

    /// Write the CRL DER to a tempfile. Returns `None` if no CRL is present.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert!(chain.write_crl_der().is_none());
    /// ```
    pub fn write_crl_der(&self) -> Option<Result<TempArtifact, Error>> {
        self.inner
            .crl_der
            .as_deref()
            .map(|der| TempArtifact::new_bytes("uselesskey-", ".crl.der", der))
    }

    // =========================================================================
    // Metadata
    // =========================================================================

    /// Get the specification used to create this chain.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("svc", ChainSpec::new("svc.example.com"));
    /// assert_eq!(chain.spec().leaf_cn, "svc.example.com");
    /// ```
    pub fn spec(&self) -> &ChainSpec {
        &self.spec
    }

    /// Get the label used to create this chain.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, ChainSpec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let chain = fx.x509_chain("my-svc", ChainSpec::new("svc.example.com"));
    /// assert_eq!(chain.label(), "my-svc");
    /// ```
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Get a reference to the factory that created this chain.
    pub(crate) fn factory(&self) -> &Factory {
        &self.factory
    }
}

fn load_chain_inner(
    factory: &Factory,
    label: &str,
    spec: &ChainSpec,
    variant: &str,
) -> Arc<ChainInner> {
    crate::srp::chain_generation::load_inner(factory, label, spec, variant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::X509FactoryExt;
    use crate::testutil::fx;
    use uselesskey_core::Seed;

    #[test]
    fn test_chain_generation() {
        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        assert_eq!(chain.label(), "test");

        assert!(chain.root_cert_der().len() > 1);
        assert!(
            chain
                .root_cert_pem()
                .contains("-----BEGIN CERTIFICATE-----")
        );
        assert!(chain.intermediate_cert_der().len() > 1);
        assert!(
            chain
                .intermediate_cert_pem()
                .contains("-----BEGIN CERTIFICATE-----")
        );
        assert!(chain.leaf_cert_der().len() > 1);
        assert!(
            chain
                .leaf_cert_pem()
                .contains("-----BEGIN CERTIFICATE-----")
        );
        assert!(chain.leaf_private_key_pkcs8_der().len() > 1);
        assert!(
            chain
                .leaf_private_key_pkcs8_pem()
                .contains("-----BEGIN PRIVATE KEY-----")
        );
    }

    #[test]
    fn test_chain_pem_format() {
        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        let chain_pem = chain.chain_pem();
        // Should contain exactly 2 certificates (leaf + intermediate)
        assert_eq!(chain_pem.matches("-----BEGIN CERTIFICATE-----").count(), 2);

        let full_chain_pem = chain.full_chain_pem();
        // Should contain exactly 3 certificates
        assert_eq!(
            full_chain_pem
                .matches("-----BEGIN CERTIFICATE-----")
                .count(),
            3
        );
    }

    #[test]
    fn test_chain_determinism() {
        let seed = Seed::from_env_value("test-seed").unwrap();
        let factory = Factory::deterministic(seed);
        let spec = ChainSpec::new("test.example.com");

        let chain1 = X509Chain::new(factory.clone(), "test", spec.clone());
        factory.clear_cache();
        let chain2 = X509Chain::new(factory, "test", spec);

        assert_eq!(chain1.root_cert_pem(), chain2.root_cert_pem());
        assert_eq!(
            chain1.intermediate_cert_pem(),
            chain2.intermediate_cert_pem()
        );
        assert_eq!(chain1.leaf_cert_pem(), chain2.leaf_cert_pem());
        assert_eq!(
            chain1.leaf_private_key_pkcs8_pem(),
            chain2.leaf_private_key_pkcs8_pem()
        );
    }

    #[test]
    fn test_good_chain_leaf_not_expired_within_five_years() {
        use x509_parser::prelude::*;

        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der()).expect("parse leaf");
        let not_before = leaf.validity().not_before.timestamp();
        let not_after = leaf.validity().not_after.timestamp();
        let validity_days = (not_after - not_before) / 86400;
        assert!(validity_days >= 365 * 5);
    }

    #[test]
    fn test_chain_isolation_from_self_signed() {
        let seed = Seed::from_env_value("test-seed").unwrap();
        let factory = Factory::deterministic(seed);

        // Generate a self-signed cert first
        let self_signed_spec = crate::X509Spec::self_signed("test.example.com");
        let self_signed = factory.x509_self_signed("test", self_signed_spec.clone());
        let self_signed_pem = self_signed.cert_pem().to_string();

        // Now generate a chain with the same label
        let chain_spec = ChainSpec::new("test.example.com");
        let _chain = X509Chain::new(factory.clone(), "test", chain_spec);

        // Self-signed cert should be unchanged
        factory.clear_cache();
        let self_signed2 = factory.x509_self_signed("test", self_signed_spec);
        assert_eq!(self_signed_pem, self_signed2.cert_pem());
    }

    #[test]
    fn test_chain_cert_parsing() {
        use x509_parser::prelude::*;

        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        // Parse root cert
        let (_, root) = X509Certificate::from_der(chain.root_cert_der()).expect("parse root");
        assert!(root.is_ca());

        // Parse intermediate cert
        let (_, int) =
            X509Certificate::from_der(chain.intermediate_cert_der()).expect("parse intermediate");
        assert!(int.is_ca());

        // Parse leaf cert — verify it is NOT a CA
        let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der()).expect("parse leaf");
        assert!(!leaf.is_ca());

        // Verify issuer/subject relationships
        assert_eq!(int.issuer(), root.subject());
        assert_eq!(leaf.issuer(), int.subject());
    }

    #[test]
    fn test_chain_sans() {
        use x509_parser::prelude::*;

        let factory = fx();
        let spec = ChainSpec::new("test.example.com").with_sans(vec![
            "test.example.com".to_string(),
            "www.example.com".to_string(),
        ]);
        let chain = X509Chain::new(factory, "test", spec);

        let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der()).expect("parse leaf");

        // Check SANs exist
        let san_ext = leaf
            .extensions()
            .iter()
            .find(|ext| ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME);
        assert!(san_ext.is_some(), "leaf cert should have SAN extension");
    }

    #[test]
    fn test_tempfile_outputs() {
        let factory = fx();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        let leaf_cert = chain.write_leaf_cert_pem().unwrap();
        assert!(leaf_cert.path().exists());

        let leaf_cert_der = chain.write_leaf_cert_der().unwrap();
        assert!(leaf_cert_der.path().exists());

        let leaf_key = chain.write_leaf_private_key_pem().unwrap();
        assert!(leaf_key.path().exists());

        let chain_file = chain.write_chain_pem().unwrap();
        assert!(chain_file.path().exists());

        let full_chain_file = chain.write_full_chain_pem().unwrap();
        assert!(full_chain_file.path().exists());

        let root_cert = chain.write_root_cert_pem().unwrap();
        assert!(root_cert.path().exists());
    }

    #[test]
    fn test_chain_cert_validity_periods() {
        use x509_parser::prelude::*;

        let factory = fx();
        let spec = ChainSpec::new("validity.example.com");
        let chain = X509Chain::new(factory, "validity", spec);

        let (_, root) = X509Certificate::from_der(chain.root_cert_der()).expect("parse root");
        let (_, int) = X509Certificate::from_der(chain.intermediate_cert_der()).expect("parse int");

        let root_nb = root.validity().not_before.timestamp();
        let root_na = root.validity().not_after.timestamp();
        let int_nb = int.validity().not_before.timestamp();
        let int_na = int.validity().not_after.timestamp();

        // not_after must be after not_before for both certs
        assert!(root_na > root_nb, "root not_after must be after not_before");
        assert!(int_na > int_nb, "int not_after must be after not_before");

        // root not_before should be <= intermediate not_before
        assert!(
            root_nb <= int_nb,
            "root not_before should be <= intermediate not_before"
        );

        // Parse leaf and check all not_before values are within a tight window
        let (_, leaf) = X509Certificate::from_der(chain.leaf_cert_der()).expect("parse leaf");
        let leaf_nb = leaf.validity().not_before.timestamp();

        // All not_before values should be within 2 days (offsets default to 1 day)
        let max_nb = root_nb.max(int_nb).max(leaf_nb);
        let min_nb = root_nb.min(int_nb).min(leaf_nb);
        assert!(
            max_nb - min_nb < 86400 * 2,
            "all not_before values should be within 2 days of each other"
        );
    }

    #[test]
    fn test_debug_includes_label_and_spec() {
        let factory = fx();
        let spec = ChainSpec::new("debug.example.com");
        let chain = X509Chain::new(factory, "debug-label", spec);

        let dbg = format!("{:?}", chain);
        assert!(dbg.contains("X509Chain"));
        assert!(dbg.contains("debug-label"));
    }

    #[test]
    fn test_private_key_accessors_non_empty() {
        let factory = fx();
        let spec = ChainSpec::new("keys.example.com");
        let chain = X509Chain::new(factory, "keys", spec);

        assert!(chain.root_private_key_pkcs8_der().len() > 1);
        assert!(
            chain
                .root_private_key_pkcs8_pem()
                .contains("BEGIN PRIVATE KEY")
        );
        assert!(chain.intermediate_private_key_pkcs8_der().len() > 1);
        assert!(
            chain
                .intermediate_private_key_pkcs8_pem()
                .contains("BEGIN PRIVATE KEY")
        );
    }
}
