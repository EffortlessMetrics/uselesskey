//! X.509 certificate chain generation and output.

use std::fmt;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_RSA_SHA256, RevocationReason,
    RevokedCertParams,
};
use rustls_pki_types::PrivatePkcs8KeyDer;
use time::Duration as TimeDuration;
use uselesskey_core::sink::TempArtifact;
use uselesskey_core::{Error, Factory};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

use crate::chain_spec::ChainSpec;
use crate::util::{deterministic_base_time, deterministic_serial_number};

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

struct ChainInner {
    root_cert_der: Arc<[u8]>,
    root_cert_pem: String,
    root_key_pkcs8_der: Arc<[u8]>,
    root_key_pkcs8_pem: String,

    intermediate_cert_der: Arc<[u8]>,
    intermediate_cert_pem: String,
    intermediate_key_pkcs8_der: Arc<[u8]>,
    intermediate_key_pkcs8_pem: String,

    leaf_cert_der: Arc<[u8]>,
    leaf_cert_pem: String,
    leaf_key_pkcs8_der: Arc<[u8]>,
    leaf_key_pkcs8_pem: String,

    crl_der: Option<Arc<[u8]>>,
    crl_pem: Option<String>,
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
    pub fn root_cert_der(&self) -> &[u8] {
        &self.inner.root_cert_der
    }

    /// PEM-encoded root CA certificate.
    pub fn root_cert_pem(&self) -> &str {
        &self.inner.root_cert_pem
    }

    /// DER-encoded root CA PKCS#8 private key bytes.
    pub fn root_private_key_pkcs8_der(&self) -> &[u8] {
        &self.inner.root_key_pkcs8_der
    }

    /// PEM-encoded root CA PKCS#8 private key.
    pub fn root_private_key_pkcs8_pem(&self) -> &str {
        &self.inner.root_key_pkcs8_pem
    }

    // =========================================================================
    // Intermediate CA outputs
    // =========================================================================

    /// DER-encoded intermediate CA certificate bytes.
    pub fn intermediate_cert_der(&self) -> &[u8] {
        &self.inner.intermediate_cert_der
    }

    /// PEM-encoded intermediate CA certificate.
    pub fn intermediate_cert_pem(&self) -> &str {
        &self.inner.intermediate_cert_pem
    }

    /// DER-encoded intermediate CA PKCS#8 private key bytes.
    pub fn intermediate_private_key_pkcs8_der(&self) -> &[u8] {
        &self.inner.intermediate_key_pkcs8_der
    }

    /// PEM-encoded intermediate CA PKCS#8 private key.
    pub fn intermediate_private_key_pkcs8_pem(&self) -> &str {
        &self.inner.intermediate_key_pkcs8_pem
    }

    // =========================================================================
    // Leaf certificate outputs
    // =========================================================================

    /// DER-encoded leaf certificate bytes.
    pub fn leaf_cert_der(&self) -> &[u8] {
        &self.inner.leaf_cert_der
    }

    /// PEM-encoded leaf certificate.
    pub fn leaf_cert_pem(&self) -> &str {
        &self.inner.leaf_cert_pem
    }

    /// DER-encoded leaf PKCS#8 private key bytes.
    pub fn leaf_private_key_pkcs8_der(&self) -> &[u8] {
        &self.inner.leaf_key_pkcs8_der
    }

    /// PEM-encoded leaf PKCS#8 private key.
    pub fn leaf_private_key_pkcs8_pem(&self) -> &str {
        &self.inner.leaf_key_pkcs8_pem
    }

    // =========================================================================
    // Combined chain outputs
    // =========================================================================

    /// Certificate chain PEM in standard TLS order: leaf + intermediate (no root).
    ///
    /// This is the format expected by most TLS servers.
    pub fn chain_pem(&self) -> String {
        format!(
            "{}\n{}",
            self.inner.leaf_cert_pem, self.inner.intermediate_cert_pem
        )
    }

    /// Full certificate chain PEM: leaf + intermediate + root.
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
    pub fn write_leaf_cert_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".leaf.crt.pem", self.leaf_cert_pem())
    }

    /// Write the leaf DER certificate to a tempfile.
    pub fn write_leaf_cert_der(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_bytes("uselesskey-", ".leaf.crt.der", self.leaf_cert_der())
    }

    /// Write the leaf PEM private key to a tempfile.
    pub fn write_leaf_private_key_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string(
            "uselesskey-",
            ".leaf.key.pem",
            self.leaf_private_key_pkcs8_pem(),
        )
    }

    /// Write the chain PEM (leaf + intermediate) to a tempfile.
    pub fn write_chain_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".chain.pem", &self.chain_pem())
    }

    /// Write the full chain PEM (leaf + intermediate + root) to a tempfile.
    pub fn write_full_chain_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".fullchain.pem", &self.full_chain_pem())
    }

    /// Write the root CA PEM certificate to a tempfile.
    pub fn write_root_cert_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".root.crt.pem", self.root_cert_pem())
    }

    // =========================================================================
    // CRL outputs (only present for RevokedLeaf variant)
    // =========================================================================

    /// DER-encoded CRL bytes, if this chain was generated with the `RevokedLeaf` variant.
    pub fn crl_der(&self) -> Option<&[u8]> {
        self.inner.crl_der.as_deref()
    }

    /// PEM-encoded CRL, if this chain was generated with the `RevokedLeaf` variant.
    pub fn crl_pem(&self) -> Option<&str> {
        self.inner.crl_pem.as_deref()
    }

    /// Write the CRL PEM to a tempfile. Returns `None` if no CRL is present.
    pub fn write_crl_pem(&self) -> Option<Result<TempArtifact, Error>> {
        self.inner
            .crl_pem
            .as_deref()
            .map(|pem| TempArtifact::new_string("uselesskey-", ".crl.pem", pem))
    }

    /// Write the CRL DER to a tempfile. Returns `None` if no CRL is present.
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
    pub fn spec(&self) -> &ChainSpec {
        &self.spec
    }

    /// Get the label used to create this chain.
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
    let spec_bytes = spec.stable_bytes();

    factory.get_or_init(DOMAIN_X509_CHAIN, label, &spec_bytes, variant, |rng| {
        let rsa_spec = RsaSpec::new(spec.rsa_bits);

        // Generate 3 RSA keypairs with role-tagged labels
        let root_key_label = format!("{}-chain-root", label);
        let int_key_label = format!("{}-chain-intermediate", label);
        let leaf_key_label = format!("{}-chain-leaf", label);

        let root_rsa = factory.rsa(&root_key_label, rsa_spec);
        let int_rsa = factory.rsa(&int_key_label, rsa_spec);
        let leaf_rsa = factory.rsa(&leaf_key_label, rsa_spec);

        // Convert to rcgen KeyPairs
        let root_kp = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(root_rsa.private_key_pkcs8_der().to_vec()),
            &PKCS_RSA_SHA256,
        )
        .expect("root key parse");

        let int_kp = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(int_rsa.private_key_pkcs8_der().to_vec()),
            &PKCS_RSA_SHA256,
        )
        .expect("intermediate key parse");

        let leaf_kp = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(leaf_rsa.private_key_pkcs8_der().to_vec()),
            &PKCS_RSA_SHA256,
        )
        .expect("leaf key parse");

        // Deterministic base time for the chain
        let base_time = {
            let mut hasher = blake3::Hasher::new();
            let label_bytes = label.as_bytes();
            hasher.update(&(label_bytes.len() as u32).to_be_bytes());
            hasher.update(label_bytes);
            let leaf_cn_bytes = spec.leaf_cn.as_bytes();
            hasher.update(&(leaf_cn_bytes.len() as u32).to_be_bytes());
            hasher.update(leaf_cn_bytes);
            let root_cn_bytes = spec.root_cn.as_bytes();
            hasher.update(&(root_cn_bytes.len() as u32).to_be_bytes());
            hasher.update(root_cn_bytes);
            hasher.update(&(spec.rsa_bits as u32).to_be_bytes());
            deterministic_base_time(hasher)
        };

        // --- Root CA ---
        let mut root_params = CertificateParams::default();
        root_params
            .distinguished_name
            .push(DnType::CommonName, spec.root_cn.clone());
        root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        root_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        root_params.not_before = base_time - TimeDuration::days(1);
        root_params.not_after =
            root_params.not_before + TimeDuration::days(spec.root_validity_days as i64);
        root_params.serial_number = Some(deterministic_serial_number(rng));

        let root_cert = root_params.self_signed(&root_kp).expect("root cert gen");

        // --- Intermediate CA ---
        let mut int_params = CertificateParams::default();
        int_params
            .distinguished_name
            .push(DnType::CommonName, spec.intermediate_cn.clone());
        int_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        int_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let int_offset = spec.intermediate_not_before_offset_days.unwrap_or(1);
        int_params.not_before = base_time - TimeDuration::days(int_offset);
        int_params.not_after =
            int_params.not_before + TimeDuration::days(spec.intermediate_validity_days as i64);
        int_params.serial_number = Some(deterministic_serial_number(rng));

        let int_cert = int_params
            .signed_by(&int_kp, &root_cert, &root_kp)
            .expect("intermediate cert gen");

        // --- Leaf ---
        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, spec.leaf_cn.clone());
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        leaf_params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        // Add SANs (sorted and deduplicated to match stable_bytes)
        let mut sorted_sans = spec.leaf_sans.clone();
        sorted_sans.sort();
        sorted_sans.dedup();
        for san in &sorted_sans {
            leaf_params.subject_alt_names.push(rcgen::SanType::DnsName(
                san.clone().try_into().expect("valid DNS name"),
            ));
        }

        let leaf_offset = spec.leaf_not_before_offset_days.unwrap_or(1);
        leaf_params.not_before = base_time - TimeDuration::days(leaf_offset);
        leaf_params.not_after =
            leaf_params.not_before + TimeDuration::days(spec.leaf_validity_days as i64);
        leaf_params.serial_number = Some(deterministic_serial_number(rng));

        let leaf_serial = leaf_params
            .serial_number
            .clone()
            .expect("leaf serial number");

        let leaf_cert = leaf_params
            .signed_by(&leaf_kp, &int_cert, &int_kp)
            .expect("leaf cert gen");

        // --- CRL (only for revoked_leaf variant) ---
        let (crl_der, crl_pem) = if variant == "revoked_leaf" {
            let crl_number = deterministic_serial_number(rng);

            let revoked = RevokedCertParams {
                serial_number: leaf_serial,
                revocation_time: base_time,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            };

            let crl_params = CertificateRevocationListParams {
                this_update: base_time,
                next_update: base_time + TimeDuration::days(30),
                crl_number,
                issuing_distribution_point: None,
                revoked_certs: vec![revoked],
                key_identifier_method: rcgen::KeyIdMethod::Sha256,
            };

            let crl = crl_params.signed_by(&int_cert, &int_kp).expect("CRL gen");

            (
                Some(Arc::from(crl.der().as_ref())),
                Some(crl.pem().expect("CRL PEM")),
            )
        } else {
            (None, None)
        };

        ChainInner {
            root_cert_der: Arc::from(root_cert.der().as_ref()),
            root_cert_pem: root_cert.pem(),
            root_key_pkcs8_der: Arc::from(root_rsa.private_key_pkcs8_der()),
            root_key_pkcs8_pem: root_rsa.private_key_pkcs8_pem().to_string(),

            intermediate_cert_der: Arc::from(int_cert.der().as_ref()),
            intermediate_cert_pem: int_cert.pem(),
            intermediate_key_pkcs8_der: Arc::from(int_rsa.private_key_pkcs8_der()),
            intermediate_key_pkcs8_pem: int_rsa.private_key_pkcs8_pem().to_string(),

            leaf_cert_der: Arc::from(leaf_cert.der().as_ref()),
            leaf_cert_pem: leaf_cert.pem(),
            leaf_key_pkcs8_der: Arc::from(leaf_rsa.private_key_pkcs8_der()),
            leaf_key_pkcs8_pem: leaf_rsa.private_key_pkcs8_pem().to_string(),

            crl_der,
            crl_pem,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::X509FactoryExt;
    use crate::testutil::fx;
    use uselesskey_core::Seed;

    #[test]
    fn test_chain_generation() {
        let factory = Factory::random();
        let spec = ChainSpec::new("test.example.com");
        let chain = X509Chain::new(factory, "test", spec);

        assert!(!chain.root_cert_der().is_empty());
        assert!(
            chain
                .root_cert_pem()
                .contains("-----BEGIN CERTIFICATE-----")
        );
        assert!(!chain.intermediate_cert_der().is_empty());
        assert!(
            chain
                .intermediate_cert_pem()
                .contains("-----BEGIN CERTIFICATE-----")
        );
        assert!(!chain.leaf_cert_der().is_empty());
        assert!(
            chain
                .leaf_cert_pem()
                .contains("-----BEGIN CERTIFICATE-----")
        );
        assert!(!chain.leaf_private_key_pkcs8_der().is_empty());
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
        let self_signed_spec = crate::spec::X509Spec::self_signed("test.example.com");
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

        assert!(!chain.root_private_key_pkcs8_der().is_empty());
        assert!(
            chain
                .root_private_key_pkcs8_pem()
                .contains("BEGIN PRIVATE KEY")
        );
        assert!(!chain.intermediate_private_key_pkcs8_der().is_empty());
        assert!(
            chain
                .intermediate_private_key_pkcs8_pem()
                .contains("BEGIN PRIVATE KEY")
        );
    }
}
