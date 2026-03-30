//! X.509 certificate chain generation and output.

use std::fmt;
use std::sync::Arc;

use base64::Engine;
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
use rand_core::SeedableRng;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_RSA_SHA256,
    RevocationReason, RevokedCertParams,
};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use rustls_pki_types::PrivatePkcs8KeyDer;
use time::Duration as TimeDuration;
use time::OffsetDateTime;
use uselesskey_core::sink::TempArtifact;
use uselesskey_core::{Error, Factory};
use uselesskey_core_x509::{
    ChainSpec, CrlIssuerKind, CrlSpec, KeyUsage, NotBeforeOffset, OcspCertStatus, OcspSpec,
    RevocationReasonCode, TimeOffsetDays, deterministic_base_time_from_parts,
};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use x509_parser::prelude::FromDer;

/// Cache domain for X.509 certificate chain fixtures.
///
/// Keep this stable: changing it changes deterministic outputs.
pub const DOMAIN_X509_CHAIN: &str = "uselesskey:x509:chain";
pub const DOMAIN_X509_REVOCATION: &str = "uselesskey:x509:revocation";

/// Deterministic revocation fixture payload.
#[derive(Clone, Debug)]
pub struct RevocationFixture {
    der: Arc<[u8]>,
    pem: Option<String>,
    base64: String,
    issuer_binding: String,
    serial_binding_hex: String,
}

impl RevocationFixture {
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn pem(&self) -> Option<&str> {
        self.pem.as_deref()
    }

    pub fn base64(&self) -> &str {
        &self.base64
    }

    pub fn issuer_binding(&self) -> &str {
        &self.issuer_binding
    }

    pub fn serial_binding_hex(&self) -> &str {
        &self.serial_binding_hex
    }
}

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

    /// Build an explicit CRL fixture for the leaf certificate.
    pub fn crl_for_leaf(&self) -> RevocationFixture {
        let (_, leaf) = x509_parser::certificate::X509Certificate::from_der(self.leaf_cert_der())
            .expect("leaf parse");
        let serial = leaf.raw_serial().to_vec();
        let spec = CrlSpec::for_intermediate(serial.clone());
        self.build_crl_fixture("leaf", &spec, serial)
    }

    /// Build an explicit CRL fixture for the intermediate certificate.
    pub fn crl_for_intermediate(&self) -> RevocationFixture {
        let (_, int_cert) =
            x509_parser::certificate::X509Certificate::from_der(self.intermediate_cert_der())
                .expect("intermediate parse");
        let serial = int_cert.raw_serial().to_vec();
        let spec = CrlSpec {
            issuer_kind: CrlIssuerKind::Root,
            this_update: TimeOffsetDays::from_base(0),
            next_update: TimeOffsetDays::from_base(30),
            revoked_serials: vec![serial.clone()],
            reason_code: Some(RevocationReasonCode::KeyCompromise),
            crl_number: 2,
        };
        self.build_crl_fixture("intermediate", &spec, serial)
    }

    /// Build an explicit OCSP fixture for the leaf certificate.
    pub fn ocsp_for_leaf(&self, status: OcspCertStatus) -> RevocationFixture {
        self.build_ocsp_fixture(
            "leaf",
            self.leaf_cert_der(),
            self.intermediate_cert_der(),
            status,
        )
    }

    /// Build an explicit OCSP fixture for the intermediate certificate.
    pub fn ocsp_for_intermediate(&self, status: OcspCertStatus) -> RevocationFixture {
        self.build_ocsp_fixture(
            "intermediate",
            self.intermediate_cert_der(),
            self.root_cert_der(),
            status,
        )
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

    fn build_crl_fixture(&self, scope: &str, spec: &CrlSpec, serial: Vec<u8>) -> RevocationFixture {
        let variant = format!("crl:{scope}");
        let mut spec_bytes = self.spec.stable_bytes();
        spec_bytes.extend_from_slice(&spec.stable_bytes());
        self.factory
            .get_or_init(
                DOMAIN_X509_REVOCATION,
                &self.label,
                &spec_bytes,
                &variant,
                |_seed| {
                    let base_time = deterministic_base_time_from_parts(&[
                        self.label.as_bytes(),
                        self.spec.leaf_cn.as_bytes(),
                        b"revocation",
                    ]);
                    let this_update =
                        base_time + TimeDuration::days(i64::from(spec.this_update.days_from_base));
                    let next_update =
                        base_time + TimeDuration::days(i64::from(spec.next_update.days_from_base));
                    let reason = spec.reason_code.map(map_reason_code);
                    let mut revoked = Vec::new();
                    for serial in &spec.revoked_serials {
                        revoked.push(RevokedCertParams {
                            serial_number: rcgen::SerialNumber::from_slice(serial),
                            revocation_time: this_update,
                            reason_code: reason,
                            invalidity_date: None,
                        });
                    }

                    let crl_params = CertificateRevocationListParams {
                        this_update,
                        next_update,
                        crl_number: rcgen::SerialNumber::from(spec.crl_number),
                        issuing_distribution_point: None,
                        revoked_certs: revoked,
                        key_identifier_method: rcgen::KeyIdMethod::Sha256,
                    };

                    let (issuer_cn, issuer_key_der, issuer_ca) =
                        if matches!(spec.issuer_kind, CrlIssuerKind::Root) {
                            (
                                self.spec.root_cn.clone(),
                                self.root_private_key_pkcs8_der(),
                                true,
                            )
                        } else {
                            (
                                self.spec.intermediate_cn.clone(),
                                self.intermediate_private_key_pkcs8_der(),
                                self.spec.intermediate_is_ca.unwrap_or(true),
                            )
                        };
                    let mut issuer_params = CertificateParams::default();
                    issuer_params.is_ca = if issuer_ca {
                        IsCa::Ca(BasicConstraints::Constrained(0))
                    } else {
                        IsCa::NoCa
                    };
                    issuer_params.key_usages =
                        vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
                    let issuer_kp = KeyPair::from_pkcs8_der_and_sign_algo(
                        &PrivatePkcs8KeyDer::from(issuer_key_der.to_vec()),
                        &PKCS_RSA_SHA256,
                    )
                    .expect("issuer key parse");
                    let issuer = Issuer::from_params(&issuer_params, issuer_kp);
                    let crl = crl_params.signed_by(&issuer).expect("CRL gen");
                    let der: Arc<[u8]> = Arc::from(crl.der().as_ref());
                    let pem = crl.pem().ok();
                    RevocationFixture {
                        der: der.clone(),
                        base64: base64::engine::general_purpose::STANDARD.encode(der.as_ref()),
                        pem,
                        issuer_binding: issuer_cn,
                        serial_binding_hex: hex_encode(&serial),
                    }
                },
            )
            .as_ref()
            .clone()
    }

    fn build_ocsp_fixture(
        &self,
        scope: &str,
        cert_der: &[u8],
        issuer_der: &[u8],
        status: OcspCertStatus,
    ) -> RevocationFixture {
        let spec = OcspSpec::for_issuer(status);
        let variant = format!("ocsp:{scope}:{status:?}");
        let mut spec_bytes = self.spec.stable_bytes();
        spec_bytes.extend_from_slice(&spec.stable_bytes());
        self.factory
            .get_or_init(
                DOMAIN_X509_REVOCATION,
                &self.label,
                &spec_bytes,
                &variant,
                |_seed| {
                    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der)
                        .expect("cert parse");
                    let (_, issuer) =
                        x509_parser::certificate::X509Certificate::from_der(issuer_der)
                            .expect("issuer parse");
                    let serial = cert.raw_serial().to_vec();
                    let payload = ocsp_like_payload(&spec, &serial, issuer.subject().to_string());
                    let issuer_key = if scope == "leaf" {
                        self.intermediate_private_key_pkcs8_der()
                    } else {
                        self.root_private_key_pkcs8_der()
                    };
                    let private_key =
                        RsaPrivateKey::from_pkcs8_der(issuer_key).expect("issuer key");
                    let signing_key = SigningKey::<Sha256>::new(private_key);
                    let signature = signing_key.sign(&payload);
                    let mut der = b"UKOCSP1".to_vec();
                    der.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                    der.extend_from_slice(&payload);
                    der.extend_from_slice(&(signature.to_vec().len() as u32).to_be_bytes());
                    der.extend_from_slice(&signature.to_vec());
                    let der: Arc<[u8]> = Arc::from(der);
                    RevocationFixture {
                        der: der.clone(),
                        pem: None,
                        base64: base64::engine::general_purpose::STANDARD.encode(der.as_ref()),
                        issuer_binding: issuer.subject().to_string(),
                        serial_binding_hex: hex_encode(&serial),
                    }
                },
            )
            .as_ref()
            .clone()
    }
}

fn map_reason_code(reason: RevocationReasonCode) -> RevocationReason {
    match reason {
        RevocationReasonCode::Unspecified => RevocationReason::Unspecified,
        RevocationReasonCode::KeyCompromise => RevocationReason::KeyCompromise,
        RevocationReasonCode::CaCompromise => RevocationReason::CaCompromise,
        RevocationReasonCode::AffiliationChanged => RevocationReason::AffiliationChanged,
        RevocationReasonCode::Superseded => RevocationReason::Superseded,
        RevocationReasonCode::CessationOfOperation => RevocationReason::CessationOfOperation,
        RevocationReasonCode::CertificateHold => RevocationReason::CertificateHold,
        RevocationReasonCode::PrivilegeWithdrawn => RevocationReason::PrivilegeWithdrawn,
        RevocationReasonCode::AaCompromise => RevocationReason::AaCompromise,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

fn ocsp_like_payload(spec: &OcspSpec, serial: &[u8], issuer_binding: String) -> Vec<u8> {
    let mut out = b"ukocsp-payload-v1|".to_vec();
    out.extend_from_slice(&spec.stable_bytes());
    out.extend_from_slice(b"|issuer=");
    out.extend_from_slice(issuer_binding.as_bytes());
    out.extend_from_slice(b"|serial=");
    out.extend_from_slice(hex_encode(serial).as_bytes());
    out
}

#[cfg(test)]
pub(crate) fn verify_ocsp_like_signature(der: &[u8], issuer_public_key: RsaPublicKey) -> bool {
    if !der.starts_with(b"UKOCSP1") {
        return false;
    }
    let mut idx = 7usize;
    if der.len() < idx + 4 {
        return false;
    }
    let payload_len =
        u32::from_be_bytes([der[idx], der[idx + 1], der[idx + 2], der[idx + 3]]) as usize;
    idx += 4;
    if der.len() < idx + payload_len + 4 {
        return false;
    }
    let payload = &der[idx..idx + payload_len];
    idx += payload_len;
    let sig_len = u32::from_be_bytes([der[idx], der[idx + 1], der[idx + 2], der[idx + 3]]) as usize;
    idx += 4;
    if der.len() < idx + sig_len {
        return false;
    }
    let sig = RsaSignature::try_from(&der[idx..idx + sig_len]);
    let Ok(sig) = sig else {
        return false;
    };
    let verifying = VerifyingKey::<Sha256>::new(issuer_public_key);
    verifying.verify(payload, &sig).is_ok()
}

#[cfg(test)]
use rsa::RsaPublicKey;
#[cfg(test)]
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
#[cfg(test)]
use rsa::signature::Verifier;

fn apply_not_before(base_time: OffsetDateTime, offset: Option<NotBeforeOffset>) -> OffsetDateTime {
    match offset.unwrap_or(NotBeforeOffset::DaysAgo(1)) {
        NotBeforeOffset::DaysAgo(days) => base_time - TimeDuration::days(days as i64),
        NotBeforeOffset::DaysFromNow(days) => base_time + TimeDuration::days(days as i64),
    }
}

fn key_usage_purposes(key_usage: KeyUsage) -> Vec<KeyUsagePurpose> {
    let mut purposes = Vec::new();
    if key_usage.key_cert_sign {
        purposes.push(KeyUsagePurpose::KeyCertSign);
    }
    if key_usage.crl_sign {
        purposes.push(KeyUsagePurpose::CrlSign);
    }
    if key_usage.digital_signature {
        purposes.push(KeyUsagePurpose::DigitalSignature);
    }
    if key_usage.key_encipherment {
        purposes.push(KeyUsagePurpose::KeyEncipherment);
    }
    purposes
}

fn load_chain_inner(
    factory: &Factory,
    label: &str,
    spec: &ChainSpec,
    variant: &str,
) -> Arc<ChainInner> {
    let spec_bytes = spec.stable_bytes();

    factory.get_or_init(DOMAIN_X509_CHAIN, label, &spec_bytes, variant, |seed| {
        let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
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
        let rsa_bits = (spec.rsa_bits as u32).to_be_bytes();
        let base_time = deterministic_base_time_from_parts(&[
            label.as_bytes(),
            spec.leaf_cn.as_bytes(),
            spec.root_cn.as_bytes(),
            &rsa_bits,
        ]);

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
        root_params.serial_number = Some(next_serial_number(&mut rng));

        let root_cert = root_params.self_signed(&root_kp).expect("root cert gen");

        // --- Intermediate CA ---
        let mut int_params = CertificateParams::default();
        int_params
            .distinguished_name
            .push(DnType::CommonName, spec.intermediate_cn.clone());
        let intermediate_is_ca = spec.intermediate_is_ca.unwrap_or(true);
        int_params.is_ca = if intermediate_is_ca {
            IsCa::Ca(BasicConstraints::Constrained(0))
        } else {
            IsCa::NoCa
        };
        int_params.key_usages =
            key_usage_purposes(spec.intermediate_key_usage.unwrap_or_else(KeyUsage::ca));
        int_params.not_before = apply_not_before(base_time, spec.intermediate_not_before);
        int_params.not_after =
            int_params.not_before + TimeDuration::days(spec.intermediate_validity_days as i64);
        int_params.serial_number = Some(next_serial_number(&mut rng));

        let root_issuer = Issuer::from_params(&root_params, &root_kp);
        let int_cert = int_params
            .signed_by(&int_kp, &root_issuer)
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

        leaf_params.not_before = apply_not_before(base_time, spec.leaf_not_before);
        leaf_params.not_after =
            leaf_params.not_before + TimeDuration::days(spec.leaf_validity_days as i64);
        leaf_params.serial_number = Some(next_serial_number(&mut rng));

        let leaf_serial = leaf_params
            .serial_number
            .clone()
            .expect("leaf serial number");

        let int_issuer = Issuer::from_params(&int_params, &int_kp);
        let leaf_cert = leaf_params
            .signed_by(&leaf_kp, &int_issuer)
            .expect("leaf cert gen");

        // --- CRL (only for revoked_leaf variant) ---
        let (crl_der, crl_pem) = if variant == "revoked_leaf" {
            let crl_number = next_serial_number(&mut rng);

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

            let int_issuer = Issuer::from_params(&int_params, &int_kp);
            let crl = crl_params.signed_by(&int_issuer).expect("CRL gen");

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

fn next_serial_number(rng: &mut impl RngCore) -> rcgen::SerialNumber {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    bytes[0] &= 0x7F;
    rcgen::SerialNumber::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::X509FactoryExt;
    use crate::testutil::fx;
    use rsa::pkcs8::DecodePublicKey;
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
        let self_signed_spec = uselesskey_core_x509::X509Spec::self_signed("test.example.com");
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

    #[test]
    fn test_explicit_crl_leaf_fixture_contains_leaf_serial() {
        let factory = fx();
        let chain = X509Chain::new(factory, "svc", ChainSpec::new("svc.example.com"));
        let crl = chain.crl_for_leaf();
        assert!(!crl.der().is_empty());
        assert!(crl.pem().is_some());

        let (_, leaf) = x509_parser::certificate::X509Certificate::from_der(chain.leaf_cert_der())
            .expect("leaf parse");
        assert_eq!(crl.serial_binding_hex(), hex_encode(leaf.raw_serial()));
    }

    #[test]
    fn test_explicit_crl_intermediate_fixture_contains_intermediate_serial() {
        let factory = fx();
        let chain = X509Chain::new(factory, "svc-crl-int", ChainSpec::new("svc.example.com"));
        let crl = chain.crl_for_intermediate();
        assert!(!crl.der().is_empty());
        assert!(crl.pem().is_some());

        let (_, intermediate) =
            x509_parser::certificate::X509Certificate::from_der(chain.intermediate_cert_der())
                .expect("intermediate parse");
        assert_eq!(
            crl.serial_binding_hex(),
            hex_encode(intermediate.raw_serial())
        );
        assert_eq!(crl.issuer_binding(), chain.spec().root_cn);

        let _ = x509_parser::revocation_list::CertificateRevocationList::from_der(crl.der())
            .expect("crl parse");
    }

    #[test]
    fn test_explicit_ocsp_fixture_signature_verifies() {
        let factory = fx();
        let chain = X509Chain::new(factory, "svc-ocsp", ChainSpec::new("svc.example.com"));
        let ocsp = chain.ocsp_for_leaf(OcspCertStatus::Revoked);
        assert!(ocsp.pem().is_none());
        assert!(!ocsp.base64().is_empty());

        let (_, int_cert) =
            x509_parser::certificate::X509Certificate::from_der(chain.intermediate_cert_der())
                .expect("intermediate parse");
        let public_key =
            RsaPublicKey::from_public_key_der(int_cert.public_key().raw).expect("pubkey parse");
        assert!(verify_ocsp_like_signature(ocsp.der(), public_key));
    }

    #[test]
    fn test_explicit_ocsp_intermediate_fixture_signature_verifies() {
        let factory = fx();
        let chain = X509Chain::new(factory, "svc-ocsp-int", ChainSpec::new("svc.example.com"));
        let ocsp = chain.ocsp_for_intermediate(OcspCertStatus::Good);
        assert!(ocsp.pem().is_none());
        assert!(!ocsp.base64().is_empty());

        let (_, root_cert) =
            x509_parser::certificate::X509Certificate::from_der(chain.root_cert_der())
                .expect("root parse");
        let public_key =
            RsaPublicKey::from_public_key_der(root_cert.public_key().raw).expect("pubkey parse");
        assert!(verify_ocsp_like_signature(ocsp.der(), public_key));
        assert_eq!(ocsp.issuer_binding(), root_cert.subject().to_string());
    }
}
