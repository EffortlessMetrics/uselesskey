//! X.509 certificate generation and output.

use std::fmt;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_RSA_SHA256,
};
use rustls_pki_types::PrivatePkcs8KeyDer;
use time::Duration as TimeDuration;
use uselesskey_core::negative::CorruptPem;
use uselesskey_core::sink::TempArtifact;
use uselesskey_core::{Error, Factory};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

use crate::chain::X509Chain;
use crate::chain_spec::ChainSpec;
use crate::negative::{X509Negative, corrupt_cert_pem, truncate_cert_der};
use crate::spec::{NotBeforeOffset, X509Spec};
use crate::util::{deterministic_base_time, deterministic_serial_number};

/// Cache domain for X.509 certificate fixtures.
///
/// Keep this stable: changing it changes deterministic outputs.
pub const DOMAIN_X509_CERT: &str = "uselesskey:x509:cert";

/// An X.509 certificate fixture.
#[derive(Clone)]
pub struct X509Cert {
    factory: Factory,
    label: String,
    spec: X509Spec,
    inner: Arc<Inner>,
}

struct Inner {
    cert_der: Arc<[u8]>,
    cert_pem: String,
    private_key_pkcs8_der: Arc<[u8]>,
    private_key_pkcs8_pem: String,
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
    fn x509_self_signed(&self, label: impl AsRef<str>, spec: X509Spec) -> X509Cert;

    /// Generate a three-level X.509 certificate chain (root CA → intermediate CA → leaf).
    ///
    /// The chain is cached by `(label, spec)` and will be reused on subsequent calls
    /// with the same parameters.
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

impl X509Cert {
    fn new(factory: Factory, label: &str, spec: X509Spec) -> Self {
        let inner = load_inner(&factory, label, &spec, "good");
        Self {
            factory,
            label: label.to_string(),
            spec,
            inner,
        }
    }

    #[allow(dead_code)] // Reserved for future variant-based negative fixtures
    fn load_variant(&self, variant: &str) -> Arc<Inner> {
        load_inner(&self.factory, &self.label, &self.spec, variant)
    }

    // =========================================================================
    // Certificate outputs
    // =========================================================================

    /// DER-encoded certificate bytes.
    pub fn cert_der(&self) -> &[u8] {
        &self.inner.cert_der
    }

    /// PEM-encoded certificate.
    pub fn cert_pem(&self) -> &str {
        &self.inner.cert_pem
    }

    /// DER-encoded PKCS#8 private key bytes.
    pub fn private_key_pkcs8_der(&self) -> &[u8] {
        &self.inner.private_key_pkcs8_der
    }

    /// PEM-encoded PKCS#8 private key.
    pub fn private_key_pkcs8_pem(&self) -> &str {
        &self.inner.private_key_pkcs8_pem
    }

    /// Combined PEM containing both certificate and private key.
    ///
    /// This is a common format for TLS server configuration where
    /// a single file holds the server identity (cert + key).
    pub fn identity_pem(&self) -> String {
        format!("{}\n{}", self.cert_pem(), self.private_key_pkcs8_pem())
    }

    // =========================================================================
    // Tempfile outputs
    // =========================================================================

    /// Write the PEM certificate to a tempfile.
    pub fn write_cert_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".crt.pem", self.cert_pem())
    }

    /// Write the DER certificate to a tempfile.
    pub fn write_cert_der(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_bytes("uselesskey-", ".crt.der", self.cert_der())
    }

    /// Write the PEM private key to a tempfile.
    pub fn write_private_key_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".key.pem", self.private_key_pkcs8_pem())
    }

    /// Write the combined identity PEM (cert + key) to a tempfile.
    pub fn write_identity_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".identity.pem", &self.identity_pem())
    }

    // =========================================================================
    // Negative fixtures
    // =========================================================================

    /// Produce a corrupted variant of the certificate PEM.
    pub fn corrupt_cert_pem(&self, how: CorruptPem) -> String {
        corrupt_cert_pem(self.cert_pem(), how)
    }

    /// Produce a truncated variant of the certificate DER.
    pub fn truncate_cert_der(&self, len: usize) -> Vec<u8> {
        truncate_cert_der(self.cert_der(), len)
    }

    /// Generate a negative fixture variant of this certificate.
    ///
    /// The variant is cached separately from the valid certificate.
    pub fn negative(&self, negative_type: X509Negative) -> X509Cert {
        let modified_spec = negative_type.apply_to_spec(&self.spec);
        let variant = negative_type.variant_name();
        let inner = load_inner_with_spec(&self.factory, &self.label, &modified_spec, variant);

        X509Cert {
            factory: self.factory.clone(),
            label: self.label.clone(),
            spec: modified_spec,
            inner,
        }
    }

    /// Get a certificate that is already expired.
    pub fn expired(&self) -> X509Cert {
        self.negative(X509Negative::Expired)
    }

    /// Get a certificate that is not yet valid.
    pub fn not_yet_valid(&self) -> X509Cert {
        self.negative(X509Negative::NotYetValid)
    }

    /// Get a certificate with wrong key usage flags.
    pub fn wrong_key_usage(&self) -> X509Cert {
        self.negative(X509Negative::WrongKeyUsage)
    }

    // =========================================================================
    // Metadata
    // =========================================================================

    /// Get the specification used to create this certificate.
    pub fn spec(&self) -> &X509Spec {
        &self.spec
    }

    /// Get the label used to create this certificate.
    pub fn label(&self) -> &str {
        &self.label
    }
}

fn load_inner(factory: &Factory, label: &str, spec: &X509Spec, variant: &str) -> Arc<Inner> {
    load_inner_with_spec(factory, label, spec, variant)
}

fn load_inner_with_spec(
    factory: &Factory,
    label: &str,
    spec: &X509Spec,
    variant: &str,
) -> Arc<Inner> {
    let spec_bytes = spec.stable_bytes();

    factory.get_or_init(DOMAIN_X509_CERT, label, &spec_bytes, variant, |rng| {
        // Generate RSA key using uselesskey-rsa for deterministic key generation.
        // We use the label + variant to derive a unique key.
        let key_label = format!("{}-{}-key", label, variant);
        let rsa_spec = RsaSpec::new(spec.rsa_bits);
        let rsa_keypair = factory.rsa(&key_label, rsa_spec);

        // Get the PKCS#8 DER key and convert it to rcgen's KeyPair
        let pkcs8_der = rsa_keypair.private_key_pkcs8_der();
        let pkcs8_key = PrivatePkcs8KeyDer::from(pkcs8_der.to_vec());
        let key_pair =
            KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_key, &PKCS_RSA_SHA256).expect("key parse");

        // Build certificate parameters
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, spec.subject_cn.clone());

        // Set validity period based on spec
        let base_time = {
            let mut hasher = blake3::Hasher::new();
            let label_bytes = label.as_bytes();
            hasher.update(&(label_bytes.len() as u32).to_be_bytes());
            hasher.update(label_bytes);
            let subject_bytes = spec.subject_cn.as_bytes();
            hasher.update(&(subject_bytes.len() as u32).to_be_bytes());
            hasher.update(subject_bytes);
            let issuer_bytes = spec.issuer_cn.as_bytes();
            hasher.update(&(issuer_bytes.len() as u32).to_be_bytes());
            hasher.update(issuer_bytes);
            hasher.update(&(spec.rsa_bits as u32).to_be_bytes());
            deterministic_base_time(hasher)
        };

        let not_before = match spec.not_before_offset {
            NotBeforeOffset::DaysAgo(days) => base_time - TimeDuration::days(days as i64),
            NotBeforeOffset::DaysFromNow(days) => base_time + TimeDuration::days(days as i64),
        };

        let not_after = not_before + TimeDuration::days(spec.validity_days as i64);

        params.not_before = not_before;
        params.not_after = not_after;
        params.serial_number = Some(deterministic_serial_number(rng));

        // Set CA status
        if spec.is_ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        } else {
            params.is_ca = IsCa::NoCa;
        }

        // Set key usage
        let mut key_usages = Vec::new();
        if spec.key_usage.digital_signature {
            key_usages.push(KeyUsagePurpose::DigitalSignature);
        }
        if spec.key_usage.key_encipherment {
            key_usages.push(KeyUsagePurpose::KeyEncipherment);
        }
        if spec.key_usage.key_cert_sign {
            key_usages.push(KeyUsagePurpose::KeyCertSign);
        }
        if spec.key_usage.crl_sign {
            key_usages.push(KeyUsagePurpose::CrlSign);
        }
        params.key_usages = key_usages;

        // Add extended key usage for TLS
        if !spec.is_ca {
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
        }

        // Generate the self-signed certificate
        let cert = params.self_signed(&key_pair).expect("cert generation");

        let cert_der: Arc<[u8]> = Arc::from(cert.der().as_ref());
        let cert_pem = cert.pem();

        let private_key_pkcs8_der: Arc<[u8]> = Arc::from(pkcs8_der);
        let private_key_pkcs8_pem = rsa_keypair.private_key_pkcs8_pem().to_string();

        Inner {
            cert_der,
            cert_pem,
            private_key_pkcs8_der,
            private_key_pkcs8_pem,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use uselesskey_core::Seed;

    #[test]
    fn test_self_signed_cert_generation() {
        let factory = Factory::random();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        assert!(!cert.cert_der().is_empty());
        assert!(cert.cert_pem().contains("-----BEGIN CERTIFICATE-----"));
        assert!(!cert.private_key_pkcs8_der().is_empty());
        assert!(
            cert.private_key_pkcs8_pem()
                .contains("-----BEGIN PRIVATE KEY-----")
        );
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
        let factory = Factory::random();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        let identity = cert.identity_pem();
        assert!(identity.contains("-----BEGIN CERTIFICATE-----"));
        assert!(identity.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_expired_cert() {
        let factory = Factory::random();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        let expired = cert.expired();
        // The expired cert should have a different DER (different validity)
        assert_ne!(cert.cert_der(), expired.cert_der());
    }

    #[test]
    fn test_not_yet_valid_cert() {
        let factory = Factory::random();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        let not_valid = cert.not_yet_valid();
        assert_ne!(cert.cert_der(), not_valid.cert_der());
    }

    #[test]
    fn test_corrupt_cert_pem() {
        let factory = Factory::random();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        let corrupted = cert.corrupt_cert_pem(CorruptPem::BadHeader);
        assert!(corrupted.contains("-----BEGIN CORRUPTED KEY-----"));
    }

    #[test]
    fn test_truncate_cert_der() {
        let factory = Factory::random();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        let truncated = cert.truncate_cert_der(10);
        assert_eq!(truncated.len(), 10);
    }

    #[test]
    fn test_tempfile_outputs() {
        let factory = Factory::random();
        let spec = X509Spec::self_signed("test.example.com");
        let cert = factory.x509_self_signed("test", spec);

        let cert_file = cert.write_cert_pem().unwrap();
        assert!(cert_file.path().exists());

        let key_file = cert.write_private_key_pem().unwrap();
        assert!(key_file.path().exists());

        let identity_file = cert.write_identity_pem().unwrap();
        assert!(identity_file.path().exists());
    }
}
