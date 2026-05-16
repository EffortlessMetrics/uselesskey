use uselesskey_core::Error;
use uselesskey_core::sink::TempArtifact;

use super::X509Cert;
use crate::srp::spec::X509Spec;

impl X509Cert {
    // =========================================================================
    // Certificate outputs
    // =========================================================================

    /// DER-encoded certificate bytes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// assert!(!cert.cert_der().is_empty());
    /// ```
    pub fn cert_der(&self) -> &[u8] {
        &self.inner.cert_der
    }

    /// PEM-encoded certificate.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// assert!(cert.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
    /// ```
    pub fn cert_pem(&self) -> &str {
        &self.inner.cert_pem
    }

    /// DER-encoded PKCS#8 private key bytes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// assert!(!cert.private_key_pkcs8_der().is_empty());
    /// ```
    pub fn private_key_pkcs8_der(&self) -> &[u8] {
        &self.inner.private_key_pkcs8_der
    }

    /// PEM-encoded PKCS#8 private key.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// assert!(cert.private_key_pkcs8_pem().contains("-----BEGIN PRIVATE KEY-----"));
    /// ```
    pub fn private_key_pkcs8_pem(&self) -> &str {
        &self.inner.private_key_pkcs8_pem
    }

    /// Combined PEM containing both certificate and private key.
    ///
    /// This is a common format for TLS server configuration where
    /// a single file holds the server identity (cert + key).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// let identity = cert.identity_pem();
    /// assert!(identity.contains("-----BEGIN CERTIFICATE-----"));
    /// assert!(identity.contains("-----BEGIN PRIVATE KEY-----"));
    /// ```
    pub fn identity_pem(&self) -> String {
        format!("{}\n{}", self.cert_pem(), self.private_key_pkcs8_pem())
    }

    // =========================================================================
    // Tempfile outputs
    // =========================================================================

    /// Write the PEM certificate to a tempfile.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// let temp = cert.write_cert_pem().unwrap();
    /// assert!(temp.path().exists());
    /// ```
    pub fn write_cert_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".crt.pem", self.cert_pem())
    }

    /// Write the DER certificate to a tempfile.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// let temp = cert.write_cert_der().unwrap();
    /// assert!(temp.path().exists());
    /// ```
    pub fn write_cert_der(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_bytes("uselesskey-", ".crt.der", self.cert_der())
    }

    /// Write the PEM private key to a tempfile.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// let temp = cert.write_private_key_pem().unwrap();
    /// assert!(temp.path().exists());
    /// ```
    pub fn write_private_key_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".key.pem", self.private_key_pkcs8_pem())
    }

    /// Write the combined identity PEM (cert + key) to a tempfile.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// let temp = cert.write_identity_pem().unwrap();
    /// assert!(temp.path().exists());
    /// ```
    pub fn write_identity_pem(&self) -> Result<TempArtifact, Error> {
        TempArtifact::new_string("uselesskey-", ".identity.pem", &self.identity_pem())
    }

    // =========================================================================
    // Metadata
    // =========================================================================

    /// Get the specification used to create this certificate.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let spec = X509Spec::self_signed("svc.example.com");
    /// let cert = fx.x509_self_signed("svc", spec.clone());
    /// assert_eq!(cert.spec().subject_cn, "svc.example.com");
    /// ```
    pub fn spec(&self) -> &X509Spec {
        &self.spec
    }

    /// Get the label used to create this certificate.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("my-svc", X509Spec::self_signed("svc.example.com"));
    /// assert_eq!(cert.label(), "my-svc");
    /// ```
    pub fn label(&self) -> &str {
        &self.label
    }
}
