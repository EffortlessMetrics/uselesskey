use uselesskey_core::negative::CorruptPem;

use super::X509Cert;
use super::material::load_inner_with_spec;
use crate::negative::{
    corrupt_cert_der_deterministic, corrupt_cert_pem, corrupt_cert_pem_deterministic,
    truncate_cert_der,
};
use crate::srp::negative::X509Negative;

impl X509Cert {
    // =========================================================================
    // Negative fixtures
    // =========================================================================

    /// Produce a corrupted variant of the certificate PEM.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_core::negative::CorruptPem;
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// let bad = cert.corrupt_cert_pem(CorruptPem::BadHeader);
    /// assert!(bad.contains("CORRUPTED"));
    /// ```
    pub fn corrupt_cert_pem(&self, how: CorruptPem) -> String {
        corrupt_cert_pem(self.cert_pem(), how)
    }

    /// Produce a deterministic corrupted certificate PEM using a variant string.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// let bad = cert.corrupt_cert_pem_deterministic("corrupt:v1");
    /// assert!(!bad.is_empty());
    /// ```
    pub fn corrupt_cert_pem_deterministic(&self, variant: &str) -> String {
        corrupt_cert_pem_deterministic(self.cert_pem(), variant)
    }

    /// Produce a truncated variant of the certificate DER.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// let truncated = cert.truncate_cert_der(10);
    /// assert_eq!(truncated.len(), 10);
    /// ```
    pub fn truncate_cert_der(&self, len: usize) -> Vec<u8> {
        truncate_cert_der(self.cert_der(), len)
    }

    /// Produce a deterministic corrupted certificate DER using a variant string.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// let bad = cert.corrupt_cert_der_deterministic("corrupt:v1");
    /// assert!(!bad.is_empty());
    /// ```
    pub fn corrupt_cert_der_deterministic(&self, variant: &str) -> Vec<u8> {
        corrupt_cert_der_deterministic(self.cert_der(), variant)
    }

    /// Generate a negative fixture variant of this certificate.
    ///
    /// The variant is cached separately from the valid certificate.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec, X509Negative};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// let expired = cert.negative(X509Negative::Expired);
    /// assert_ne!(cert.cert_der(), expired.cert_der());
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// let expired = cert.expired();
    /// assert_ne!(cert.cert_der(), expired.cert_der());
    /// ```
    pub fn expired(&self) -> X509Cert {
        self.negative(X509Negative::Expired)
    }

    /// Get a certificate that is not yet valid.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// let future = cert.not_yet_valid();
    /// assert_ne!(cert.cert_der(), future.cert_der());
    /// ```
    pub fn not_yet_valid(&self) -> X509Cert {
        self.negative(X509Negative::NotYetValid)
    }

    /// Get a certificate with wrong key usage flags.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use uselesskey_core::{Factory, Seed};
    /// # use uselesskey_x509::{X509FactoryExt, X509Spec};
    /// let fx = Factory::deterministic(Seed::from_env_value("test-seed").unwrap());
    /// let cert = fx.x509_self_signed("svc", X509Spec::self_signed("svc.example.com"));
    /// let wrong = cert.wrong_key_usage();
    /// assert!(wrong.spec().is_ca);
    /// ```
    pub fn wrong_key_usage(&self) -> X509Cert {
        self.negative(X509Negative::WrongKeyUsage)
    }
}
