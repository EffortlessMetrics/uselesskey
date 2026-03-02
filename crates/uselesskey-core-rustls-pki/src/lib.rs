//! rustls-pki-types adapter traits for uselesskey fixtures.
//!
//! This crate is intentionally focused on PKI conversion only:
//! converting fixture outputs into `rustls_pki_types` key and certificate types.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Extension trait to convert uselesskey fixtures into `PrivateKeyDer`.
///
/// Implemented for types that have a PKCS#8 DER private key.
pub trait RustlsPrivateKeyExt {
    /// Convert the private key to a `PrivateKeyDer<'static>` (PKCS#8 variant).
    fn private_key_der_rustls(&self) -> PrivateKeyDer<'static>;
}

/// Extension trait to convert uselesskey X.509 fixtures into `CertificateDer`.
///
/// Implemented for types that represent a single certificate.
pub trait RustlsCertExt {
    /// Convert the certificate to a `CertificateDer<'static>`.
    fn certificate_der_rustls(&self) -> CertificateDer<'static>;
}

/// Extension trait for X.509 certificate chains.
///
/// Provides the full chain in rustls format.
#[cfg(feature = "x509")]
pub trait RustlsChainExt {
    /// Get the certificate chain as a `Vec<CertificateDer>` (leaf + intermediate, no root).
    ///
    /// This is the format expected by `rustls::ServerConfig`.
    fn chain_der_rustls(&self) -> Vec<CertificateDer<'static>>;

    /// Get the root CA certificate as a `CertificateDer`.
    ///
    /// Use this to add to a `RootCertStore` for client-side verification.
    fn root_certificate_der_rustls(&self) -> CertificateDer<'static>;
}

#[cfg(feature = "x509")]
impl RustlsPrivateKeyExt for uselesskey_x509::X509Cert {
    fn private_key_der_rustls(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            self.private_key_pkcs8_der().to_vec(),
        ))
    }
}

#[cfg(feature = "x509")]
impl RustlsCertExt for uselesskey_x509::X509Cert {
    fn certificate_der_rustls(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.cert_der().to_vec())
    }
}

#[cfg(feature = "x509")]
impl RustlsPrivateKeyExt for uselesskey_x509::X509Chain {
    fn private_key_der_rustls(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            self.leaf_private_key_pkcs8_der().to_vec(),
        ))
    }
}

#[cfg(feature = "x509")]
impl RustlsCertExt for uselesskey_x509::X509Chain {
    fn certificate_der_rustls(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.leaf_cert_der().to_vec())
    }
}

#[cfg(feature = "x509")]
impl RustlsChainExt for uselesskey_x509::X509Chain {
    fn chain_der_rustls(&self) -> Vec<CertificateDer<'static>> {
        vec![
            CertificateDer::from(self.leaf_cert_der().to_vec()),
            CertificateDer::from(self.intermediate_cert_der().to_vec()),
        ]
    }

    fn root_certificate_der_rustls(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.root_cert_der().to_vec())
    }
}

#[cfg(feature = "rsa")]
impl RustlsPrivateKeyExt for uselesskey_rsa::RsaKeyPair {
    fn private_key_der_rustls(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            self.private_key_pkcs8_der().to_vec(),
        ))
    }
}

#[cfg(feature = "ecdsa")]
impl RustlsPrivateKeyExt for uselesskey_ecdsa::EcdsaKeyPair {
    fn private_key_der_rustls(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            self.private_key_pkcs8_der().to_vec(),
        ))
    }
}

#[cfg(feature = "ed25519")]
impl RustlsPrivateKeyExt for uselesskey_ed25519::Ed25519KeyPair {
    fn private_key_der_rustls(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            self.private_key_pkcs8_der().to_vec(),
        ))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "x509")]
    mod x509_tests {
        use crate::{RustlsCertExt, RustlsChainExt, RustlsPrivateKeyExt};
        use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

        #[test]
        fn test_self_signed_private_key() {
            let fx = uselesskey_core::Factory::random();
            let cert = fx.x509_self_signed("test", X509Spec::self_signed("test.example.com"));

            let key = cert.private_key_der_rustls();
            assert_eq!(key.secret_der(), cert.private_key_pkcs8_der());
        }

        #[test]
        fn test_self_signed_certificate() {
            let fx = uselesskey_core::Factory::random();
            let cert = fx.x509_self_signed("test", X509Spec::self_signed("test.example.com"));

            let cert_der = cert.certificate_der_rustls();
            assert_eq!(cert_der.as_ref(), cert.cert_der());
        }

        #[test]
        fn test_chain_private_key() {
            let fx = uselesskey_core::Factory::random();
            let chain = fx.x509_chain("test", ChainSpec::new("test.example.com"));

            let key = chain.private_key_der_rustls();
            assert_eq!(key.secret_der(), chain.leaf_private_key_pkcs8_der());
        }

        #[test]
        fn test_chain_certificate() {
            let fx = uselesskey_core::Factory::random();
            let chain = fx.x509_chain("test", ChainSpec::new("test.example.com"));

            let cert_der = chain.certificate_der_rustls();
            assert_eq!(cert_der.as_ref(), chain.leaf_cert_der());
        }

        #[test]
        fn test_chain_der_rustls() {
            let fx = uselesskey_core::Factory::random();
            let chain = fx.x509_chain("test", ChainSpec::new("test.example.com"));

            let chain_certs = chain.chain_der_rustls();
            assert_eq!(chain_certs.len(), 2);
            assert_eq!(chain_certs[0].as_ref(), chain.leaf_cert_der());
            assert_eq!(chain_certs[1].as_ref(), chain.intermediate_cert_der());
        }

        #[test]
        fn test_root_certificate() {
            let fx = uselesskey_core::Factory::random();
            let chain = fx.x509_chain("test", ChainSpec::new("test.example.com"));

            let root = chain.root_certificate_der_rustls();
            assert_eq!(root.as_ref(), chain.root_cert_der());
        }
    }

    #[cfg(feature = "rsa")]
    mod rsa_tests {
        use crate::RustlsPrivateKeyExt;
        use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

        #[test]
        fn test_rsa_private_key() {
            let fx = uselesskey_core::Factory::random();
            let keypair = fx.rsa("test", RsaSpec::rs256());

            let key = keypair.private_key_der_rustls();
            assert_eq!(key.secret_der(), keypair.private_key_pkcs8_der());
        }
    }

    #[cfg(feature = "ecdsa")]
    mod ecdsa_tests {
        use crate::RustlsPrivateKeyExt;
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

        #[test]
        fn test_ecdsa_es256_private_key() {
            let fx = uselesskey_core::Factory::random();
            let keypair = fx.ecdsa("test", EcdsaSpec::es256());

            let key = keypair.private_key_der_rustls();
            assert_eq!(key.secret_der(), keypair.private_key_pkcs8_der());
        }

        #[test]
        fn test_ecdsa_es384_private_key() {
            let fx = uselesskey_core::Factory::random();
            let keypair = fx.ecdsa("test", EcdsaSpec::es384());

            let key = keypair.private_key_der_rustls();
            assert_eq!(key.secret_der(), keypair.private_key_pkcs8_der());
        }
    }

    #[cfg(feature = "ed25519")]
    mod ed25519_tests {
        use crate::RustlsPrivateKeyExt;
        use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

        #[test]
        fn test_ed25519_private_key() {
            let fx = uselesskey_core::Factory::random();
            let keypair = fx.ed25519("test", Ed25519Spec::new());

            let key = keypair.private_key_der_rustls();
            assert_eq!(key.secret_der(), keypair.private_key_pkcs8_der());
        }
    }
}
