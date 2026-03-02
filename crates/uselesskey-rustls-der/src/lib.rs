#![forbid(unsafe_code)]

//! DER conversion adapters between uselesskey fixtures and `rustls-pki-types`.

use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Extension trait to convert uselesskey fixtures into `PrivateKeyDer`.
///
/// Implemented for types that expose PKCS#8 DER private keys.
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
#[cfg(feature = "x509")]
pub trait RustlsChainExt {
    /// Get the certificate chain as a `Vec<CertificateDer>` (leaf + intermediate, no root).
    fn chain_der_rustls(&self) -> Vec<CertificateDer<'static>>;

    /// Get the root CA certificate as a `CertificateDer`.
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
