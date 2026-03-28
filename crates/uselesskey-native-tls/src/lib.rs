#![forbid(unsafe_code)]

//! native-tls adapters for uselesskey X.509 fixtures.
//!
//! This crate keeps platform-specific native-tls identity/certificate
//! wiring inside adapter-level helpers.

#[cfg(feature = "x509")]
use native_tls::{Certificate, Identity, TlsConnector, TlsConnectorBuilder};

/// Convert X.509 fixtures into native-tls identity/certificate inputs.
#[cfg(feature = "x509")]
pub trait NativeTlsIdentityExt {
    /// Build an `Identity` containing certificate + private key.
    fn identity_native_tls(&self) -> Identity;

    /// Build a trusted `Certificate` (leaf for self-signed, root for chains).
    fn trust_certificate_native_tls(&self) -> Certificate;

    /// Create connector builder with fixture trust installed.
    fn connector_builder_native_tls(&self) -> TlsConnectorBuilder {
        let mut builder = TlsConnector::builder();
        builder
            .add_root_certificate(self.trust_certificate_native_tls())
            .danger_accept_invalid_hostnames(true);
        builder
    }

    /// Create connector with fixture trust installed.
    fn connector_native_tls(&self) -> TlsConnector {
        self.connector_builder_native_tls()
            .build()
            .expect("valid connector")
    }
}

#[cfg(feature = "x509")]
impl NativeTlsIdentityExt for uselesskey_x509::X509Cert {
    fn identity_native_tls(&self) -> Identity {
        Identity::from_pkcs8(self.cert_pem().as_bytes(), self.private_key_pkcs8_pem().as_bytes())
            .expect("valid native-tls identity from self-signed fixture")
    }

    fn trust_certificate_native_tls(&self) -> Certificate {
        Certificate::from_pem(self.cert_pem().as_bytes())
            .expect("valid native-tls certificate from self-signed fixture")
    }
}

#[cfg(feature = "x509")]
impl NativeTlsIdentityExt for uselesskey_x509::X509Chain {
    fn identity_native_tls(&self) -> Identity {
        Identity::from_pkcs8(self.chain_pem().as_bytes(), self.leaf_private_key_pkcs8_pem().as_bytes())
            .expect("valid native-tls identity from chain fixture")
    }

    fn trust_certificate_native_tls(&self) -> Certificate {
        Certificate::from_pem(self.root_cert_pem().as_bytes())
            .expect("valid native-tls root certificate from chain fixture")
    }
}
