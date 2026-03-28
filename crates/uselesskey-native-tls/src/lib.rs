#![forbid(unsafe_code)]

//! native-tls adapters for uselesskey X.509 fixtures.
//!
//! This crate only converts existing fixture bytes to native-tls-friendly
//! types and builders.

#[cfg(feature = "x509")]
use native_tls::{Certificate, Identity, TlsConnector, TlsConnectorBuilder};

#[cfg(feature = "x509")]
pub trait NativeTlsX509Ext {
    fn native_tls_identity_pkcs8(&self) -> Identity;
    fn native_tls_root_certificate(&self) -> Certificate;
    fn native_tls_connector_builder(&self) -> TlsConnectorBuilder;
    fn native_tls_connector(&self) -> TlsConnector;
}

#[cfg(feature = "x509")]
impl NativeTlsX509Ext for uselesskey_x509::X509Chain {
    fn native_tls_identity_pkcs8(&self) -> Identity {
        Identity::from_pkcs8(
            self.full_chain_pem().as_bytes(),
            self.leaf_private_key_pkcs8_pem().as_bytes(),
        )
        .expect("valid chain/key for native-tls identity")
    }

    fn native_tls_root_certificate(&self) -> Certificate {
        Certificate::from_der(self.root_cert_der()).expect("valid root cert der")
    }

    fn native_tls_connector_builder(&self) -> TlsConnectorBuilder {
        let mut builder = TlsConnector::builder();
        builder.add_root_certificate(self.native_tls_root_certificate());
        builder
    }

    fn native_tls_connector(&self) -> TlsConnector {
        self.native_tls_connector_builder()
            .build()
            .expect("native tls connector from uselesskey chain")
    }
}
