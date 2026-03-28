#![forbid(unsafe_code)]

//! native-tls adapters for uselesskey X.509 fixtures.

use native_tls::{Certificate, Identity, TlsConnector};

pub trait NativeTlsX509Ext {
    fn identity_native_tls_pkcs8(&self) -> Identity;
    fn root_certificate_native_tls(&self) -> Certificate;
    fn connector_native_tls(&self) -> TlsConnector;
}

impl NativeTlsX509Ext for uselesskey_x509::X509Chain {
    fn identity_native_tls_pkcs8(&self) -> Identity {
        Identity::from_pkcs8(self.leaf_cert_pem().as_bytes(), self.leaf_private_key_pkcs8_pem().as_bytes())
            .expect("valid PKCS#8 identity material")
    }

    fn root_certificate_native_tls(&self) -> Certificate {
        Certificate::from_pem(self.root_cert_pem().as_bytes()).expect("valid root certificate PEM")
    }

    fn connector_native_tls(&self) -> TlsConnector {
        let cert = self.root_certificate_native_tls();
        TlsConnector::builder()
            .add_root_certificate(cert)
            .build()
            .expect("build native-tls connector")
    }
}

impl NativeTlsX509Ext for uselesskey_x509::X509Cert {
    fn identity_native_tls_pkcs8(&self) -> Identity {
        Identity::from_pkcs8(self.cert_pem().as_bytes(), self.private_key_pkcs8_pem().as_bytes())
            .expect("valid PKCS#8 identity material")
    }

    fn root_certificate_native_tls(&self) -> Certificate {
        Certificate::from_pem(self.cert_pem().as_bytes()).expect("valid root certificate PEM")
    }

    fn connector_native_tls(&self) -> TlsConnector {
        let cert = self.root_certificate_native_tls();
        TlsConnector::builder()
            .add_root_certificate(cert)
            .build()
            .expect("build native-tls connector")
    }
}
