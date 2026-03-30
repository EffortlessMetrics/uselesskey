#![forbid(unsafe_code)]

//! native-tls conversions for uselesskey X.509 fixtures.

use native_tls::{Certificate, Identity, TlsConnector, TlsConnectorBuilder};

pub trait NativeTlsX509Ext {
    fn identity_native_tls(&self) -> Identity;
    fn certificate_native_tls(&self) -> Certificate;
    fn connector_builder_native_tls(&self) -> TlsConnectorBuilder {
        let mut builder = TlsConnector::builder();
        builder.add_root_certificate(self.certificate_native_tls());
        builder
    }
}

impl NativeTlsX509Ext for uselesskey_x509::X509Cert {
    fn identity_native_tls(&self) -> Identity {
        Identity::from_pkcs8(
            self.cert_pem().as_bytes(),
            self.private_key_pkcs8_pem().as_bytes(),
        )
        .expect("valid certificate/key PEM")
    }

    fn certificate_native_tls(&self) -> Certificate {
        Certificate::from_pem(self.cert_pem().as_bytes()).expect("valid certificate PEM")
    }
}

pub trait NativeTlsX509ChainExt {
    fn leaf_identity_native_tls(&self) -> Identity;
    fn root_certificate_native_tls(&self) -> Certificate;
    fn connector_builder_native_tls(&self) -> TlsConnectorBuilder {
        let mut builder = TlsConnector::builder();
        builder.add_root_certificate(self.root_certificate_native_tls());
        builder
    }
}

impl NativeTlsX509ChainExt for uselesskey_x509::X509Chain {
    fn leaf_identity_native_tls(&self) -> Identity {
        Identity::from_pkcs8(
            self.leaf_cert_pem().as_bytes(),
            self.leaf_private_key_pkcs8_pem().as_bytes(),
        )
        .expect("valid leaf certificate/key PEM")
    }

    fn root_certificate_native_tls(&self) -> Certificate {
        Certificate::from_pem(self.root_cert_pem().as_bytes()).expect("valid root certificate PEM")
    }
}

#[cfg(test)]
mod tests {
    use uselesskey_core::Factory;
    use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

    use crate::{NativeTlsX509ChainExt, NativeTlsX509Ext};

    #[test]
    fn self_signed_native_tls_conversions() {
        let cert = Factory::random()
            .x509_self_signed("native-tls-cert", X509Spec::self_signed("svc.example.com"));
        let _identity = cert.identity_native_tls();
        let _cert = cert.certificate_native_tls();
        let _builder = cert.connector_builder_native_tls();
    }

    #[test]
    fn chain_native_tls_conversions() {
        let chain =
            Factory::random().x509_chain("native-tls-chain", ChainSpec::new("svc.example.com"));
        let _identity = chain.leaf_identity_native_tls();
        let _root = chain.root_certificate_native_tls();
        let _builder = chain.connector_builder_native_tls();
    }
}
