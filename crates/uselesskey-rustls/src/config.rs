//! Convenience builders for `rustls::ServerConfig` and `rustls::ClientConfig`.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

#[cfg(feature = "x509")]
use crate::RustlsCertExt;
#[cfg(feature = "x509")]
use crate::RustlsChainExt;
#[cfg(feature = "server-config")]
use crate::RustlsPrivateKeyExt;

// ---------------------------------------------------------------------------
// ServerConfig
// ---------------------------------------------------------------------------

/// Extension trait that builds a `rustls::ServerConfig` from uselesskey fixtures.
#[cfg(feature = "server-config")]
pub trait RustlsServerConfigExt {
    /// Build a `ServerConfig` using the process-default `CryptoProvider`.
    fn server_config_rustls(&self) -> rustls::ServerConfig;

    /// Build a `ServerConfig` with an explicit `CryptoProvider`.
    fn server_config_rustls_with_provider(
        &self,
        provider: Arc<CryptoProvider>,
    ) -> rustls::ServerConfig;
}

#[cfg(all(feature = "x509", feature = "server-config"))]
impl RustlsServerConfigExt for uselesskey_x509::X509Chain {
    fn server_config_rustls(&self) -> rustls::ServerConfig {
        let private_key = self.private_key_der_rustls();
        let cert_chain = self.chain_der_rustls();
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .expect("valid server config")
    }

    fn server_config_rustls_with_provider(
        &self,
        provider: Arc<CryptoProvider>,
    ) -> rustls::ServerConfig {
        let private_key = self.private_key_der_rustls();
        let cert_chain = self.chain_der_rustls();
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("valid protocol versions")
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .expect("valid server config")
    }
}

#[cfg(all(feature = "x509", feature = "server-config"))]
impl RustlsServerConfigExt for uselesskey_x509::X509Cert {
    fn server_config_rustls(&self) -> rustls::ServerConfig {
        let private_key = self.private_key_der_rustls();
        let cert_chain = vec![self.certificate_der_rustls()];
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .expect("valid server config")
    }

    fn server_config_rustls_with_provider(
        &self,
        provider: Arc<CryptoProvider>,
    ) -> rustls::ServerConfig {
        let private_key = self.private_key_der_rustls();
        let cert_chain = vec![self.certificate_der_rustls()];
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("valid protocol versions")
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .expect("valid server config")
    }
}

// ---------------------------------------------------------------------------
// ClientConfig
// ---------------------------------------------------------------------------

/// Extension trait that builds a `rustls::ClientConfig` from uselesskey fixtures.
#[cfg(feature = "client-config")]
pub trait RustlsClientConfigExt {
    /// Build a `ClientConfig` that trusts the root CA, with no client certificate.
    fn client_config_rustls(&self) -> rustls::ClientConfig;

    /// Build a `ClientConfig` with an explicit `CryptoProvider`.
    fn client_config_rustls_with_provider(
        &self,
        provider: Arc<CryptoProvider>,
    ) -> rustls::ClientConfig;
}

#[cfg(all(feature = "x509", feature = "client-config"))]
impl RustlsClientConfigExt for uselesskey_x509::X509Chain {
    fn client_config_rustls(&self) -> rustls::ClientConfig {
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(self.root_certificate_der_rustls())
            .expect("valid root cert");
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    }

    fn client_config_rustls_with_provider(
        &self,
        provider: Arc<CryptoProvider>,
    ) -> rustls::ClientConfig {
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(self.root_certificate_der_rustls())
            .expect("valid root cert");
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("valid protocol versions")
            .with_root_certificates(root_store)
            .with_no_client_auth()
    }
}

#[cfg(all(feature = "x509", feature = "client-config"))]
impl RustlsClientConfigExt for uselesskey_x509::X509Cert {
    fn client_config_rustls(&self) -> rustls::ClientConfig {
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(self.certificate_der_rustls())
            .expect("valid root cert");
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    }

    fn client_config_rustls_with_provider(
        &self,
        provider: Arc<CryptoProvider>,
    ) -> rustls::ClientConfig {
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(self.certificate_der_rustls())
            .expect("valid root cert");
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("valid protocol versions")
            .with_root_certificates(root_store)
            .with_no_client_auth()
    }
}

// ---------------------------------------------------------------------------
// mTLS
// ---------------------------------------------------------------------------

/// Extension trait for mutual TLS configurations.
#[cfg(all(feature = "server-config", feature = "client-config"))]
pub trait RustlsMtlsExt {
    /// Build a `ServerConfig` that requires client certificates verified against
    /// the chain's root CA.
    fn server_config_mtls_rustls(&self) -> rustls::ServerConfig;

    /// Build a `ServerConfig` for mTLS with an explicit `CryptoProvider`.
    fn server_config_mtls_rustls_with_provider(
        &self,
        provider: Arc<CryptoProvider>,
    ) -> rustls::ServerConfig;

    /// Build a `ClientConfig` that presents the leaf certificate as a client
    /// certificate and trusts the root CA.
    fn client_config_mtls_rustls(&self) -> rustls::ClientConfig;

    /// Build a `ClientConfig` for mTLS with an explicit `CryptoProvider`.
    fn client_config_mtls_rustls_with_provider(
        &self,
        provider: Arc<CryptoProvider>,
    ) -> rustls::ClientConfig;
}

#[cfg(all(feature = "x509", feature = "server-config", feature = "client-config"))]
impl RustlsMtlsExt for uselesskey_x509::X509Chain {
    fn server_config_mtls_rustls(&self) -> rustls::ServerConfig {
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(self.root_certificate_der_rustls())
            .expect("valid root cert");

        let client_verifier = rustls::server::WebPkiClientVerifier::builder(root_store.into())
            .build()
            .expect("valid client verifier");

        let private_key = self.private_key_der_rustls();
        let cert_chain = self.chain_der_rustls();

        rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(cert_chain, private_key)
            .expect("valid mTLS server config")
    }

    fn server_config_mtls_rustls_with_provider(
        &self,
        provider: Arc<CryptoProvider>,
    ) -> rustls::ServerConfig {
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(self.root_certificate_der_rustls())
            .expect("valid root cert");

        let client_verifier = rustls::server::WebPkiClientVerifier::builder(root_store.into())
            .build()
            .expect("valid client verifier");

        let private_key = self.private_key_der_rustls();
        let cert_chain = self.chain_der_rustls();

        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("valid protocol versions")
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(cert_chain, private_key)
            .expect("valid mTLS server config")
    }

    fn client_config_mtls_rustls(&self) -> rustls::ClientConfig {
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(self.root_certificate_der_rustls())
            .expect("valid root cert");

        let private_key = self.private_key_der_rustls();
        let cert_chain = self.chain_der_rustls();

        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, private_key)
            .expect("valid mTLS client config")
    }

    fn client_config_mtls_rustls_with_provider(
        &self,
        provider: Arc<CryptoProvider>,
    ) -> rustls::ClientConfig {
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(self.root_certificate_der_rustls())
            .expect("valid root cert");

        let private_key = self.private_key_der_rustls();
        let cert_chain = self.chain_der_rustls();

        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("valid protocol versions")
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, private_key)
            .expect("valid mTLS client config")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(all(feature = "server-config", feature = "client-config"))]
mod tests {
    use super::*;
    use uselesskey_core::Factory;
    use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

    use std::sync::Once;
    static INIT: Once = Once::new();

    fn install_provider() {
        INIT.call_once(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("install ring provider");
        });
    }

    fn ring_provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    #[test]
    fn server_config_from_chain() {
        install_provider();
        let fx = Factory::random();
        let chain = fx.x509_chain("test", ChainSpec::new("test.example.com"));
        // Succeeds without panic = config was built with valid cert/key
        let _cfg = chain.server_config_rustls();
    }

    #[test]
    fn server_config_from_chain_with_provider() {
        install_provider();
        let fx = Factory::random();
        let chain = fx.x509_chain("test-provider", ChainSpec::new("test.example.com"));
        let _cfg = chain.server_config_rustls_with_provider(ring_provider());
    }

    #[test]
    fn client_config_from_chain() {
        install_provider();
        let fx = Factory::random();
        let chain = fx.x509_chain("test", ChainSpec::new("test.example.com"));
        let _cfg = chain.client_config_rustls();
    }

    #[test]
    fn client_config_from_chain_with_provider() {
        install_provider();
        let fx = Factory::random();
        let chain = fx.x509_chain("test-provider", ChainSpec::new("test.example.com"));
        let _cfg = chain.client_config_rustls_with_provider(ring_provider());
    }

    #[test]
    fn server_config_from_self_signed() {
        install_provider();
        let fx = Factory::random();
        let cert = fx.x509_self_signed("test", X509Spec::self_signed("test.example.com"));
        let _cfg = cert.server_config_rustls();
    }

    #[test]
    fn server_config_from_self_signed_with_provider() {
        install_provider();
        let fx = Factory::random();
        let cert = fx.x509_self_signed("test-provider", X509Spec::self_signed("test.example.com"));
        let _cfg = cert.server_config_rustls_with_provider(ring_provider());
    }

    #[test]
    fn client_config_from_self_signed() {
        install_provider();
        let fx = Factory::random();
        let cert = fx.x509_self_signed("test", X509Spec::self_signed("test.example.com"));
        let _cfg = cert.client_config_rustls();
    }

    #[test]
    fn client_config_from_self_signed_with_provider() {
        install_provider();
        let fx = Factory::random();
        let cert = fx.x509_self_signed("test-provider", X509Spec::self_signed("test.example.com"));
        let _cfg = cert.client_config_rustls_with_provider(ring_provider());
    }

    #[test]
    fn tls_handshake_roundtrip() {
        install_provider();
        let fx = Factory::random();
        let chain = fx.x509_chain("tls-test", ChainSpec::new("test.example.com"));

        let server_config = Arc::new(chain.server_config_rustls());
        let client_config = Arc::new(chain.client_config_rustls());

        let server_name: rustls::pki_types::ServerName<'_> = "test.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client =
            rustls::ClientConnection::new(client_config, server_name.to_owned()).unwrap();

        // Drive the handshake to completion by transferring bytes between
        // client and server until neither side needs to write.
        let mut buf = Vec::new();
        loop {
            let mut progress = false;

            // client -> server
            buf.clear();
            if client.wants_write() {
                client.write_tls(&mut buf).unwrap();
                if !buf.is_empty() {
                    server.read_tls(&mut &buf[..]).unwrap();
                    server.process_new_packets().unwrap();
                    progress = true;
                }
            }

            // server -> client
            buf.clear();
            if server.wants_write() {
                server.write_tls(&mut buf).unwrap();
                if !buf.is_empty() {
                    client.read_tls(&mut &buf[..]).unwrap();
                    client.process_new_packets().unwrap();
                    progress = true;
                }
            }

            if !progress {
                break;
            }
        }

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }

    #[test]
    fn mtls_with_provider_roundtrip() {
        let fx = Factory::random();
        let chain = fx.x509_chain("mtls-provider-test", ChainSpec::new("test.example.com"));

        let provider = ring_provider();
        let server_config =
            Arc::new(chain.server_config_mtls_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_mtls_rustls_with_provider(provider));

        let server_name: rustls::pki_types::ServerName<'_> = "test.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client =
            rustls::ClientConnection::new(client_config, server_name.to_owned()).unwrap();

        let mut buf = Vec::new();
        loop {
            let mut progress = false;

            buf.clear();
            if client.wants_write() {
                client.write_tls(&mut buf).unwrap();
                if !buf.is_empty() {
                    server.read_tls(&mut &buf[..]).unwrap();
                    server.process_new_packets().unwrap();
                    progress = true;
                }
            }

            buf.clear();
            if server.wants_write() {
                server.write_tls(&mut buf).unwrap();
                if !buf.is_empty() {
                    client.read_tls(&mut &buf[..]).unwrap();
                    client.process_new_packets().unwrap();
                    progress = true;
                }
            }

            if !progress {
                break;
            }
        }

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }

    #[test]
    fn mtls_roundtrip() {
        install_provider();
        let fx = Factory::random();
        let chain = fx.x509_chain("mtls-test", ChainSpec::new("test.example.com"));

        let server_config = Arc::new(chain.server_config_mtls_rustls());
        let client_config = Arc::new(chain.client_config_mtls_rustls());

        let server_name: rustls::pki_types::ServerName<'_> = "test.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client =
            rustls::ClientConnection::new(client_config, server_name.to_owned()).unwrap();

        let mut buf = Vec::new();
        loop {
            let mut progress = false;

            buf.clear();
            if client.wants_write() {
                client.write_tls(&mut buf).unwrap();
                if !buf.is_empty() {
                    server.read_tls(&mut &buf[..]).unwrap();
                    server.process_new_packets().unwrap();
                    progress = true;
                }
            }

            buf.clear();
            if server.wants_write() {
                server.write_tls(&mut buf).unwrap();
                if !buf.is_empty() {
                    client.read_tls(&mut &buf[..]).unwrap();
                    client.process_new_packets().unwrap();
                    progress = true;
                }
            }

            if !progress {
                break;
            }
        }

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }
}
