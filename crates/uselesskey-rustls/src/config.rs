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
    use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

    use std::sync::Once;
    static INIT: Once = Once::new();

    fn install_provider() {
        INIT.call_once(|| {
            // When both `rustls-ring` and `rustls-aws-lc-rs` features are
            // enabled (e.g. via `--all-features`), another provider may
            // already be set as process-default. Ignore the error — the
            // explicit-provider tests cover the critical paths.
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn ring_provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    // Maximum iterations for TLS handshake loops to prevent infinite loops
    // A normal TLS handshake completes in well under 10 iterations
    const MAX_HANDSHAKE_ITERATIONS: usize = 10;

    #[test]
    fn server_config_from_chain() {
        install_provider();
        let fx = super::super::testutil::fx();
        let chain = fx.x509_chain("test", ChainSpec::new("test.example.com"));
        // Succeeds without panic = config was built with valid cert/key
        let _cfg = chain.server_config_rustls();
    }

    #[test]
    fn server_config_from_chain_with_provider() {
        install_provider();
        let fx = super::super::testutil::fx();
        let chain = fx.x509_chain("test-provider", ChainSpec::new("test.example.com"));
        let _cfg = chain.server_config_rustls_with_provider(ring_provider());
    }

    #[test]
    fn client_config_from_chain() {
        install_provider();
        let fx = super::super::testutil::fx();
        let chain = fx.x509_chain("test", ChainSpec::new("test.example.com"));
        let _cfg = chain.client_config_rustls();
    }

    #[test]
    fn client_config_from_chain_with_provider() {
        install_provider();
        let fx = super::super::testutil::fx();
        let chain = fx.x509_chain("test-provider", ChainSpec::new("test.example.com"));
        let _cfg = chain.client_config_rustls_with_provider(ring_provider());
    }

    #[test]
    fn server_config_from_self_signed() {
        install_provider();
        let fx = super::super::testutil::fx();
        let cert = fx.x509_self_signed("test", X509Spec::self_signed("test.example.com"));
        let _cfg = cert.server_config_rustls();
    }

    #[test]
    fn server_config_from_self_signed_with_provider() {
        install_provider();
        let fx = super::super::testutil::fx();
        let cert = fx.x509_self_signed("test-provider", X509Spec::self_signed("test.example.com"));
        let _cfg = cert.server_config_rustls_with_provider(ring_provider());
    }

    #[test]
    fn client_config_from_self_signed() {
        install_provider();
        let fx = super::super::testutil::fx();
        let cert = fx.x509_self_signed("test", X509Spec::self_signed("test.example.com"));
        let _cfg = cert.client_config_rustls();
    }

    #[test]
    fn client_config_from_self_signed_with_provider() {
        install_provider();
        let fx = super::super::testutil::fx();
        let cert = fx.x509_self_signed("test-provider", X509Spec::self_signed("test.example.com"));
        let _cfg = cert.client_config_rustls_with_provider(ring_provider());
    }

    #[test]
    fn tls_handshake_roundtrip() {
        let fx = super::super::testutil::fx();
        let chain = fx.x509_chain("tls-test", ChainSpec::new("test.example.com"));

        let provider = ring_provider();
        let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

        let server_name: rustls::pki_types::ServerName<'_> = "test.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client =
            rustls::ClientConnection::new(client_config, server_name.to_owned()).unwrap();

        // Drive the handshake to completion by transferring bytes between
        // client and server until neither side needs to write.
        let mut buf = Vec::new();
        for iteration in 0..MAX_HANDSHAKE_ITERATIONS {
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

            // Safety check: if we've exhausted iterations without completing,
            // something is wrong with the handshake state machine
            assert!(
                iteration < MAX_HANDSHAKE_ITERATIONS - 1,
                "TLS handshake did not complete within {} iterations",
                MAX_HANDSHAKE_ITERATIONS
            );
        }

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }

    #[test]
    fn mtls_with_provider_roundtrip() {
        let fx = super::super::testutil::fx();
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
        for iteration in 0..MAX_HANDSHAKE_ITERATIONS {
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

            // Safety check: if we've exhausted iterations without completing,
            // something is wrong with the handshake state machine
            assert!(
                iteration < MAX_HANDSHAKE_ITERATIONS - 1,
                "mTLS handshake did not complete within {} iterations",
                MAX_HANDSHAKE_ITERATIONS
            );
        }

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }

    // -----------------------------------------------------------------
    // Default-provider mTLS coverage (no-panic-helper style).
    //
    // The non-mTLS default-provider variants (`server_config_rustls`,
    // `client_config_rustls`) are covered above, but the default-provider
    // mTLS variants (`server_config_mtls_rustls`,
    // `client_config_mtls_rustls`) were previously only exercised
    // indirectly through cross-crate integration tests. These tests pin
    // those code paths directly and use the `uselesskey-test-support`
    // no-panic helpers so future migration work need not revisit them.
    // -----------------------------------------------------------------

    use uselesskey_test_support::{TestResult, ensure, require_ok};

    #[test]
    fn server_config_mtls_from_chain_default_provider() -> TestResult<()> {
        install_provider();
        let fx = super::super::testutil::fx();
        let chain = fx.x509_chain("mtls-default-server", ChainSpec::new("test.example.com"));

        // Building the config exercises the default-provider mTLS path
        // including WebPkiClientVerifier::builder. A failure here would
        // panic on the internal `.expect("valid mTLS server config")`.
        let cfg = chain.server_config_mtls_rustls();

        // Sanity-check defaults that the builder leaves untouched, to
        // ensure we're observing a real ServerConfig and not just that
        // construction didn't panic.
        ensure!(
            cfg.alpn_protocols.is_empty(),
            "default ServerConfig must have no ALPN protocols configured",
        );
        Ok(())
    }

    #[test]
    fn client_config_mtls_from_chain_default_provider() -> TestResult<()> {
        install_provider();
        let fx = super::super::testutil::fx();
        let chain = fx.x509_chain("mtls-default-client", ChainSpec::new("test.example.com"));

        let cfg = chain.client_config_mtls_rustls();

        ensure!(
            cfg.alpn_protocols.is_empty(),
            "default ClientConfig must have no ALPN protocols configured",
        );
        Ok(())
    }

    #[test]
    fn mtls_default_provider_pair_completes_handshake() -> TestResult<()> {
        install_provider();
        let fx = super::super::testutil::fx();
        let chain = fx.x509_chain("mtls-default-handshake", ChainSpec::new("test.example.com"));

        let server_config = Arc::new(chain.server_config_mtls_rustls());
        let client_config = Arc::new(chain.client_config_mtls_rustls());

        let server_name: rustls::pki_types::ServerName<'_> = require_ok(
            "test.example.com".try_into(),
            "test.example.com must parse as ServerName",
        )?;
        let mut server = require_ok(
            rustls::ServerConnection::new(server_config),
            "ServerConnection::new",
        )?;
        let mut client = require_ok(
            rustls::ClientConnection::new(client_config, server_name.to_owned()),
            "ClientConnection::new",
        )?;

        let mut buf = Vec::new();
        for iteration in 0..MAX_HANDSHAKE_ITERATIONS {
            let mut progress = false;

            buf.clear();
            if client.wants_write() {
                require_ok(client.write_tls(&mut buf), "client.write_tls")?;
                if !buf.is_empty() {
                    require_ok(server.read_tls(&mut &buf[..]), "server.read_tls")?;
                    require_ok(server.process_new_packets(), "server.process_new_packets")?;
                    progress = true;
                }
            }

            buf.clear();
            if server.wants_write() {
                require_ok(server.write_tls(&mut buf), "server.write_tls")?;
                if !buf.is_empty() {
                    require_ok(client.read_tls(&mut &buf[..]), "client.read_tls")?;
                    require_ok(client.process_new_packets(), "client.process_new_packets")?;
                    progress = true;
                }
            }

            if !progress {
                break;
            }

            ensure!(
                iteration < MAX_HANDSHAKE_ITERATIONS - 1,
                "default-provider mTLS handshake did not complete within {} iterations",
                MAX_HANDSHAKE_ITERATIONS,
            );
        }

        ensure!(!client.is_handshaking(), "client must finish handshaking");
        ensure!(!server.is_handshaking(), "server must finish handshaking");
        Ok(())
    }

    #[test]
    fn mtls_roundtrip() {
        let fx = super::super::testutil::fx();
        let chain = fx.x509_chain("mtls-test", ChainSpec::new("test.example.com"));

        let provider = ring_provider();
        let server_config =
            Arc::new(chain.server_config_mtls_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_mtls_rustls_with_provider(provider));

        let server_name: rustls::pki_types::ServerName<'_> = "test.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client =
            rustls::ClientConnection::new(client_config, server_name.to_owned()).unwrap();

        let mut buf = Vec::new();
        for iteration in 0..MAX_HANDSHAKE_ITERATIONS {
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

            // Safety check: if we've exhausted iterations without completing,
            // something is wrong with the handshake state machine
            assert!(
                iteration < MAX_HANDSHAKE_ITERATIONS - 1,
                "mTLS handshake did not complete within {} iterations",
                MAX_HANDSHAKE_ITERATIONS
            );
        }

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }
}
