#![forbid(unsafe_code)]

//! Integration between uselesskey X.509 fixtures and `tonic` transport TLS types.
//!
//! This crate provides extension traits that convert uselesskey certificates and
//! chains into `tonic::transport::{Identity, Certificate, ServerTlsConfig, ClientTlsConfig}`.
//!
//! # Features
//!
//! - `x509` (default) - X.509 certificates and chain support
//!
//! # Example
//!
#![cfg_attr(feature = "x509", doc = "```")]
#![cfg_attr(not(feature = "x509"), doc = "```ignore")]
//! use uselesskey_core::Factory;
//! use uselesskey_x509::{ChainSpec, X509FactoryExt};
//! use uselesskey_tonic::{TonicClientTlsExt, TonicServerTlsExt};
//!
//! let fx = Factory::random();
//! let chain = fx.x509_chain("grpc-service", ChainSpec::new("test.example.com"));
//!
//! let server_tls = chain.server_tls_config_tonic();
//! let client_tls = chain.client_tls_config_tonic("test.example.com");
//! # let _ = (server_tls, client_tls);
//! ```

use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};

/// Convert uselesskey fixtures into `tonic::transport::Identity`.
#[cfg(feature = "x509")]
pub trait TonicIdentityExt {
    /// Convert the fixture to a tonic identity.
    fn identity_tonic(&self) -> Identity;
}

#[cfg(feature = "x509")]
impl TonicIdentityExt for uselesskey_x509::X509Cert {
    fn identity_tonic(&self) -> Identity {
        Identity::from_pem(self.cert_pem(), self.private_key_pkcs8_pem())
    }
}

#[cfg(feature = "x509")]
impl TonicIdentityExt for uselesskey_x509::X509Chain {
    fn identity_tonic(&self) -> Identity {
        Identity::from_pem(self.chain_pem(), self.leaf_private_key_pkcs8_pem())
    }
}

/// Build `tonic::transport::ServerTlsConfig` from uselesskey fixtures.
#[cfg(feature = "x509")]
pub trait TonicServerTlsExt {
    /// Build a server TLS config with server identity.
    fn server_tls_config_tonic(&self) -> ServerTlsConfig;
}

#[cfg(feature = "x509")]
impl TonicServerTlsExt for uselesskey_x509::X509Cert {
    fn server_tls_config_tonic(&self) -> ServerTlsConfig {
        ServerTlsConfig::new().identity(self.identity_tonic())
    }
}

#[cfg(feature = "x509")]
impl TonicServerTlsExt for uselesskey_x509::X509Chain {
    fn server_tls_config_tonic(&self) -> ServerTlsConfig {
        ServerTlsConfig::new().identity(self.identity_tonic())
    }
}

/// Build `tonic::transport::ClientTlsConfig` from uselesskey fixtures.
#[cfg(feature = "x509")]
pub trait TonicClientTlsExt {
    /// Build a client TLS config that trusts the fixture CA/cert.
    fn client_tls_config_tonic(&self, domain_name: impl Into<String>) -> ClientTlsConfig;
}

#[cfg(feature = "x509")]
impl TonicClientTlsExt for uselesskey_x509::X509Cert {
    fn client_tls_config_tonic(&self, domain_name: impl Into<String>) -> ClientTlsConfig {
        ClientTlsConfig::new()
            .domain_name(domain_name)
            .ca_certificate(Certificate::from_pem(self.cert_pem()))
    }
}

#[cfg(feature = "x509")]
impl TonicClientTlsExt for uselesskey_x509::X509Chain {
    fn client_tls_config_tonic(&self, domain_name: impl Into<String>) -> ClientTlsConfig {
        ClientTlsConfig::new()
            .domain_name(domain_name)
            .ca_certificate(Certificate::from_pem(self.root_cert_pem()))
    }
}

/// Build mutual TLS (`mTLS`) configs from X.509 chains.
#[cfg(feature = "x509")]
pub trait TonicMtlsExt {
    /// Build a server TLS config requiring client certificates trusted by the chain root.
    fn server_tls_config_mtls_tonic(&self) -> ServerTlsConfig;

    /// Build a client TLS config with a client identity and root trust.
    fn client_tls_config_mtls_tonic(&self, domain_name: impl Into<String>) -> ClientTlsConfig;
}

#[cfg(feature = "x509")]
impl TonicMtlsExt for uselesskey_x509::X509Chain {
    fn server_tls_config_mtls_tonic(&self) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(self.identity_tonic())
            .client_ca_root(Certificate::from_pem(self.root_cert_pem()))
    }

    fn client_tls_config_mtls_tonic(&self, domain_name: impl Into<String>) -> ClientTlsConfig {
        self.client_tls_config_tonic(domain_name)
            .identity(self.identity_tonic())
    }
}

#[cfg(test)]
mod tests {
    use super::{TonicClientTlsExt, TonicIdentityExt, TonicMtlsExt, TonicServerTlsExt};
    use std::sync::OnceLock;
    use uselesskey_core::{Factory, Seed};
    use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

    static FX: OnceLock<Factory> = OnceLock::new();

    fn fx() -> Factory {
        FX.get_or_init(|| {
            let seed = Seed::from_env_value("uselesskey-tonic-inline-test-seed-v1")
                .expect("test seed should always parse");
            Factory::deterministic(seed)
        })
        .clone()
    }

    #[test]
    fn self_signed_identity_and_tls_configs_build() {
        let fx = fx();
        let cert = fx.x509_self_signed("grpc-self-signed", X509Spec::self_signed("localhost"));

        let _identity = cert.identity_tonic();
        let _server = cert.server_tls_config_tonic();
        let _client = cert.client_tls_config_tonic("localhost");
    }

    #[test]
    fn chain_identity_and_tls_configs_build() {
        let fx = fx();
        let chain = fx.x509_chain("grpc-chain", ChainSpec::new("test.example.com"));

        let _identity = chain.identity_tonic();
        let _server = chain.server_tls_config_tonic();
        let _client = chain.client_tls_config_tonic("test.example.com");
    }

    #[test]
    fn chain_mtls_configs_build() {
        let fx = fx();
        let chain = fx.x509_chain("grpc-mtls", ChainSpec::new("test.example.com"));

        let _server = chain.server_tls_config_mtls_tonic();
        let _client = chain.client_tls_config_mtls_tonic("test.example.com");
    }

    #[test]
    fn deterministic_chain_material_stays_stable() {
        let seed = Seed::from_env_value("grpc-tonic-stability").expect("seed");
        let fx = Factory::deterministic(seed);

        let a = fx.x509_chain("stable", ChainSpec::new("det.example.com"));
        fx.clear_cache();
        let b = fx.x509_chain("stable", ChainSpec::new("det.example.com"));

        assert_eq!(a.chain_pem(), b.chain_pem());
        assert_eq!(a.root_cert_pem(), b.root_cert_pem());
        assert_eq!(
            a.leaf_private_key_pkcs8_pem(),
            b.leaf_private_key_pkcs8_pem()
        );
    }
}
