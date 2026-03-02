//! Insta snapshot tests for uselesskey-tonic adapter.
//!
//! These tests snapshot TLS configuration metadata produced by deterministic
//! X.509 fixtures to detect unintended changes in adapter output.
//! CRITICAL: No actual key bytes appear in snapshots — all crypto material is redacted.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_tonic::{TonicClientTlsExt, TonicIdentityExt, TonicMtlsExt, TonicServerTlsExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

// =========================================================================
// Self-signed certificate snapshots
// =========================================================================

mod self_signed_snapshots {
    use super::*;

    #[derive(Serialize)]
    struct SelfSignedTlsSnapshot {
        domain: &'static str,
        cert_pem_lines: usize,
        cert_pem_has_begin: bool,
        cert_pem_has_end: bool,
        private_key_pem_has_begin: bool,
        private_key_pem_has_end: bool,
        cert_der_len: usize,
        private_key_der_len: usize,
        cert_pem: String,
        private_key_pem: String,
    }

    #[test]
    fn snapshot_self_signed_tls_metadata() {
        let fx = fx();
        let cert = fx.x509_self_signed("snapshot-ss", X509Spec::self_signed("localhost"));

        let cert_pem = cert.cert_pem().to_string();
        let key_pem = cert.private_key_pkcs8_pem().to_string();

        let result = SelfSignedTlsSnapshot {
            domain: "localhost",
            cert_pem_lines: cert_pem.lines().count(),
            cert_pem_has_begin: cert_pem.contains("-----BEGIN CERTIFICATE-----"),
            cert_pem_has_end: cert_pem.contains("-----END CERTIFICATE-----"),
            private_key_pem_has_begin: key_pem.contains("-----BEGIN PRIVATE KEY-----"),
            private_key_pem_has_end: key_pem.contains("-----END PRIVATE KEY-----"),
            cert_der_len: cert.cert_der().len(),
            private_key_der_len: cert.private_key_pkcs8_der().len(),
            cert_pem,
            private_key_pem: key_pem,
        };

        insta::assert_yaml_snapshot!("tonic_self_signed_tls_metadata", result, {
            ".cert_pem" => "[REDACTED]",
            ".private_key_pem" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_self_signed_identity_builds() {
        let fx = fx();
        let cert = fx.x509_self_signed("snapshot-ss-id", X509Spec::self_signed("localhost"));

        // Identity creation is infallible — snapshot that it succeeds with metadata
        let _identity = cert.identity_tonic();

        #[derive(Serialize)]
        struct IdentityBuildResult {
            domain: &'static str,
            identity_built: bool,
            server_tls_built: bool,
            client_tls_built: bool,
        }

        let _server = cert.server_tls_config_tonic();
        let _client = cert.client_tls_config_tonic("localhost");

        let result = IdentityBuildResult {
            domain: "localhost",
            identity_built: true,
            server_tls_built: true,
            client_tls_built: true,
        };

        insta::assert_yaml_snapshot!("tonic_self_signed_identity_builds", result);
    }

    #[test]
    fn snapshot_self_signed_custom_domain() {
        let fx = fx();
        let cert = fx.x509_self_signed(
            "snapshot-ss-custom",
            X509Spec::self_signed("api.example.com"),
        );

        #[derive(Serialize)]
        struct CustomDomainSnapshot {
            domain: &'static str,
            cert_pem_has_begin: bool,
            cert_pem_has_end: bool,
            cert_der_len: usize,
            private_key_der_len: usize,
            identity_built: bool,
        }

        let cert_pem = cert.cert_pem().to_string();
        let _identity = cert.identity_tonic();

        let result = CustomDomainSnapshot {
            domain: "api.example.com",
            cert_pem_has_begin: cert_pem.contains("-----BEGIN CERTIFICATE-----"),
            cert_pem_has_end: cert_pem.contains("-----END CERTIFICATE-----"),
            cert_der_len: cert.cert_der().len(),
            private_key_der_len: cert.private_key_pkcs8_der().len(),
            identity_built: true,
        };

        insta::assert_yaml_snapshot!("tonic_self_signed_custom_domain", result);
    }
}

// =========================================================================
// Chain certificate snapshots
// =========================================================================

mod chain_snapshots {
    use super::*;

    #[derive(Serialize)]
    struct ChainTlsSnapshot {
        domain: &'static str,
        chain_pem_cert_count: usize,
        full_chain_pem_cert_count: usize,
        root_cert_pem_cert_count: usize,
        leaf_cert_pem_cert_count: usize,
        root_cert_der_len: usize,
        intermediate_cert_der_len: usize,
        leaf_cert_der_len: usize,
        leaf_private_key_der_len: usize,
        chain_pem: String,
        root_cert_pem: String,
        leaf_private_key_pem: String,
    }

    #[test]
    fn snapshot_chain_tls_metadata() {
        let fx = fx();
        let chain = fx.x509_chain("snapshot-chain", ChainSpec::new("test.example.com"));

        let chain_pem = chain.chain_pem().to_string();
        let full_chain_pem = chain.full_chain_pem();
        let root_pem = chain.root_cert_pem().to_string();
        let leaf_pem = chain.leaf_cert_pem();
        let key_pem = chain.leaf_private_key_pkcs8_pem().to_string();

        let result = ChainTlsSnapshot {
            domain: "test.example.com",
            chain_pem_cert_count: chain_pem.matches("-----BEGIN CERTIFICATE-----").count(),
            full_chain_pem_cert_count: full_chain_pem
                .matches("-----BEGIN CERTIFICATE-----")
                .count(),
            root_cert_pem_cert_count: root_pem.matches("-----BEGIN CERTIFICATE-----").count(),
            leaf_cert_pem_cert_count: leaf_pem.matches("-----BEGIN CERTIFICATE-----").count(),
            root_cert_der_len: chain.root_cert_der().len(),
            intermediate_cert_der_len: chain.intermediate_cert_der().len(),
            leaf_cert_der_len: chain.leaf_cert_der().len(),
            leaf_private_key_der_len: chain.leaf_private_key_pkcs8_der().len(),
            chain_pem,
            root_cert_pem: root_pem,
            leaf_private_key_pem: key_pem,
        };

        insta::assert_yaml_snapshot!("tonic_chain_tls_metadata", result, {
            ".chain_pem" => "[REDACTED]",
            ".root_cert_pem" => "[REDACTED]",
            ".leaf_private_key_pem" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_chain_all_configs_build() {
        let fx = fx();
        let chain = fx.x509_chain("snapshot-chain-cfg", ChainSpec::new("grpc.example.com"));

        let _identity = chain.identity_tonic();
        let _server = chain.server_tls_config_tonic();
        let _client = chain.client_tls_config_tonic("grpc.example.com");

        #[derive(Serialize)]
        struct ChainConfigResult {
            domain: &'static str,
            identity_built: bool,
            server_tls_built: bool,
            client_tls_built: bool,
        }

        let result = ChainConfigResult {
            domain: "grpc.example.com",
            identity_built: true,
            server_tls_built: true,
            client_tls_built: true,
        };

        insta::assert_yaml_snapshot!("tonic_chain_all_configs_build", result);
    }

    #[test]
    fn snapshot_chain_custom_domain_metadata() {
        let fx = fx();
        let chain = fx.x509_chain("snapshot-chain-custom", ChainSpec::new("rpc.custom.io"));

        let chain_pem = chain.chain_pem().to_string();

        #[derive(Serialize)]
        struct CustomChainInfo {
            domain: &'static str,
            chain_pem_cert_count: usize,
            root_cert_der_len: usize,
            intermediate_cert_der_len: usize,
            leaf_cert_der_len: usize,
            leaf_private_key_der_len: usize,
        }

        let result = CustomChainInfo {
            domain: "rpc.custom.io",
            chain_pem_cert_count: chain_pem.matches("-----BEGIN CERTIFICATE-----").count(),
            root_cert_der_len: chain.root_cert_der().len(),
            intermediate_cert_der_len: chain.intermediate_cert_der().len(),
            leaf_cert_der_len: chain.leaf_cert_der().len(),
            leaf_private_key_der_len: chain.leaf_private_key_pkcs8_der().len(),
        };

        insta::assert_yaml_snapshot!("tonic_chain_custom_domain_metadata", result);
    }
}

// =========================================================================
// mTLS snapshots
// =========================================================================

mod mtls_snapshots {
    use super::*;

    #[test]
    fn snapshot_mtls_configs_build() {
        let fx = fx();
        let chain = fx.x509_chain("snapshot-mtls", ChainSpec::new("mtls.example.com"));

        let _server = chain.server_tls_config_mtls_tonic();
        let _client = chain.client_tls_config_mtls_tonic("mtls.example.com");

        #[derive(Serialize)]
        struct MtlsConfigResult {
            domain: &'static str,
            server_mtls_built: bool,
            client_mtls_built: bool,
            chain_pem_cert_count: usize,
            root_cert_der_len: usize,
        }

        let result = MtlsConfigResult {
            domain: "mtls.example.com",
            server_mtls_built: true,
            client_mtls_built: true,
            chain_pem_cert_count: chain
                .chain_pem()
                .matches("-----BEGIN CERTIFICATE-----")
                .count(),
            root_cert_der_len: chain.root_cert_der().len(),
        };

        insta::assert_yaml_snapshot!("tonic_mtls_configs_build", result);
    }

    #[test]
    fn snapshot_mtls_chain_cert_details() {
        let fx = fx();
        let chain = fx.x509_chain(
            "snapshot-mtls-details",
            ChainSpec::new("secure.example.com"),
        );

        let _server = chain.server_tls_config_mtls_tonic();
        let _client = chain.client_tls_config_mtls_tonic("secure.example.com");

        #[derive(Serialize)]
        struct MtlsCertDetails {
            domain: &'static str,
            root_cert_der_len: usize,
            intermediate_cert_der_len: usize,
            leaf_cert_der_len: usize,
            leaf_private_key_der_len: usize,
            full_chain_pem_cert_count: usize,
            server_mtls_built: bool,
            client_mtls_built: bool,
        }

        let full_chain_pem = chain.full_chain_pem();

        let result = MtlsCertDetails {
            domain: "secure.example.com",
            root_cert_der_len: chain.root_cert_der().len(),
            intermediate_cert_der_len: chain.intermediate_cert_der().len(),
            leaf_cert_der_len: chain.leaf_cert_der().len(),
            leaf_private_key_der_len: chain.leaf_private_key_pkcs8_der().len(),
            full_chain_pem_cert_count: full_chain_pem
                .matches("-----BEGIN CERTIFICATE-----")
                .count(),
            server_mtls_built: true,
            client_mtls_built: true,
        };

        insta::assert_yaml_snapshot!("tonic_mtls_chain_cert_details", result);
    }
}

// =========================================================================
// RSA key size snapshots
// =========================================================================

mod key_size_snapshots {
    use super::*;

    #[test]
    fn snapshot_chain_key_sizes() {
        let fx = fx();

        #[derive(Serialize)]
        struct KeySizeInfo {
            rsa_bits: usize,
            leaf_cert_der_len: usize,
            leaf_private_key_der_len: usize,
            root_cert_der_len: usize,
        }

        let cases: Vec<KeySizeInfo> = [2048, 4096]
            .into_iter()
            .map(|bits| {
                let chain = fx.x509_chain(
                    format!("snapshot-bits-{bits}"),
                    ChainSpec::new(format!("bits{bits}.example.com")).with_rsa_bits(bits),
                );
                KeySizeInfo {
                    rsa_bits: bits,
                    leaf_cert_der_len: chain.leaf_cert_der().len(),
                    leaf_private_key_der_len: chain.leaf_private_key_pkcs8_der().len(),
                    root_cert_der_len: chain.root_cert_der().len(),
                }
            })
            .collect();

        insta::assert_yaml_snapshot!("tonic_chain_key_sizes", cases);
    }
}
