//! Insta snapshot tests for uselesskey-tonic adapter.
//!
//! These tests snapshot metadata about tonic TLS config conversions
//! produced by deterministic keys to detect unintended changes.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_tonic::{TonicClientTlsExt, TonicIdentityExt, TonicMtlsExt, TonicServerTlsExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

// =========================================================================
// Self-signed cert snapshots
// =========================================================================

mod self_signed_snapshots {
    use super::*;

    #[derive(Serialize)]
    struct SelfSignedMeta {
        description: &'static str,
        cert_pem_starts_with: String,
        key_pem_starts_with: String,
        cert_der_len: usize,
        private_key_der_len: usize,
    }

    #[test]
    fn snapshot_tonic_self_signed_cert() {
        let fx = fx();
        let cert = fx.x509_self_signed(
            "snap-self-signed",
            X509Spec::self_signed("test.example.com"),
        );

        let meta = SelfSignedMeta {
            description: "Self-signed X.509 cert for tonic",
            cert_pem_starts_with: cert.cert_pem()[..27].to_string(),
            key_pem_starts_with: cert.private_key_pkcs8_pem()[..27].to_string(),
            cert_der_len: cert.cert_der().len(),
            private_key_der_len: cert.private_key_pkcs8_der().len(),
        };

        insta::assert_yaml_snapshot!("tonic_self_signed_cert", meta);
    }

    #[test]
    fn snapshot_tonic_self_signed_identity() {
        let fx = fx();
        let cert = fx.x509_self_signed(
            "snap-ss-identity",
            X509Spec::self_signed("test.example.com"),
        );

        // identity_tonic() should not panic
        let _identity = cert.identity_tonic();

        #[derive(Serialize)]
        struct IdentityMeta {
            description: &'static str,
            conversion_ok: bool,
        }

        let meta = IdentityMeta {
            description: "Self-signed identity conversion",
            conversion_ok: true,
        };

        insta::assert_yaml_snapshot!("tonic_self_signed_identity", meta);
    }
}

// =========================================================================
// Certificate chain snapshots
// =========================================================================

mod chain_snapshots {
    use super::*;

    #[derive(Serialize)]
    struct ChainMeta {
        description: &'static str,
        root_cert_der_len: usize,
        leaf_cert_der_len: usize,
        leaf_private_key_der_len: usize,
        chain_pem_cert_count: usize,
        full_chain_pem_cert_count: usize,
    }

    #[test]
    fn snapshot_tonic_chain_cert() {
        let fx = fx();
        let chain = fx.x509_chain("snap-chain", ChainSpec::new("test.example.com"));

        let chain_pem_count = chain
            .chain_pem()
            .matches("-----BEGIN CERTIFICATE-----")
            .count();
        let full_chain_pem_count = chain
            .full_chain_pem()
            .matches("-----BEGIN CERTIFICATE-----")
            .count();

        let meta = ChainMeta {
            description: "X.509 chain for tonic (leaf + intermediate + root)",
            root_cert_der_len: chain.root_cert_der().len(),
            leaf_cert_der_len: chain.leaf_cert_der().len(),
            leaf_private_key_der_len: chain.leaf_private_key_pkcs8_der().len(),
            chain_pem_cert_count: chain_pem_count,
            full_chain_pem_cert_count: full_chain_pem_count,
        };

        insta::assert_yaml_snapshot!("tonic_chain_cert", meta);
    }

    #[test]
    fn snapshot_tonic_chain_tls_configs() {
        let fx = fx();
        let chain = fx.x509_chain("snap-chain-tls", ChainSpec::new("test.example.com"));

        let _identity = chain.identity_tonic();
        let _server = chain.server_tls_config_tonic();
        let _client = chain.client_tls_config_tonic("test.example.com");

        #[derive(Serialize)]
        struct TlsConfigMeta {
            description: &'static str,
            identity_ok: bool,
            server_tls_ok: bool,
            client_tls_ok: bool,
        }

        let meta = TlsConfigMeta {
            description: "Chain TLS config conversions",
            identity_ok: true,
            server_tls_ok: true,
            client_tls_ok: true,
        };

        insta::assert_yaml_snapshot!("tonic_chain_tls_configs", meta);
    }
}

// =========================================================================
// mTLS snapshots
// =========================================================================

mod mtls_snapshots {
    use super::*;

    #[derive(Serialize)]
    struct MtlsMeta {
        description: &'static str,
        server_mtls_ok: bool,
        client_mtls_ok: bool,
    }

    #[test]
    fn snapshot_tonic_mtls_configs() {
        let fx = fx();
        let chain = fx.x509_chain("snap-mtls", ChainSpec::new("test.example.com"));

        let _server = chain.server_tls_config_mtls_tonic();
        let _client = chain.client_tls_config_mtls_tonic("test.example.com");

        let meta = MtlsMeta {
            description: "mTLS config conversions",
            server_mtls_ok: true,
            client_mtls_ok: true,
        };

        insta::assert_yaml_snapshot!("tonic_mtls_configs", meta);
    }
}

// =========================================================================
// Determinism snapshots
// =========================================================================

mod determinism_snapshots {
    use super::*;

    #[derive(Serialize)]
    struct Determinism {
        description: &'static str,
        same_cert_pem: bool,
        same_private_key_pem: bool,
        cert_der_len: usize,
    }

    #[test]
    fn snapshot_tonic_self_signed_determinism() {
        let fx = fx();
        let spec = X509Spec::self_signed("det.example.com");

        let cert1 = fx.x509_self_signed("snap-det-ss", spec.clone());
        let cert2 = fx.x509_self_signed("snap-det-ss", spec);

        let result = Determinism {
            description: "Self-signed cert determinism",
            same_cert_pem: cert1.cert_pem() == cert2.cert_pem(),
            same_private_key_pem: cert1.private_key_pkcs8_pem() == cert2.private_key_pkcs8_pem(),
            cert_der_len: cert1.cert_der().len(),
        };

        insta::assert_yaml_snapshot!("tonic_self_signed_determinism", result);
    }

    #[test]
    fn snapshot_tonic_chain_determinism() {
        let fx = fx();
        let spec = ChainSpec::new("det-chain.example.com");

        let chain1 = fx.x509_chain("snap-det-chain", spec.clone());
        let chain2 = fx.x509_chain("snap-det-chain", spec);

        #[derive(Serialize)]
        struct ChainDeterminism {
            description: &'static str,
            same_chain_pem: bool,
            same_root_cert: bool,
            same_leaf_cert: bool,
            same_leaf_key: bool,
            leaf_cert_der_len: usize,
        }

        let result = ChainDeterminism {
            description: "Chain determinism",
            same_chain_pem: chain1.chain_pem() == chain2.chain_pem(),
            same_root_cert: chain1.root_cert_pem() == chain2.root_cert_pem(),
            same_leaf_cert: chain1.leaf_cert_pem() == chain2.leaf_cert_pem(),
            same_leaf_key: chain1.leaf_private_key_pkcs8_pem()
                == chain2.leaf_private_key_pkcs8_pem(),
            leaf_cert_der_len: chain1.leaf_cert_der().len(),
        };

        insta::assert_yaml_snapshot!("tonic_chain_determinism", result);
    }
}

// =========================================================================
// Debug safety snapshots
// =========================================================================

#[derive(Serialize)]
struct DebugSafety {
    contains_struct_name: bool,
    contains_label: bool,
    contains_private_key_marker: bool,
    contains_certificate_marker: bool,
    uses_non_exhaustive: bool,
}

#[test]
fn snapshot_debug_safety_self_signed() {
    let fx = fx();
    let cert = fx.x509_self_signed("snap-debug-ss", X509Spec::self_signed("debug.example.com"));
    let dbg = format!("{cert:?}");

    let result = DebugSafety {
        contains_struct_name: dbg.contains("X509Cert"),
        contains_label: dbg.contains("snap-debug-ss"),
        contains_private_key_marker: dbg.contains("BEGIN PRIVATE KEY"),
        contains_certificate_marker: dbg.contains("BEGIN CERTIFICATE"),
        uses_non_exhaustive: dbg.contains(".."),
    };

    insta::assert_yaml_snapshot!("tonic_debug_safety_self_signed", result);
}

#[test]
fn snapshot_debug_safety_chain() {
    let fx = fx();
    let chain = fx.x509_chain("snap-debug-chain", ChainSpec::new("debug.example.com"));
    let dbg = format!("{chain:?}");

    let result = DebugSafety {
        contains_struct_name: dbg.contains("X509Chain"),
        contains_label: dbg.contains("snap-debug-chain"),
        contains_private_key_marker: dbg.contains("BEGIN PRIVATE KEY"),
        contains_certificate_marker: dbg.contains("BEGIN CERTIFICATE"),
        uses_non_exhaustive: dbg.contains(".."),
    };

    insta::assert_yaml_snapshot!("tonic_debug_safety_chain", result);
}

// =========================================================================
// Adapter summary snapshot
// =========================================================================

#[test]
fn snapshot_tonic_adapter_summary() {
    let fx = fx();

    let ss = fx.x509_self_signed("snap-summary-ss", X509Spec::self_signed("test.example.com"));
    let chain = fx.x509_chain("snap-summary-chain", ChainSpec::new("test.example.com"));

    #[derive(Serialize)]
    struct AdapterEntry {
        fixture_type: &'static str,
        identity_ok: bool,
        server_tls_ok: bool,
        client_tls_ok: bool,
        cert_der_len: usize,
    }

    let items: Vec<AdapterEntry> = vec![
        AdapterEntry {
            fixture_type: "X509Cert (self-signed)",
            identity_ok: true,
            server_tls_ok: true,
            client_tls_ok: true,
            cert_der_len: ss.cert_der().len(),
        },
        AdapterEntry {
            fixture_type: "X509Chain",
            identity_ok: true,
            server_tls_ok: true,
            client_tls_ok: true,
            cert_der_len: chain.leaf_cert_der().len(),
        },
    ];

    // Verify all conversions succeed
    let _ = ss.identity_tonic();
    let _ = ss.server_tls_config_tonic();
    let _ = ss.client_tls_config_tonic("test.example.com");
    let _ = chain.identity_tonic();
    let _ = chain.server_tls_config_tonic();
    let _ = chain.client_tls_config_tonic("test.example.com");
    let _ = chain.server_tls_config_mtls_tonic();
    let _ = chain.client_tls_config_mtls_tonic("test.example.com");

    insta::assert_yaml_snapshot!("tonic_adapter_summary", items);
}
