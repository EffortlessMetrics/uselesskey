//! Integration tests for uselesskey-tonic adapter.
//!
//! These tests verify basic TLS config creation, certificate chain handling,
//! determinism, and debug safety for the tonic transport adapters.

mod testutil;

use testutil::fx;
use uselesskey_core::{Factory, Seed};
use uselesskey_tonic::{TonicClientTlsExt, TonicIdentityExt, TonicMtlsExt, TonicServerTlsExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

// =========================================================================
// Basic TLS config creation — self-signed
// =========================================================================

#[test]
fn self_signed_identity_creates_successfully() {
    let fx = fx();
    let cert = fx.x509_self_signed("int-ss-identity", X509Spec::self_signed("localhost"));
    let _identity = cert.identity_tonic();
}

#[test]
fn self_signed_server_tls_config_creates_successfully() {
    let fx = fx();
    let cert = fx.x509_self_signed("int-ss-server", X509Spec::self_signed("localhost"));
    let _server = cert.server_tls_config_tonic();
}

#[test]
fn self_signed_client_tls_config_creates_successfully() {
    let fx = fx();
    let cert = fx.x509_self_signed("int-ss-client", X509Spec::self_signed("localhost"));
    let _client = cert.client_tls_config_tonic("localhost");
}

#[test]
fn self_signed_all_configs_from_same_cert() {
    let fx = fx();
    let cert = fx.x509_self_signed("int-ss-all", X509Spec::self_signed("test.example.com"));

    let _identity = cert.identity_tonic();
    let _server = cert.server_tls_config_tonic();
    let _client = cert.client_tls_config_tonic("test.example.com");
}

// =========================================================================
// Basic TLS config creation — certificate chain
// =========================================================================

#[test]
fn chain_identity_creates_successfully() {
    let fx = fx();
    let chain = fx.x509_chain("int-chain-identity", ChainSpec::new("chain.example.com"));
    let _identity = chain.identity_tonic();
}

#[test]
fn chain_server_tls_config_creates_successfully() {
    let fx = fx();
    let chain = fx.x509_chain("int-chain-server", ChainSpec::new("chain.example.com"));
    let _server = chain.server_tls_config_tonic();
}

#[test]
fn chain_client_tls_config_creates_successfully() {
    let fx = fx();
    let chain = fx.x509_chain("int-chain-client", ChainSpec::new("chain.example.com"));
    let _client = chain.client_tls_config_tonic("chain.example.com");
}

#[test]
fn chain_all_configs_from_same_chain() {
    let fx = fx();
    let chain = fx.x509_chain("int-chain-all", ChainSpec::new("chain.example.com"));

    let _identity = chain.identity_tonic();
    let _server = chain.server_tls_config_tonic();
    let _client = chain.client_tls_config_tonic("chain.example.com");
}

// =========================================================================
// mTLS config creation
// =========================================================================

#[test]
fn chain_mtls_server_config_creates_successfully() {
    let fx = fx();
    let chain = fx.x509_chain("int-mtls-server", ChainSpec::new("mtls.example.com"));
    let _server = chain.server_tls_config_mtls_tonic();
}

#[test]
fn chain_mtls_client_config_creates_successfully() {
    let fx = fx();
    let chain = fx.x509_chain("int-mtls-client", ChainSpec::new("mtls.example.com"));
    let _client = chain.client_tls_config_mtls_tonic("mtls.example.com");
}

#[test]
fn chain_mtls_both_configs_from_same_chain() {
    let fx = fx();
    let chain = fx.x509_chain("int-mtls-both", ChainSpec::new("mtls.example.com"));

    let _server = chain.server_tls_config_mtls_tonic();
    let _client = chain.client_tls_config_mtls_tonic("mtls.example.com");
}

// =========================================================================
// Certificate chain handling
// =========================================================================

#[test]
fn chain_pem_contains_two_certificates() {
    let fx = fx();
    let chain = fx.x509_chain("int-chain-count", ChainSpec::new("chain.example.com"));
    let cert_count = chain
        .chain_pem()
        .matches("-----BEGIN CERTIFICATE-----")
        .count();
    assert_eq!(
        cert_count, 2,
        "chain_pem should contain leaf + intermediate"
    );
}

#[test]
fn full_chain_pem_contains_three_certificates() {
    let fx = fx();
    let chain = fx.x509_chain("int-full-chain", ChainSpec::new("chain.example.com"));
    let cert_count = chain
        .full_chain_pem()
        .matches("-----BEGIN CERTIFICATE-----")
        .count();
    assert_eq!(
        cert_count, 3,
        "full_chain_pem should contain leaf + intermediate + root"
    );
}

#[test]
fn chain_root_cert_is_valid_pem() {
    let fx = fx();
    let chain = fx.x509_chain("int-root-pem", ChainSpec::new("chain.example.com"));
    assert!(
        chain
            .root_cert_pem()
            .starts_with("-----BEGIN CERTIFICATE-----"),
        "Root cert PEM should start with BEGIN CERTIFICATE"
    );
}

#[test]
fn chain_leaf_cert_is_valid_pem() {
    let fx = fx();
    let chain = fx.x509_chain("int-leaf-pem", ChainSpec::new("chain.example.com"));
    assert!(
        chain
            .leaf_cert_pem()
            .starts_with("-----BEGIN CERTIFICATE-----"),
        "Leaf cert PEM should start with BEGIN CERTIFICATE"
    );
}

#[test]
fn chain_leaf_private_key_is_valid_pem() {
    let fx = fx();
    let chain = fx.x509_chain("int-leaf-key", ChainSpec::new("chain.example.com"));
    assert!(
        chain
            .leaf_private_key_pkcs8_pem()
            .starts_with("-----BEGIN PRIVATE KEY-----"),
        "Leaf private key PEM should start with BEGIN PRIVATE KEY"
    );
}

#[test]
fn chain_der_outputs_are_nonempty() {
    let fx = fx();
    let chain = fx.x509_chain("int-der-nonempty", ChainSpec::new("chain.example.com"));
    assert!(
        !chain.root_cert_der().is_empty(),
        "Root DER should be non-empty"
    );
    assert!(
        !chain.leaf_cert_der().is_empty(),
        "Leaf DER should be non-empty"
    );
    assert!(
        !chain.leaf_private_key_pkcs8_der().is_empty(),
        "Leaf key DER should be non-empty"
    );
}

#[test]
fn self_signed_cert_has_valid_pem_format() {
    let fx = fx();
    let cert = fx.x509_self_signed("int-ss-pem-fmt", X509Spec::self_signed("localhost"));
    assert!(
        cert.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"),
        "Cert PEM should start with BEGIN CERTIFICATE"
    );
    assert!(
        cert.private_key_pkcs8_pem()
            .starts_with("-----BEGIN PRIVATE KEY-----"),
        "Key PEM should start with BEGIN PRIVATE KEY"
    );
    assert!(!cert.cert_der().is_empty(), "Cert DER should be non-empty");
    assert!(
        !cert.private_key_pkcs8_der().is_empty(),
        "Key DER should be non-empty"
    );
}

// =========================================================================
// Determinism verification — same seed → same config
// =========================================================================

#[test]
fn deterministic_self_signed_produces_identical_output() {
    let seed = Seed::from_env_value("tonic-int-det-ss-v1").expect("seed");
    let fx = Factory::deterministic(seed);

    let cert1 = fx.x509_self_signed("det-ss", X509Spec::self_signed("det.example.com"));
    fx.clear_cache();
    let cert2 = fx.x509_self_signed("det-ss", X509Spec::self_signed("det.example.com"));

    assert_eq!(cert1.cert_pem(), cert2.cert_pem());
    assert_eq!(cert1.private_key_pkcs8_pem(), cert2.private_key_pkcs8_pem());
    assert_eq!(cert1.cert_der(), cert2.cert_der());
    assert_eq!(cert1.private_key_pkcs8_der(), cert2.private_key_pkcs8_der());
}

#[test]
fn deterministic_chain_produces_identical_output() {
    let seed = Seed::from_env_value("tonic-int-det-chain-v1").expect("seed");
    let fx = Factory::deterministic(seed);

    let chain1 = fx.x509_chain("det-chain", ChainSpec::new("det-chain.example.com"));
    fx.clear_cache();
    let chain2 = fx.x509_chain("det-chain", ChainSpec::new("det-chain.example.com"));

    assert_eq!(chain1.chain_pem(), chain2.chain_pem());
    assert_eq!(chain1.root_cert_pem(), chain2.root_cert_pem());
    assert_eq!(chain1.leaf_cert_pem(), chain2.leaf_cert_pem());
    assert_eq!(
        chain1.leaf_private_key_pkcs8_pem(),
        chain2.leaf_private_key_pkcs8_pem()
    );
    assert_eq!(chain1.root_cert_der(), chain2.root_cert_der());
    assert_eq!(chain1.leaf_cert_der(), chain2.leaf_cert_der());
}

#[test]
fn different_seeds_produce_different_self_signed_certs() {
    let fx_a = Factory::deterministic(Seed::new([0x11; 32]));
    let fx_b = Factory::deterministic(Seed::new([0x22; 32]));

    let cert_a = fx_a.x509_self_signed("diff-ss", X509Spec::self_signed("a.example.com"));
    let cert_b = fx_b.x509_self_signed("diff-ss", X509Spec::self_signed("a.example.com"));

    assert_ne!(
        cert_a.cert_der(),
        cert_b.cert_der(),
        "Different seeds should produce different certs"
    );
}

#[test]
fn different_seeds_produce_different_chains() {
    let fx_a = Factory::deterministic(Seed::new([0x33; 32]));
    let fx_b = Factory::deterministic(Seed::new([0x44; 32]));

    let chain_a = fx_a.x509_chain("diff-chain", ChainSpec::new("a.example.com"));
    let chain_b = fx_b.x509_chain("diff-chain", ChainSpec::new("a.example.com"));

    assert_ne!(
        chain_a.leaf_cert_der(),
        chain_b.leaf_cert_der(),
        "Different seeds should produce different chain leaf certs"
    );
}

#[test]
fn different_labels_produce_different_certs() {
    let fx = fx();

    let cert_a = fx.x509_self_signed("label-a", X509Spec::self_signed("test.example.com"));
    let cert_b = fx.x509_self_signed("label-b", X509Spec::self_signed("test.example.com"));

    assert_ne!(
        cert_a.cert_der(),
        cert_b.cert_der(),
        "Different labels should produce different certs"
    );
}

// =========================================================================
// Debug safety — no key material in Debug output
// =========================================================================

#[test]
fn x509_cert_debug_does_not_leak_private_key() {
    let fx = fx();
    let cert = fx.x509_self_signed("debug-ss", X509Spec::self_signed("debug.example.com"));
    let dbg = format!("{cert:?}");

    assert!(
        dbg.contains("X509Cert"),
        "Debug output should contain type name"
    );
    assert!(
        dbg.contains("debug-ss"),
        "Debug output should contain the label"
    );
    assert!(
        !dbg.contains("BEGIN PRIVATE KEY"),
        "Debug output must NOT contain private key PEM"
    );
    assert!(
        !dbg.contains("BEGIN CERTIFICATE"),
        "Debug output must NOT contain certificate PEM"
    );
    assert!(
        dbg.contains(".."),
        "Debug output should use non-exhaustive format"
    );
}

#[test]
fn x509_chain_debug_does_not_leak_private_key() {
    let fx = fx();
    let chain = fx.x509_chain("debug-chain", ChainSpec::new("debug.example.com"));
    let dbg = format!("{chain:?}");

    assert!(
        dbg.contains("X509Chain"),
        "Debug output should contain type name"
    );
    assert!(
        dbg.contains("debug-chain"),
        "Debug output should contain the label"
    );
    assert!(
        !dbg.contains("BEGIN PRIVATE KEY"),
        "Debug output must NOT contain private key PEM"
    );
    assert!(
        !dbg.contains("BEGIN CERTIFICATE"),
        "Debug output must NOT contain certificate PEM"
    );
    assert!(
        dbg.contains(".."),
        "Debug output should use non-exhaustive format"
    );
}

// =========================================================================
// Domain name handling
// =========================================================================

#[test]
fn client_tls_config_accepts_string_domain() {
    let fx = fx();
    let cert = fx.x509_self_signed("domain-str", X509Spec::self_signed("test.example.com"));
    let _client = cert.client_tls_config_tonic(String::from("test.example.com"));
}

#[test]
fn client_tls_config_accepts_str_domain() {
    let fx = fx();
    let cert = fx.x509_self_signed("domain-ref", X509Spec::self_signed("test.example.com"));
    let _client = cert.client_tls_config_tonic("test.example.com");
}

#[test]
fn mtls_client_config_accepts_string_domain() {
    let fx = fx();
    let chain = fx.x509_chain("domain-mtls", ChainSpec::new("test.example.com"));
    let _client = chain.client_tls_config_mtls_tonic(String::from("test.example.com"));
}

// =========================================================================
// Caching — same label+spec returns cached result
// =========================================================================

#[test]
fn cached_self_signed_returns_same_arc() {
    let fx = fx();
    let cert1 = fx.x509_self_signed("cached-ss", X509Spec::self_signed("cache.example.com"));
    let cert2 = fx.x509_self_signed("cached-ss", X509Spec::self_signed("cache.example.com"));

    assert_eq!(
        cert1.cert_der(),
        cert2.cert_der(),
        "Cached calls should return identical cert"
    );
    assert_eq!(
        cert1.private_key_pkcs8_der(),
        cert2.private_key_pkcs8_der(),
        "Cached calls should return identical key"
    );
}

#[test]
fn cached_chain_returns_same_arc() {
    let fx = fx();
    let chain1 = fx.x509_chain("cached-chain", ChainSpec::new("cache.example.com"));
    let chain2 = fx.x509_chain("cached-chain", ChainSpec::new("cache.example.com"));

    assert_eq!(
        chain1.chain_pem(),
        chain2.chain_pem(),
        "Cached calls should return identical chain"
    );
}
