//! Deep PEM structure validation and chain ordering tests for tonic adapter.
//!
//! Verifies that the PEM output passed to tonic has the correct structure
//! and ordering for TLS handshakes to succeed.

mod testutil;

use testutil::fx;
use uselesskey_tonic::{TonicClientTlsExt, TonicIdentityExt, TonicServerTlsExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

// =========================================================================
// PEM header/footer validation
// =========================================================================

#[test]
fn self_signed_cert_pem_has_matching_begin_end() {
    let fx = fx();
    let cert = fx.x509_self_signed("pem-be-ss", X509Spec::self_signed("localhost"));
    let pem = cert.cert_pem();
    let begins = pem.matches("-----BEGIN CERTIFICATE-----").count();
    let ends = pem.matches("-----END CERTIFICATE-----").count();
    assert_eq!(begins, ends, "BEGIN and END counts should match");
    assert_eq!(
        begins, 1,
        "Self-signed cert should have exactly one certificate"
    );
}

#[test]
fn self_signed_key_pem_has_matching_begin_end() {
    let fx = fx();
    let cert = fx.x509_self_signed("pem-key-ss", X509Spec::self_signed("localhost"));
    let pem = cert.private_key_pkcs8_pem();
    let begins = pem.matches("-----BEGIN PRIVATE KEY-----").count();
    let ends = pem.matches("-----END PRIVATE KEY-----").count();
    assert_eq!(begins, ends, "Key PEM BEGIN and END should match");
    assert_eq!(begins, 1, "Should have exactly one key block");
}

#[test]
fn chain_pem_each_cert_has_matching_begin_end() {
    let fx = fx();
    let chain = fx.x509_chain("pem-be-chain", ChainSpec::new("chain.example.com"));
    let pem = chain.chain_pem();
    let begins = pem.matches("-----BEGIN CERTIFICATE-----").count();
    let ends = pem.matches("-----END CERTIFICATE-----").count();
    assert_eq!(begins, ends, "chain_pem BEGIN and END counts should match");
    assert_eq!(begins, 2, "chain_pem should have 2 certs");
}

#[test]
fn full_chain_pem_each_cert_has_matching_begin_end() {
    let fx = fx();
    let chain = fx.x509_chain("pem-full-be", ChainSpec::new("chain.example.com"));
    let pem = chain.full_chain_pem();
    let begins = pem.matches("-----BEGIN CERTIFICATE-----").count();
    let ends = pem.matches("-----END CERTIFICATE-----").count();
    assert_eq!(
        begins, ends,
        "full_chain_pem BEGIN and END counts should match"
    );
    assert_eq!(begins, 3, "full_chain_pem should have 3 certs");
}

// =========================================================================
// Chain ordering: leaf first, then intermediate, then root (in full chain)
// =========================================================================

#[test]
fn chain_pem_leaf_comes_before_intermediate() {
    let fx = fx();
    let chain = fx.x509_chain("pem-order", ChainSpec::new("order.example.com"));

    let chain_pem = chain.chain_pem();
    let leaf_pem = chain.leaf_cert_pem();
    let intermediate_pem = chain.intermediate_cert_pem();

    // Leaf should appear first in chain_pem
    let leaf_pos = chain_pem
        .find(leaf_pem)
        .expect("leaf should appear in chain_pem");
    let intermediate_pos = chain_pem
        .find(intermediate_pem)
        .expect("intermediate should appear in chain_pem");

    assert!(
        leaf_pos < intermediate_pos,
        "Leaf should come before intermediate in chain_pem"
    );
}

#[test]
fn full_chain_pem_ordering_leaf_intermediate_root() {
    let fx = fx();
    let chain = fx.x509_chain("pem-full-order", ChainSpec::new("order.example.com"));

    let full_pem = chain.full_chain_pem();
    let leaf_pem = chain.leaf_cert_pem();
    let intermediate_pem = chain.intermediate_cert_pem();
    let root_pem = chain.root_cert_pem();

    let leaf_pos = full_pem
        .find(leaf_pem)
        .expect("leaf should appear in full_chain_pem");
    let intermediate_pos = full_pem
        .find(intermediate_pem)
        .expect("intermediate should appear in full_chain_pem");
    let root_pos = full_pem
        .find(root_pem)
        .expect("root should appear in full_chain_pem");

    assert!(
        leaf_pos < intermediate_pos,
        "Leaf should come before intermediate"
    );
    assert!(
        intermediate_pos < root_pos,
        "Intermediate should come before root"
    );
}

// =========================================================================
// DER sizes are reasonable
// =========================================================================

#[test]
fn self_signed_der_sizes_reasonable() {
    let fx = fx();
    let cert = fx.x509_self_signed("pem-der-sz", X509Spec::self_signed("localhost"));
    let cert_der = cert.cert_der();
    let key_der = cert.private_key_pkcs8_der();

    // RSA 2048 cert DER is typically 600-1200 bytes; key DER ~1200 bytes
    assert!(
        cert_der.len() > 100,
        "cert DER should be at least 100 bytes, got {}",
        cert_der.len()
    );
    assert!(
        key_der.len() > 100,
        "key DER should be at least 100 bytes, got {}",
        key_der.len()
    );
}

#[test]
fn chain_der_sizes_all_reasonable() {
    let fx = fx();
    let chain = fx.x509_chain("pem-chain-sz", ChainSpec::new("size.example.com"));

    assert!(chain.root_cert_der().len() > 100);
    assert!(chain.intermediate_cert_der().len() > 100);
    assert!(chain.leaf_cert_der().len() > 100);
    assert!(chain.leaf_private_key_pkcs8_der().len() > 100);
}

#[test]
fn larger_rsa_key_produces_larger_artifacts() {
    let fx = fx();
    let chain_2k = fx.x509_chain(
        "pem-sz-2k",
        ChainSpec::new("size.example.com").with_rsa_bits(2048),
    );
    let chain_4k = fx.x509_chain(
        "pem-sz-4k",
        ChainSpec::new("size.example.com").with_rsa_bits(4096),
    );

    assert!(
        chain_4k.leaf_private_key_pkcs8_der().len() > chain_2k.leaf_private_key_pkcs8_der().len(),
        "4096-bit key DER should be larger than 2048-bit"
    );
    assert!(
        chain_4k.leaf_cert_der().len() > chain_2k.leaf_cert_der().len(),
        "4096-bit cert DER should be larger than 2048-bit"
    );
}

// =========================================================================
// Root and intermediate keys are accessible (for advanced setups)
// =========================================================================

#[test]
fn root_private_key_accessible() {
    let fx = fx();
    let chain = fx.x509_chain("pem-root-key", ChainSpec::new("root.example.com"));
    let root_key_pem = chain.root_private_key_pkcs8_pem();
    assert!(root_key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(!chain.root_private_key_pkcs8_der().is_empty());
}

#[test]
fn intermediate_private_key_accessible() {
    let fx = fx();
    let chain = fx.x509_chain("pem-int-key", ChainSpec::new("int.example.com"));
    let int_key_pem = chain.intermediate_private_key_pkcs8_pem();
    assert!(int_key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(!chain.intermediate_private_key_pkcs8_der().is_empty());
}

#[test]
fn intermediate_cert_pem_accessible() {
    let fx = fx();
    let chain = fx.x509_chain("pem-int-cert", ChainSpec::new("int.example.com"));
    let int_cert_pem = chain.intermediate_cert_pem();
    assert!(int_cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
}

// =========================================================================
// Tonic config from various chain configurations
// =========================================================================

#[test]
fn identity_from_chain_with_sans() {
    let fx = fx();
    let chain = fx.x509_chain(
        "pem-sans",
        ChainSpec::new("primary.example.com")
            .with_sans(vec!["alt1.example.com".into(), "alt2.example.com".into()]),
    );
    let _identity = chain.identity_tonic();
    let _server = chain.server_tls_config_tonic();
    let _client = chain.client_tls_config_tonic("alt1.example.com");
}

#[test]
fn identity_from_chain_with_custom_cns() {
    let fx = fx();
    let chain = fx.x509_chain(
        "pem-cns",
        ChainSpec::new("leaf.example.com")
            .with_root_cn("Test Root CA")
            .with_intermediate_cn("Test Intermediate CA"),
    );
    let _identity = chain.identity_tonic();
    let _server = chain.server_tls_config_tonic();
}

#[test]
fn self_signed_with_custom_validity() {
    let fx = fx();
    let cert = fx.x509_self_signed(
        "pem-validity",
        X509Spec::self_signed("localhost").with_validity_days(1),
    );
    let _identity = cert.identity_tonic();
    let _server = cert.server_tls_config_tonic();
    let _client = cert.client_tls_config_tonic("localhost");
}
