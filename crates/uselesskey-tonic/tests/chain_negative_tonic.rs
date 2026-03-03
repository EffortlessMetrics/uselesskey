//! Tests for tonic adapter integration with X.509 chain negative fixtures.
//!
//! Covers:
//! - Expired leaf / intermediate certs build tonic configs (deferred validation)
//! - Revoked leaf certs build tonic configs
//! - Unknown CA chain builds tonic configs
//! - Hostname mismatch chain builds tonic configs
//! - CRL availability through negative chains

mod testutil;

use testutil::fx;
use uselesskey_tonic::{TonicClientTlsExt, TonicIdentityExt, TonicMtlsExt, TonicServerTlsExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt};

// =========================================================================
// Expired leaf certificate
// =========================================================================

#[test]
fn expired_leaf_chain_identity_builds() {
    let fx = fx();
    let chain = fx.x509_chain("neg-expired-leaf", ChainSpec::new("expired.example.com"));
    let expired = chain.expired_leaf();
    let _identity = expired.identity_tonic();
}

#[test]
fn expired_leaf_chain_server_tls_builds() {
    let fx = fx();
    let chain = fx.x509_chain("neg-exp-leaf-srv", ChainSpec::new("expired.example.com"));
    let expired = chain.expired_leaf();
    let _server = expired.server_tls_config_tonic();
}

#[test]
fn expired_leaf_chain_client_tls_builds() {
    let fx = fx();
    let chain = fx.x509_chain("neg-exp-leaf-cli", ChainSpec::new("expired.example.com"));
    let expired = chain.expired_leaf();
    let _client = expired.client_tls_config_tonic("expired.example.com");
}

#[test]
fn expired_leaf_chain_mtls_builds() {
    let fx = fx();
    let chain = fx.x509_chain("neg-exp-leaf-mtls", ChainSpec::new("expired.example.com"));
    let expired = chain.expired_leaf();
    let _server = expired.server_tls_config_mtls_tonic();
    let _client = expired.client_tls_config_mtls_tonic("expired.example.com");
}

// =========================================================================
// Expired intermediate certificate
// =========================================================================

#[test]
fn expired_intermediate_chain_identity_builds() {
    let fx = fx();
    let chain = fx.x509_chain("neg-exp-int", ChainSpec::new("expired-int.example.com"));
    let expired = chain.expired_intermediate();
    let _identity = expired.identity_tonic();
}

#[test]
fn expired_intermediate_chain_server_tls_builds() {
    let fx = fx();
    let chain = fx.x509_chain("neg-exp-int-srv", ChainSpec::new("expired-int.example.com"));
    let expired = chain.expired_intermediate();
    let _server = expired.server_tls_config_tonic();
}

#[test]
fn expired_intermediate_chain_mtls_builds() {
    let fx = fx();
    let chain = fx.x509_chain(
        "neg-exp-int-mtls",
        ChainSpec::new("expired-int.example.com"),
    );
    let expired = chain.expired_intermediate();
    let _server = expired.server_tls_config_mtls_tonic();
    let _client = expired.client_tls_config_mtls_tonic("expired-int.example.com");
}

// =========================================================================
// Revoked leaf certificate
// =========================================================================

#[test]
fn revoked_leaf_chain_identity_builds() {
    let fx = fx();
    let chain = fx.x509_chain("neg-revoked", ChainSpec::new("revoked.example.com"));
    let revoked = chain.revoked_leaf();
    let _identity = revoked.identity_tonic();
}

#[test]
fn revoked_leaf_chain_server_tls_builds() {
    let fx = fx();
    let chain = fx.x509_chain("neg-revoked-srv", ChainSpec::new("revoked.example.com"));
    let revoked = chain.revoked_leaf();
    let _server = revoked.server_tls_config_tonic();
}

#[test]
fn revoked_leaf_chain_client_tls_builds() {
    let fx = fx();
    let chain = fx.x509_chain("neg-revoked-cli", ChainSpec::new("revoked.example.com"));
    let revoked = chain.revoked_leaf();
    let _client = revoked.client_tls_config_tonic("revoked.example.com");
}

#[test]
fn revoked_leaf_chain_has_crl() {
    let fx = fx();
    let chain = fx.x509_chain("neg-revoked-crl", ChainSpec::new("revoked.example.com"));
    let revoked = chain.revoked_leaf();
    assert!(
        revoked.crl_der().is_some(),
        "Revoked leaf chain should have a CRL"
    );
    assert!(
        revoked.crl_pem().is_some(),
        "Revoked leaf chain should have a CRL PEM"
    );
}

// =========================================================================
// Unknown CA chain
// =========================================================================

#[test]
fn unknown_ca_chain_identity_builds() {
    let fx = fx();
    let chain = fx.x509_chain("neg-unknown-ca", ChainSpec::new("unknown.example.com"));
    let unknown = chain.unknown_ca();
    let _identity = unknown.identity_tonic();
}

#[test]
fn unknown_ca_chain_server_tls_builds() {
    let fx = fx();
    let chain = fx.x509_chain("neg-uca-srv", ChainSpec::new("unknown.example.com"));
    let unknown = chain.unknown_ca();
    let _server = unknown.server_tls_config_tonic();
}

#[test]
fn unknown_ca_chain_client_tls_builds() {
    let fx = fx();
    let chain = fx.x509_chain("neg-uca-cli", ChainSpec::new("unknown.example.com"));
    let unknown = chain.unknown_ca();
    let _client = unknown.client_tls_config_tonic("unknown.example.com");
}

#[test]
fn unknown_ca_has_different_root() {
    let fx = fx();
    let chain = fx.x509_chain("neg-uca-diff", ChainSpec::new("unknown.example.com"));
    let unknown = chain.unknown_ca();
    assert_ne!(
        chain.root_cert_der(),
        unknown.root_cert_der(),
        "Unknown CA should have a different root certificate"
    );
}

// =========================================================================
// Hostname mismatch chain
// =========================================================================

#[test]
fn hostname_mismatch_chain_identity_builds() {
    let fx = fx();
    let chain = fx.x509_chain("neg-hostname", ChainSpec::new("correct.example.com"));
    let mismatched = chain.hostname_mismatch("wrong.example.com");
    let _identity = mismatched.identity_tonic();
}

#[test]
fn hostname_mismatch_chain_server_tls_builds() {
    let fx = fx();
    let chain = fx.x509_chain("neg-host-srv", ChainSpec::new("correct.example.com"));
    let mismatched = chain.hostname_mismatch("wrong.example.com");
    let _server = mismatched.server_tls_config_tonic();
}

#[test]
fn hostname_mismatch_chain_mtls_builds() {
    let fx = fx();
    let chain = fx.x509_chain("neg-host-mtls", ChainSpec::new("correct.example.com"));
    let mismatched = chain.hostname_mismatch("wrong.example.com");
    let _server = mismatched.server_tls_config_mtls_tonic();
    let _client = mismatched.client_tls_config_mtls_tonic("correct.example.com");
}

#[test]
fn hostname_mismatch_has_different_leaf() {
    let fx = fx();
    let chain = fx.x509_chain("neg-host-diff", ChainSpec::new("correct.example.com"));
    let mismatched = chain.hostname_mismatch("wrong.example.com");
    assert_ne!(
        chain.leaf_cert_der(),
        mismatched.leaf_cert_der(),
        "Hostname mismatch should produce a different leaf certificate"
    );
}

// =========================================================================
// Negative chain PEM structure still valid
// =========================================================================

#[test]
fn expired_leaf_chain_pem_has_two_certs() {
    let fx = fx();
    let chain = fx.x509_chain("neg-pem-cnt", ChainSpec::new("pem.example.com"));
    let expired = chain.expired_leaf();
    let count = expired
        .chain_pem()
        .matches("-----BEGIN CERTIFICATE-----")
        .count();
    assert_eq!(
        count, 2,
        "expired leaf chain_pem should still contain 2 certs"
    );
}

#[test]
fn unknown_ca_full_chain_pem_has_three_certs() {
    let fx = fx();
    let chain = fx.x509_chain("neg-full-pem", ChainSpec::new("pem.example.com"));
    let unknown = chain.unknown_ca();
    let count = unknown
        .full_chain_pem()
        .matches("-----BEGIN CERTIFICATE-----")
        .count();
    assert_eq!(
        count, 3,
        "unknown CA full_chain_pem should still contain 3 certs"
    );
}

#[test]
fn revoked_leaf_key_pem_has_correct_header() {
    let fx = fx();
    let chain = fx.x509_chain("neg-key-hdr", ChainSpec::new("key.example.com"));
    let revoked = chain.revoked_leaf();
    assert!(
        revoked
            .leaf_private_key_pkcs8_pem()
            .starts_with("-----BEGIN PRIVATE KEY-----")
    );
}
