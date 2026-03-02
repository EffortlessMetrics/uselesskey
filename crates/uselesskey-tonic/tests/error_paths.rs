//! Error path and boundary condition tests for uselesskey-tonic.

mod testutil;

use testutil::fx;
use uselesskey_tonic::{TonicClientTlsExt, TonicIdentityExt, TonicMtlsExt, TonicServerTlsExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

// =========================================================================
// Self-signed cert: configs build without error
// =========================================================================

#[test]
fn self_signed_identity_builds() {
    let fx = fx();
    let cert = fx.x509_self_signed("tonic-ss", X509Spec::self_signed("localhost"));
    let _identity = cert.identity_tonic();
}

#[test]
fn self_signed_server_tls_builds() {
    let fx = fx();
    let cert = fx.x509_self_signed("tonic-server", X509Spec::self_signed("localhost"));
    let _server = cert.server_tls_config_tonic();
}

#[test]
fn self_signed_client_tls_builds() {
    let fx = fx();
    let cert = fx.x509_self_signed("tonic-client", X509Spec::self_signed("localhost"));
    let _client = cert.client_tls_config_tonic("localhost");
}

// =========================================================================
// Chain: configs build without error
// =========================================================================

#[test]
fn chain_identity_builds() {
    let fx = fx();
    let chain = fx.x509_chain("tonic-chain", ChainSpec::new("test.example.com"));
    let _identity = chain.identity_tonic();
}

#[test]
fn chain_server_tls_builds() {
    let fx = fx();
    let chain = fx.x509_chain("tonic-chain-srv", ChainSpec::new("test.example.com"));
    let _server = chain.server_tls_config_tonic();
}

#[test]
fn chain_client_tls_builds() {
    let fx = fx();
    let chain = fx.x509_chain("tonic-chain-cli", ChainSpec::new("test.example.com"));
    let _client = chain.client_tls_config_tonic("test.example.com");
}

// =========================================================================
// mTLS: configs build without error
// =========================================================================

#[test]
fn chain_mtls_server_builds() {
    let fx = fx();
    let chain = fx.x509_chain("tonic-mtls-srv", ChainSpec::new("test.example.com"));
    let _server = chain.server_tls_config_mtls_tonic();
}

#[test]
fn chain_mtls_client_builds() {
    let fx = fx();
    let chain = fx.x509_chain("tonic-mtls-cli", ChainSpec::new("test.example.com"));
    let _client = chain.client_tls_config_mtls_tonic("test.example.com");
}

// =========================================================================
// Boundary: empty domain name
// =========================================================================

#[test]
fn client_tls_empty_domain_builds() {
    let fx = fx();
    let cert = fx.x509_self_signed("tonic-empty-dom", X509Spec::self_signed("localhost"));
    // Empty domain is accepted by tonic (it's just a string)
    let _client = cert.client_tls_config_tonic("");
}

#[test]
fn mtls_client_empty_domain_builds() {
    let fx = fx();
    let chain = fx.x509_chain("tonic-mtls-empty", ChainSpec::new("test.example.com"));
    let _client = chain.client_tls_config_mtls_tonic("");
}

// =========================================================================
// Expired cert identity still builds (tonic doesn't validate at build time)
// =========================================================================

#[test]
fn expired_cert_identity_builds() {
    let fx = fx();
    let spec = X509Spec::self_signed("expired.example.com");
    let cert = fx.x509_self_signed("tonic-expired", spec);
    let expired = cert.expired();

    // tonic Identity::from_pem doesn't validate cert times
    let _identity = expired.identity_tonic();
}

#[test]
fn expired_cert_server_tls_builds() {
    let fx = fx();
    let spec = X509Spec::self_signed("expired.example.com");
    let cert = fx.x509_self_signed("tonic-expired-srv", spec);
    let expired = cert.expired();

    let _server = expired.server_tls_config_tonic();
}

#[test]
fn expired_cert_client_tls_builds() {
    let fx = fx();
    let spec = X509Spec::self_signed("expired.example.com");
    let cert = fx.x509_self_signed("tonic-expired-cli", spec);
    let expired = cert.expired();

    let _client = expired.client_tls_config_tonic("expired.example.com");
}

// =========================================================================
// Not-yet-valid cert identity still builds
// =========================================================================

#[test]
fn not_yet_valid_cert_identity_builds() {
    let fx = fx();
    let spec = X509Spec::self_signed("future.example.com");
    let cert = fx.x509_self_signed("tonic-future", spec);
    let future = cert.not_yet_valid();

    let _identity = future.identity_tonic();
}

// =========================================================================
// Determinism: same seed produces same TLS configs
// =========================================================================

#[test]
fn deterministic_chain_material_consistent() {
    use uselesskey_core::{Factory, Seed};

    let seed = Seed::from_env_value("tonic-det-test").expect("seed");
    let fx = Factory::deterministic(seed);

    let a = fx.x509_chain("det-test", ChainSpec::new("det.example.com"));
    fx.clear_cache();
    let b = fx.x509_chain("det-test", ChainSpec::new("det.example.com"));

    assert_eq!(a.chain_pem(), b.chain_pem());
    assert_eq!(a.root_cert_pem(), b.root_cert_pem());
}
