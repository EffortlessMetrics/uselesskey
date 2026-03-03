//! Insta snapshot tests for uselesskey-core-rustls-pki.
//!
//! These tests snapshot PKI type conversion metadata (DER lengths,
//! chain counts) to detect unintended changes. All key material
//! and certificate bytes are redacted.

mod testutil;

use serde::Serialize;
use testutil::fx;
use uselesskey_core_rustls_pki::{RustlsCertExt, RustlsChainExt, RustlsPrivateKeyExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

// ---------------------------------------------------------------------------
// Self-signed certificate conversions
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct SelfSignedConversion {
    private_key_der_len: usize,
    cert_der_len: usize,
    private_key_matches_source: bool,
    cert_matches_source: bool,
}

#[test]
fn snapshot_self_signed_rustls_conversion() {
    let fx = fx();
    let cert = fx.x509_self_signed("snap-ss", X509Spec::self_signed("snap.example.com"));

    let key = cert.private_key_der_rustls();
    let cert_der = cert.certificate_der_rustls();

    let snap = SelfSignedConversion {
        private_key_der_len: key.secret_der().len(),
        cert_der_len: cert_der.as_ref().len(),
        private_key_matches_source: key.secret_der() == cert.private_key_pkcs8_der(),
        cert_matches_source: cert_der.as_ref() == cert.cert_der(),
    };
    insta::assert_yaml_snapshot!("self_signed_rustls_conversion", snap);
}

// ---------------------------------------------------------------------------
// Chain conversions
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ChainConversion {
    leaf_private_key_der_len: usize,
    leaf_cert_der_len: usize,
    chain_cert_count: usize,
    root_cert_der_len: usize,
    private_key_matches_source: bool,
    leaf_cert_matches_source: bool,
    root_cert_matches_source: bool,
}

#[test]
fn snapshot_chain_rustls_conversion() {
    let fx = fx();
    let chain = fx.x509_chain("snap-chain", ChainSpec::new("chain.example.com"));

    let key = chain.private_key_der_rustls();
    let leaf_cert = chain.certificate_der_rustls();
    let chain_certs = chain.chain_der_rustls();
    let root_cert = chain.root_certificate_der_rustls();

    let snap = ChainConversion {
        leaf_private_key_der_len: key.secret_der().len(),
        leaf_cert_der_len: leaf_cert.as_ref().len(),
        chain_cert_count: chain_certs.len(),
        root_cert_der_len: root_cert.as_ref().len(),
        private_key_matches_source: key.secret_der() == chain.leaf_private_key_pkcs8_der(),
        leaf_cert_matches_source: leaf_cert.as_ref() == chain.leaf_cert_der(),
        root_cert_matches_source: root_cert.as_ref() == chain.root_cert_der(),
    };
    insta::assert_yaml_snapshot!("chain_rustls_conversion", snap);
}

// ---------------------------------------------------------------------------
// RSA key conversion
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct RsaConversion {
    private_key_der_len: usize,
    matches_source: bool,
}

#[test]
fn snapshot_rsa_rustls_conversion() {
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    let fx = fx();
    let kp = fx.rsa("snap-rsa", RsaSpec::rs256());

    let key = kp.private_key_der_rustls();

    let snap = RsaConversion {
        private_key_der_len: key.secret_der().len(),
        matches_source: key.secret_der() == kp.private_key_pkcs8_der(),
    };
    insta::assert_yaml_snapshot!("rsa_rustls_conversion", snap);
}

// ---------------------------------------------------------------------------
// ECDSA key conversion
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct EcdsaConversion {
    curve: &'static str,
    private_key_der_len: usize,
    matches_source: bool,
}

#[test]
fn snapshot_ecdsa_rustls_conversion() {
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    let fx = fx();

    let results: Vec<EcdsaConversion> = vec![
        {
            let kp = fx.ecdsa("snap-p256", EcdsaSpec::es256());
            let key = kp.private_key_der_rustls();
            EcdsaConversion {
                curve: "P-256",
                private_key_der_len: key.secret_der().len(),
                matches_source: key.secret_der() == kp.private_key_pkcs8_der(),
            }
        },
        {
            let kp = fx.ecdsa("snap-p384", EcdsaSpec::es384());
            let key = kp.private_key_der_rustls();
            EcdsaConversion {
                curve: "P-384",
                private_key_der_len: key.secret_der().len(),
                matches_source: key.secret_der() == kp.private_key_pkcs8_der(),
            }
        },
    ];
    insta::assert_yaml_snapshot!("ecdsa_rustls_conversion", results);
}

// ---------------------------------------------------------------------------
// Ed25519 key conversion
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct Ed25519Conversion {
    private_key_der_len: usize,
    matches_source: bool,
}

#[test]
fn snapshot_ed25519_rustls_conversion() {
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    let fx = fx();
    let kp = fx.ed25519("snap-ed25519", Ed25519Spec::new());

    let key = kp.private_key_der_rustls();

    let snap = Ed25519Conversion {
        private_key_der_len: key.secret_der().len(),
        matches_source: key.secret_der() == kp.private_key_pkcs8_der(),
    };
    insta::assert_yaml_snapshot!("ed25519_rustls_conversion", snap);
}
