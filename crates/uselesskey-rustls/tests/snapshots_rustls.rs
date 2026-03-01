//! Insta snapshot tests for uselesskey-rustls adapter.
//!
//! These tests snapshot key and certificate metadata produced by deterministic
//! fixtures to detect unintended changes in adapter output.
//! CRITICAL: No actual key bytes appear in snapshots — all crypto material is redacted.

mod testutil;

use serde::Serialize;
use testutil::fx;

#[derive(Serialize)]
struct RustlsKeySnapshot {
    key_type: &'static str,
    der_variant: &'static str,
    der_len: usize,
    der_hex: String,
}

// =========================================================================
// RSA snapshots
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_snapshots {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustls::RustlsPrivateKeyExt;

    #[test]
    fn snapshot_rustls_rsa_2048_private_key() {
        let fx = fx();
        let keypair = fx.rsa("snapshot-rsa-2048", RsaSpec::rs256());
        let key = keypair.private_key_der_rustls();

        let result = RustlsKeySnapshot {
            key_type: "RSA-2048",
            der_variant: "Pkcs8",
            der_len: key.secret_der().len(),
            der_hex: hex::encode(key.secret_der()),
        };

        insta::assert_yaml_snapshot!("rustls_rsa_2048_private_key", result, {
            ".der_hex" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_rustls_rsa_key_sizes() {
        let fx = fx();

        #[derive(Serialize)]
        struct RsaSizeInfo {
            label: &'static str,
            bits: usize,
            der_len: usize,
        }

        let cases: Vec<RsaSizeInfo> = [(2048, "rsa-2048"), (4096, "rsa-4096")]
            .into_iter()
            .map(|(bits, label)| {
                let kp = fx.rsa(label, RsaSpec::new(bits));
                let key = kp.private_key_der_rustls();
                RsaSizeInfo {
                    label,
                    bits,
                    der_len: key.secret_der().len(),
                }
            })
            .collect();

        insta::assert_yaml_snapshot!("rustls_rsa_key_sizes", cases);
    }
}

// =========================================================================
// ECDSA snapshots
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_snapshots {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_rustls::RustlsPrivateKeyExt;

    #[test]
    fn snapshot_rustls_ecdsa_p256_private_key() {
        let fx = fx();
        let keypair = fx.ecdsa("snapshot-ecdsa-p256", EcdsaSpec::es256());
        let key = keypair.private_key_der_rustls();

        let result = RustlsKeySnapshot {
            key_type: "ECDSA-P256",
            der_variant: "Pkcs8",
            der_len: key.secret_der().len(),
            der_hex: hex::encode(key.secret_der()),
        };

        insta::assert_yaml_snapshot!("rustls_ecdsa_p256_private_key", result, {
            ".der_hex" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_rustls_ecdsa_p384_private_key() {
        let fx = fx();
        let keypair = fx.ecdsa("snapshot-ecdsa-p384", EcdsaSpec::es384());
        let key = keypair.private_key_der_rustls();

        let result = RustlsKeySnapshot {
            key_type: "ECDSA-P384",
            der_variant: "Pkcs8",
            der_len: key.secret_der().len(),
            der_hex: hex::encode(key.secret_der()),
        };

        insta::assert_yaml_snapshot!("rustls_ecdsa_p384_private_key", result, {
            ".der_hex" => "[REDACTED]",
        });
    }
}

// =========================================================================
// Ed25519 snapshots
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_snapshots {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rustls::RustlsPrivateKeyExt;

    #[test]
    fn snapshot_rustls_ed25519_private_key() {
        let fx = fx();
        let keypair = fx.ed25519("snapshot-ed25519", Ed25519Spec::new());
        let key = keypair.private_key_der_rustls();

        let result = RustlsKeySnapshot {
            key_type: "Ed25519",
            der_variant: "Pkcs8",
            der_len: key.secret_der().len(),
            der_hex: hex::encode(key.secret_der()),
        };

        insta::assert_yaml_snapshot!("rustls_ed25519_private_key", result, {
            ".der_hex" => "[REDACTED]",
        });
    }
}

// =========================================================================
// X.509 certificate snapshots
// =========================================================================

#[cfg(feature = "x509")]
mod x509_snapshots {
    use super::*;
    use uselesskey_rustls::{RustlsCertExt, RustlsChainExt, RustlsPrivateKeyExt};
    use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

    #[test]
    fn snapshot_rustls_self_signed_cert() {
        let fx = fx();
        let cert = fx.x509_self_signed("snapshot-ss", X509Spec::self_signed("test.example.com"));

        #[derive(Serialize)]
        struct SelfSignedInfo {
            cert_der_len: usize,
            cert_der_hex: String,
            private_key_der_len: usize,
            private_key_der_hex: String,
            der_variant: &'static str,
        }

        let cert_der = cert.certificate_der_rustls();
        let key = cert.private_key_der_rustls();

        let result = SelfSignedInfo {
            cert_der_len: cert_der.as_ref().len(),
            cert_der_hex: hex::encode(cert_der.as_ref()),
            private_key_der_len: key.secret_der().len(),
            private_key_der_hex: hex::encode(key.secret_der()),
            der_variant: "Pkcs8",
        };

        insta::assert_yaml_snapshot!("rustls_self_signed_cert", result, {
            ".cert_der_hex" => "[REDACTED]",
            ".private_key_der_hex" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_rustls_chain_metadata() {
        let fx = fx();
        let chain = fx.x509_chain("snapshot-chain", ChainSpec::new("test.example.com"));

        #[derive(Serialize)]
        struct ChainInfo {
            chain_len: usize,
            leaf_cert_der_len: usize,
            leaf_cert_der_hex: String,
            intermediate_cert_der_len: usize,
            intermediate_cert_der_hex: String,
            root_cert_der_len: usize,
            root_cert_der_hex: String,
            private_key_der_len: usize,
            private_key_der_hex: String,
        }

        let chain_certs = chain.chain_der_rustls();
        let root = chain.root_certificate_der_rustls();
        let key = chain.private_key_der_rustls();

        let result = ChainInfo {
            chain_len: chain_certs.len(),
            leaf_cert_der_len: chain_certs[0].as_ref().len(),
            leaf_cert_der_hex: hex::encode(chain_certs[0].as_ref()),
            intermediate_cert_der_len: chain_certs[1].as_ref().len(),
            intermediate_cert_der_hex: hex::encode(chain_certs[1].as_ref()),
            root_cert_der_len: root.as_ref().len(),
            root_cert_der_hex: hex::encode(root.as_ref()),
            private_key_der_len: key.secret_der().len(),
            private_key_der_hex: hex::encode(key.secret_der()),
        };

        insta::assert_yaml_snapshot!("rustls_chain_metadata", result, {
            ".leaf_cert_der_hex" => "[REDACTED]",
            ".intermediate_cert_der_hex" => "[REDACTED]",
            ".root_cert_der_hex" => "[REDACTED]",
            ".private_key_der_hex" => "[REDACTED]",
        });
    }
}
