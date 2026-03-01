//! Insta snapshot tests for uselesskey-rustls adapter.
//!
//! These tests snapshot metadata about rustls-pki-types conversions
//! produced by deterministic keys to detect unintended changes.

mod testutil;

use serde::Serialize;
use testutil::fx;

// =========================================================================
// RSA snapshots
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_snapshots {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustls::RustlsPrivateKeyExt;

    #[derive(Serialize)]
    struct RustlsKeyMeta {
        algorithm: &'static str,
        key_format: &'static str,
        der_len: usize,
    }

    #[test]
    fn snapshot_rustls_rsa_2048() {
        let fx = fx();
        let keypair = fx.rsa("snapshot-rsa-2048", RsaSpec::rs256());
        let key = keypair.private_key_der_rustls();

        let meta = RustlsKeyMeta {
            algorithm: "RSA-2048",
            key_format: "PKCS8",
            der_len: key.secret_der().len(),
        };

        insta::assert_yaml_snapshot!("rustls_rsa_2048_private_key", meta, {
            // no key material to redact — only metadata
        });
    }

    #[test]
    fn snapshot_rustls_rsa_4096() {
        let fx = fx();
        let keypair = fx.rsa("snapshot-rsa-4096", RsaSpec::new(4096));
        let key = keypair.private_key_der_rustls();

        let meta = RustlsKeyMeta {
            algorithm: "RSA-4096",
            key_format: "PKCS8",
            der_len: key.secret_der().len(),
        };

        insta::assert_yaml_snapshot!("rustls_rsa_4096_private_key", meta);
    }

    #[test]
    fn snapshot_rustls_rsa_determinism() {
        let fx = fx();
        let kp1 = fx.rsa("snapshot-rsa-det", RsaSpec::rs256());
        let kp2 = fx.rsa("snapshot-rsa-det", RsaSpec::rs256());

        let len1 = kp1.private_key_der_rustls().secret_der().len();
        let len2 = kp2.private_key_der_rustls().secret_der().len();

        #[derive(Serialize)]
        struct Determinism {
            algorithm: &'static str,
            same_output: bool,
            der_len: usize,
        }

        let result = Determinism {
            algorithm: "RSA-2048",
            same_output: kp1.private_key_der_rustls().secret_der()
                == kp2.private_key_der_rustls().secret_der(),
            der_len: len1,
        };

        assert_eq!(len1, len2);
        insta::assert_yaml_snapshot!("rustls_rsa_determinism", result);
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

    #[derive(Serialize)]
    struct RustlsKeyMeta {
        algorithm: &'static str,
        key_format: &'static str,
        der_len: usize,
    }

    #[test]
    fn snapshot_rustls_ecdsa_p256() {
        let fx = fx();
        let keypair = fx.ecdsa("snapshot-ecdsa-p256", EcdsaSpec::es256());
        let key = keypair.private_key_der_rustls();

        let meta = RustlsKeyMeta {
            algorithm: "ECDSA-P256",
            key_format: "PKCS8",
            der_len: key.secret_der().len(),
        };

        insta::assert_yaml_snapshot!("rustls_ecdsa_p256_private_key", meta);
    }

    #[test]
    fn snapshot_rustls_ecdsa_p384() {
        let fx = fx();
        let keypair = fx.ecdsa("snapshot-ecdsa-p384", EcdsaSpec::es384());
        let key = keypair.private_key_der_rustls();

        let meta = RustlsKeyMeta {
            algorithm: "ECDSA-P384",
            key_format: "PKCS8",
            der_len: key.secret_der().len(),
        };

        insta::assert_yaml_snapshot!("rustls_ecdsa_p384_private_key", meta);
    }

    #[test]
    fn snapshot_rustls_ecdsa_determinism() {
        let fx = fx();
        let kp1 = fx.ecdsa("snapshot-ecdsa-det", EcdsaSpec::es256());
        let kp2 = fx.ecdsa("snapshot-ecdsa-det", EcdsaSpec::es256());

        #[derive(Serialize)]
        struct Determinism {
            algorithm: &'static str,
            same_output: bool,
            der_len: usize,
        }

        let result = Determinism {
            algorithm: "ECDSA-P256",
            same_output: kp1.private_key_der_rustls().secret_der()
                == kp2.private_key_der_rustls().secret_der(),
            der_len: kp1.private_key_der_rustls().secret_der().len(),
        };

        insta::assert_yaml_snapshot!("rustls_ecdsa_determinism", result);
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

    #[derive(Serialize)]
    struct RustlsKeyMeta {
        algorithm: &'static str,
        key_format: &'static str,
        der_len: usize,
    }

    #[test]
    fn snapshot_rustls_ed25519() {
        let fx = fx();
        let keypair = fx.ed25519("snapshot-ed25519", Ed25519Spec::new());
        let key = keypair.private_key_der_rustls();

        let meta = RustlsKeyMeta {
            algorithm: "Ed25519",
            key_format: "PKCS8",
            der_len: key.secret_der().len(),
        };

        insta::assert_yaml_snapshot!("rustls_ed25519_private_key", meta);
    }

    #[test]
    fn snapshot_rustls_ed25519_determinism() {
        let fx = fx();
        let kp1 = fx.ed25519("snapshot-ed25519-det", Ed25519Spec::new());
        let kp2 = fx.ed25519("snapshot-ed25519-det", Ed25519Spec::new());

        #[derive(Serialize)]
        struct Determinism {
            algorithm: &'static str,
            same_output: bool,
            der_len: usize,
        }

        let result = Determinism {
            algorithm: "Ed25519",
            same_output: kp1.private_key_der_rustls().secret_der()
                == kp2.private_key_der_rustls().secret_der(),
            der_len: kp1.private_key_der_rustls().secret_der().len(),
        };

        insta::assert_yaml_snapshot!("rustls_ed25519_determinism", result);
    }
}

// =========================================================================
// X.509 snapshots
// =========================================================================

#[cfg(feature = "x509")]
mod x509_snapshots {
    use super::*;
    use uselesskey_rustls::{RustlsCertExt, RustlsChainExt, RustlsPrivateKeyExt};
    use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

    #[derive(Serialize)]
    struct X509CertMeta {
        description: &'static str,
        key_format: &'static str,
        private_key_der_len: usize,
        cert_der_len: usize,
    }

    #[derive(Serialize)]
    struct X509ChainMeta {
        description: &'static str,
        key_format: &'static str,
        private_key_der_len: usize,
        leaf_cert_der_len: usize,
        chain_len: usize,
        root_cert_der_len: usize,
    }

    #[test]
    fn snapshot_rustls_x509_self_signed() {
        let fx = fx();
        let cert = fx.x509_self_signed(
            "snapshot-self-signed",
            X509Spec::self_signed("test.example.com"),
        );

        let meta = X509CertMeta {
            description: "X.509 self-signed certificate",
            key_format: "PKCS8",
            private_key_der_len: cert.private_key_der_rustls().secret_der().len(),
            cert_der_len: cert.certificate_der_rustls().as_ref().len(),
        };

        insta::assert_yaml_snapshot!("rustls_x509_self_signed", meta);
    }

    #[test]
    fn snapshot_rustls_x509_chain() {
        let fx = fx();
        let chain = fx.x509_chain("snapshot-chain", ChainSpec::new("test.example.com"));

        let chain_certs = chain.chain_der_rustls();

        let meta = X509ChainMeta {
            description: "X.509 certificate chain (leaf + intermediate)",
            key_format: "PKCS8",
            private_key_der_len: chain.private_key_der_rustls().secret_der().len(),
            leaf_cert_der_len: chain.certificate_der_rustls().as_ref().len(),
            chain_len: chain_certs.len(),
            root_cert_der_len: chain.root_certificate_der_rustls().as_ref().len(),
        };

        insta::assert_yaml_snapshot!("rustls_x509_chain", meta);
    }

    #[test]
    fn snapshot_rustls_x509_chain_determinism() {
        let fx = fx();
        let c1 = fx.x509_chain("snapshot-chain-det", ChainSpec::new("test.example.com"));
        let c2 = fx.x509_chain("snapshot-chain-det", ChainSpec::new("test.example.com"));

        #[derive(Serialize)]
        struct Determinism {
            description: &'static str,
            same_private_key: bool,
            same_leaf_cert: bool,
            same_root_cert: bool,
            chain_len: usize,
        }

        let result = Determinism {
            description: "X.509 chain determinism",
            same_private_key: c1.private_key_der_rustls().secret_der()
                == c2.private_key_der_rustls().secret_der(),
            same_leaf_cert: c1.certificate_der_rustls().as_ref()
                == c2.certificate_der_rustls().as_ref(),
            same_root_cert: c1.root_certificate_der_rustls().as_ref()
                == c2.root_certificate_der_rustls().as_ref(),
            chain_len: c1.chain_der_rustls().len(),
        };

        insta::assert_yaml_snapshot!("rustls_x509_chain_determinism", result);
    }
}

// =========================================================================
// All key types summary
// =========================================================================

#[cfg(all(feature = "rsa", feature = "ecdsa", feature = "ed25519", feature = "x509"))]
mod all_types_snapshot {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustls::{RustlsCertExt, RustlsChainExt, RustlsPrivateKeyExt};
    use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

    #[derive(Serialize)]
    struct AdapterSummary {
        key_type: &'static str,
        algorithm: &'static str,
        conversion_ok: bool,
        key_format: &'static str,
        private_key_der_len: usize,
    }

    #[test]
    fn snapshot_rustls_all_adapter_summary() {
        let fx = fx();

        let rsa = fx.rsa("summary-rsa", RsaSpec::rs256());
        let ecdsa_p256 = fx.ecdsa("summary-ecdsa-p256", EcdsaSpec::es256());
        let ecdsa_p384 = fx.ecdsa("summary-ecdsa-p384", EcdsaSpec::es384());
        let ed25519 = fx.ed25519("summary-ed25519", Ed25519Spec::new());
        let x509_self = fx.x509_self_signed(
            "summary-x509-self",
            X509Spec::self_signed("test.example.com"),
        );
        let x509_chain = fx.x509_chain("summary-x509-chain", ChainSpec::new("test.example.com"));

        let items: Vec<AdapterSummary> = vec![
            AdapterSummary {
                key_type: "RSA",
                algorithm: "RS256 (2048-bit)",
                conversion_ok: true,
                key_format: "PKCS8",
                private_key_der_len: rsa.private_key_der_rustls().secret_der().len(),
            },
            AdapterSummary {
                key_type: "ECDSA",
                algorithm: "ES256 (P-256)",
                conversion_ok: true,
                key_format: "PKCS8",
                private_key_der_len: ecdsa_p256.private_key_der_rustls().secret_der().len(),
            },
            AdapterSummary {
                key_type: "ECDSA",
                algorithm: "ES384 (P-384)",
                conversion_ok: true,
                key_format: "PKCS8",
                private_key_der_len: ecdsa_p384.private_key_der_rustls().secret_der().len(),
            },
            AdapterSummary {
                key_type: "Ed25519",
                algorithm: "Ed25519",
                conversion_ok: true,
                key_format: "PKCS8",
                private_key_der_len: ed25519.private_key_der_rustls().secret_der().len(),
            },
            AdapterSummary {
                key_type: "X509-SelfSigned",
                algorithm: "ECDSA-P256 (default)",
                conversion_ok: true,
                key_format: "PKCS8",
                private_key_der_len: x509_self.private_key_der_rustls().secret_der().len(),
            },
            AdapterSummary {
                key_type: "X509-Chain",
                algorithm: "ECDSA-P256 (default)",
                conversion_ok: true,
                key_format: "PKCS8",
                private_key_der_len: x509_chain.private_key_der_rustls().secret_der().len(),
            },
        ];

        insta::assert_yaml_snapshot!("rustls_all_adapter_summary", items);
    }
}
