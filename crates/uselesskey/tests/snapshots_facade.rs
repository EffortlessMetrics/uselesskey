//! Insta snapshot tests for the uselesskey facade crate.
//!
//! These tests snapshot key shapes produced through the public facade API
//! to detect unintended changes in re-exported outputs.

mod testutil;

use serde::Serialize;
use testutil::fx;

#[derive(Serialize)]
struct KeyShape {
    algorithm: &'static str,
    private_key_pem_header: &'static str,
    private_key_der_len: usize,
    public_key_pem_header: &'static str,
    public_key_der_len: usize,
}

#[cfg(feature = "rsa")]
mod rsa_snapshots {
    use super::*;
    use uselesskey::{RsaFactoryExt, RsaSpec};

    #[test]
    fn snapshot_facade_rsa_2048_shape() {
        let fx = fx();
        let kp = fx.rsa("snapshot-rsa", RsaSpec::rs256());

        let result = KeyShape {
            algorithm: "RSA-2048",
            private_key_pem_header: "-----BEGIN PRIVATE KEY-----",
            private_key_der_len: kp.private_key_pkcs8_der().len(),
            public_key_pem_header: "-----BEGIN PUBLIC KEY-----",
            public_key_der_len: kp.public_key_spki_der().len(),
        };

        insta::assert_yaml_snapshot!("facade_rsa_2048_shape", result);
    }

    #[test]
    fn snapshot_facade_rsa_pem_headers() {
        let fx = fx();
        let kp = fx.rsa("snapshot-rsa-pem", RsaSpec::rs256());

        #[derive(Serialize)]
        struct PemHeaders {
            private_starts_with: bool,
            public_starts_with: bool,
        }

        let result = PemHeaders {
            private_starts_with: kp
                .private_key_pkcs8_pem()
                .starts_with("-----BEGIN PRIVATE KEY-----"),
            public_starts_with: kp
                .public_key_spki_pem()
                .starts_with("-----BEGIN PUBLIC KEY-----"),
        };

        insta::assert_yaml_snapshot!("facade_rsa_pem_headers", result);
    }
}

#[cfg(feature = "ecdsa")]
mod ecdsa_snapshots {
    use super::*;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn snapshot_facade_ecdsa_p256_shape() {
        let fx = fx();
        let kp = fx.ecdsa("snapshot-ecdsa-p256", EcdsaSpec::es256());

        let result = KeyShape {
            algorithm: "ECDSA-P256",
            private_key_pem_header: "-----BEGIN PRIVATE KEY-----",
            private_key_der_len: kp.private_key_pkcs8_der().len(),
            public_key_pem_header: "-----BEGIN PUBLIC KEY-----",
            public_key_der_len: kp.public_key_spki_der().len(),
        };

        insta::assert_yaml_snapshot!("facade_ecdsa_p256_shape", result);
    }

    #[test]
    fn snapshot_facade_ecdsa_p384_shape() {
        let fx = fx();
        let kp = fx.ecdsa("snapshot-ecdsa-p384", EcdsaSpec::es384());

        let result = KeyShape {
            algorithm: "ECDSA-P384",
            private_key_pem_header: "-----BEGIN PRIVATE KEY-----",
            private_key_der_len: kp.private_key_pkcs8_der().len(),
            public_key_pem_header: "-----BEGIN PUBLIC KEY-----",
            public_key_der_len: kp.public_key_spki_der().len(),
        };

        insta::assert_yaml_snapshot!("facade_ecdsa_p384_shape", result);
    }
}

#[cfg(feature = "ed25519")]
mod ed25519_snapshots {
    use super::*;
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn snapshot_facade_ed25519_shape() {
        let fx = fx();
        let kp = fx.ed25519("snapshot-ed25519", Ed25519Spec::new());

        let result = KeyShape {
            algorithm: "Ed25519",
            private_key_pem_header: "-----BEGIN PRIVATE KEY-----",
            private_key_der_len: kp.private_key_pkcs8_der().len(),
            public_key_pem_header: "-----BEGIN PUBLIC KEY-----",
            public_key_der_len: kp.public_key_spki_der().len(),
        };

        insta::assert_yaml_snapshot!("facade_ed25519_shape", result);
    }
}

#[cfg(feature = "hmac")]
mod hmac_snapshots {
    use super::*;
    use uselesskey::{HmacFactoryExt, HmacSpec};

    #[test]
    fn snapshot_facade_hmac_shapes() {
        let fx = fx();

        #[derive(Serialize)]
        struct HmacShape {
            algorithm: &'static str,
            secret_len: usize,
        }

        let cases: Vec<HmacShape> = vec![
            {
                let s = fx.hmac("snapshot-hs256", HmacSpec::hs256());
                HmacShape {
                    algorithm: "HS256",
                    secret_len: s.secret_bytes().len(),
                }
            },
            {
                let s = fx.hmac("snapshot-hs384", HmacSpec::hs384());
                HmacShape {
                    algorithm: "HS384",
                    secret_len: s.secret_bytes().len(),
                }
            },
            {
                let s = fx.hmac("snapshot-hs512", HmacSpec::hs512());
                HmacShape {
                    algorithm: "HS512",
                    secret_len: s.secret_bytes().len(),
                }
            },
        ];

        insta::assert_yaml_snapshot!("facade_hmac_shapes", cases);
    }
}

#[cfg(feature = "token")]
mod token_snapshots {
    use super::*;
    use uselesskey::{TokenFactoryExt, TokenSpec};

    #[test]
    fn snapshot_facade_token_shapes() {
        let fx = fx();

        #[derive(Serialize)]
        struct TokenShape {
            kind: &'static str,
            value_len: usize,
            value_non_empty: bool,
        }

        let cases: Vec<TokenShape> = vec![
            {
                let t = fx.token("snapshot-api-key", TokenSpec::api_key());
                TokenShape {
                    kind: "api_key",
                    value_len: t.value().len(),
                    value_non_empty: !t.value().is_empty(),
                }
            },
            {
                let t = fx.token("snapshot-bearer", TokenSpec::bearer());
                TokenShape {
                    kind: "bearer",
                    value_len: t.value().len(),
                    value_non_empty: !t.value().is_empty(),
                }
            },
            {
                let t = fx.token("snapshot-oauth", TokenSpec::oauth_access_token());
                TokenShape {
                    kind: "oauth_access_token",
                    value_len: t.value().len(),
                    value_non_empty: !t.value().is_empty(),
                }
            },
        ];

        insta::assert_yaml_snapshot!("facade_token_shapes", cases);
    }
}

#[cfg(feature = "x509")]
mod x509_snapshots {
    use super::*;
    use uselesskey::{ChainSpec, X509FactoryExt, X509Spec};

    #[test]
    fn snapshot_facade_x509_self_signed_shape() {
        let fx = fx();
        let cert = fx.x509_self_signed("snapshot-x509", X509Spec::self_signed("test.example.com"));

        #[derive(Serialize)]
        struct X509Shape {
            cert_der_len: usize,
            private_key_der_len: usize,
            cert_pem_starts_with: bool,
            key_pem_starts_with: bool,
        }

        let result = X509Shape {
            cert_der_len: cert.cert_der().len(),
            private_key_der_len: cert.private_key_pkcs8_der().len(),
            cert_pem_starts_with: cert.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"),
            key_pem_starts_with: cert
                .private_key_pkcs8_pem()
                .starts_with("-----BEGIN PRIVATE KEY-----"),
        };

        insta::assert_yaml_snapshot!("facade_x509_self_signed_shape", result);
    }

    #[test]
    fn snapshot_facade_x509_chain_shape() {
        let fx = fx();
        let chain = fx.x509_chain("snapshot-chain", ChainSpec::new("test.example.com"));

        #[derive(Serialize)]
        struct ChainShape {
            root_cert_der_len: usize,
            intermediate_cert_der_len: usize,
            leaf_cert_der_len: usize,
            leaf_private_key_der_len: usize,
            chain_pem_cert_count: usize,
            full_chain_pem_cert_count: usize,
        }

        let result = ChainShape {
            root_cert_der_len: chain.root_cert_der().len(),
            intermediate_cert_der_len: chain.intermediate_cert_der().len(),
            leaf_cert_der_len: chain.leaf_cert_der().len(),
            leaf_private_key_der_len: chain.leaf_private_key_pkcs8_der().len(),
            chain_pem_cert_count: chain
                .chain_pem()
                .matches("-----BEGIN CERTIFICATE-----")
                .count(),
            full_chain_pem_cert_count: chain
                .full_chain_pem()
                .matches("-----BEGIN CERTIFICATE-----")
                .count(),
        };

        insta::assert_yaml_snapshot!("facade_x509_chain_shape", result);
    }
}
