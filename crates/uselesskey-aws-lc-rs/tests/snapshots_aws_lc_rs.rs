//! Insta snapshot tests for uselesskey-aws-lc-rs adapter.
//!
//! These tests snapshot public key material produced by deterministic keys
//! to detect unintended changes in adapter output.
//!
//! Gated on `has_nasm` on Windows (aws-lc-rs requires NASM).

mod testutil;

#[cfg(all(feature = "native", any(not(windows), has_nasm)))]
mod snapshot_tests {
    use crate::testutil::fx;
    use serde::Serialize;

    #[derive(Serialize)]
    struct AwsLcKeySnapshot {
        algorithm: &'static str,
        public_key_hex: String,
        public_key_len: usize,
    }

    #[cfg(feature = "rsa")]
    mod rsa_snapshots {
        use super::*;
        use aws_lc_rs::signature::KeyPair;
        use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;
        use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

        #[test]
        fn snapshot_aws_lc_rsa_2048_public_key() {
            let fx = fx();
            let keypair = fx.rsa("snapshot-rsa", RsaSpec::rs256());
            let aws_kp = keypair.rsa_key_pair_aws_lc_rs();

            let pub_bytes = aws_kp.public_key().as_ref();

            let result = AwsLcKeySnapshot {
                algorithm: "RSA-2048",
                public_key_hex: hex::encode(pub_bytes),
                public_key_len: pub_bytes.len(),
            };

            insta::assert_yaml_snapshot!("aws_lc_rsa_2048_public_key", result, {
                ".public_key_hex" => "[REDACTED]",
            });
        }

        #[test]
        fn snapshot_aws_lc_rsa_modulus_len() {
            let fx = fx();

            #[derive(Serialize)]
            struct RsaModulusInfo {
                label: &'static str,
                bits: usize,
                modulus_len: usize,
            }

            let cases: Vec<RsaModulusInfo> = [(2048, "rsa-2048"), (4096, "rsa-4096")]
                .into_iter()
                .map(|(bits, label)| {
                    let kp = fx.rsa(label, RsaSpec::new(bits));
                    let aws_kp = kp.rsa_key_pair_aws_lc_rs();
                    RsaModulusInfo {
                        label,
                        bits,
                        modulus_len: aws_kp.public_modulus_len(),
                    }
                })
                .collect();

            insta::assert_yaml_snapshot!("aws_lc_rsa_modulus_lengths", cases);
        }

        #[test]
        fn snapshot_aws_lc_rsa_4096_public_key() {
            let fx = fx();
            let keypair = fx.rsa("snapshot-rsa-4096", RsaSpec::new(4096));
            let aws_kp = keypair.rsa_key_pair_aws_lc_rs();

            let pub_bytes = aws_kp.public_key().as_ref();

            let result = AwsLcKeySnapshot {
                algorithm: "RSA-4096",
                public_key_hex: hex::encode(pub_bytes),
                public_key_len: pub_bytes.len(),
            };

            insta::assert_yaml_snapshot!("aws_lc_rsa_4096_public_key", result, {
                ".public_key_hex" => "[REDACTED]",
            });
        }

        #[test]
        fn snapshot_aws_lc_rsa_deterministic_same_label() {
            let fx = fx();

            #[derive(Serialize)]
            struct DeterminismCheck {
                label: &'static str,
                first_modulus_len: usize,
                second_modulus_len: usize,
                lengths_match: bool,
            }

            let kp1 = fx.rsa("determinism-check", RsaSpec::rs256());
            let kp2 = fx.rsa("determinism-check", RsaSpec::rs256());
            let r1 = kp1.rsa_key_pair_aws_lc_rs();
            let r2 = kp2.rsa_key_pair_aws_lc_rs();

            let result = DeterminismCheck {
                label: "determinism-check",
                first_modulus_len: r1.public_modulus_len(),
                second_modulus_len: r2.public_modulus_len(),
                lengths_match: r1.public_modulus_len() == r2.public_modulus_len(),
            };

            insta::assert_yaml_snapshot!("aws_lc_rsa_deterministic_same_label", result);
        }
    }

    #[cfg(feature = "ecdsa")]
    mod ecdsa_snapshots {
        use super::*;
        use aws_lc_rs::signature::KeyPair;
        use uselesskey_aws_lc_rs::AwsLcRsEcdsaKeyPairExt;
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

        #[test]
        fn snapshot_aws_lc_ecdsa_p256_public_key() {
            let fx = fx();
            let keypair = fx.ecdsa("snapshot-ecdsa-p256", EcdsaSpec::es256());
            let aws_kp = keypair.ecdsa_key_pair_aws_lc_rs();

            let pub_bytes = aws_kp.public_key().as_ref();

            let result = AwsLcKeySnapshot {
                algorithm: "ECDSA-P256",
                public_key_hex: hex::encode(pub_bytes),
                public_key_len: pub_bytes.len(),
            };

            insta::assert_yaml_snapshot!("aws_lc_ecdsa_p256_public_key", result, {
                ".public_key_hex" => "[REDACTED]",
            });
        }

        #[test]
        fn snapshot_aws_lc_ecdsa_p384_public_key() {
            let fx = fx();
            let keypair = fx.ecdsa("snapshot-ecdsa-p384", EcdsaSpec::es384());
            let aws_kp = keypair.ecdsa_key_pair_aws_lc_rs();

            let pub_bytes = aws_kp.public_key().as_ref();

            let result = AwsLcKeySnapshot {
                algorithm: "ECDSA-P384",
                public_key_hex: hex::encode(pub_bytes),
                public_key_len: pub_bytes.len(),
            };

            insta::assert_yaml_snapshot!("aws_lc_ecdsa_p384_public_key", result, {
                ".public_key_hex" => "[REDACTED]",
            });
        }

        #[test]
        fn snapshot_aws_lc_ecdsa_key_sizes() {
            let fx = fx();

            #[derive(Serialize)]
            struct EcdsaSizeInfo {
                curve: &'static str,
                public_key_len: usize,
            }

            let cases: Vec<EcdsaSizeInfo> = vec![
                {
                    let kp = fx.ecdsa("sizes-p256", EcdsaSpec::es256());
                    let aws_kp = kp.ecdsa_key_pair_aws_lc_rs();
                    EcdsaSizeInfo {
                        curve: "P-256",
                        public_key_len: aws_kp.public_key().as_ref().len(),
                    }
                },
                {
                    let kp = fx.ecdsa("sizes-p384", EcdsaSpec::es384());
                    let aws_kp = kp.ecdsa_key_pair_aws_lc_rs();
                    EcdsaSizeInfo {
                        curve: "P-384",
                        public_key_len: aws_kp.public_key().as_ref().len(),
                    }
                },
            ];

            insta::assert_yaml_snapshot!("aws_lc_ecdsa_key_sizes", cases);
        }
    }

    #[cfg(feature = "ed25519")]
    mod ed25519_snapshots {
        use super::*;
        use aws_lc_rs::signature::KeyPair;
        use uselesskey_aws_lc_rs::AwsLcRsEd25519KeyPairExt;
        use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

        #[test]
        fn snapshot_aws_lc_ed25519_public_key() {
            let fx = fx();
            let keypair = fx.ed25519("snapshot-ed25519", Ed25519Spec::new());
            let aws_kp = keypair.ed25519_key_pair_aws_lc_rs();

            let pub_bytes = aws_kp.public_key().as_ref();

            let result = AwsLcKeySnapshot {
                algorithm: "Ed25519",
                public_key_hex: hex::encode(pub_bytes),
                public_key_len: pub_bytes.len(),
            };

            insta::assert_yaml_snapshot!("aws_lc_ed25519_public_key", result, {
                ".public_key_hex" => "[REDACTED]",
            });
        }

        #[test]
        fn snapshot_aws_lc_ed25519_key_len_invariant() {
            let fx = fx();

            #[derive(Serialize)]
            struct Ed25519LenInfo {
                label: &'static str,
                public_key_len: usize,
            }

            let cases: Vec<Ed25519LenInfo> = ["ed-len-a", "ed-len-b", "ed-len-c"]
                .into_iter()
                .map(|label| {
                    let kp = fx.ed25519(label, Ed25519Spec::new());
                    let aws_kp = kp.ed25519_key_pair_aws_lc_rs();
                    Ed25519LenInfo {
                        label,
                        public_key_len: aws_kp.public_key().as_ref().len(),
                    }
                })
                .collect();

            insta::assert_yaml_snapshot!("aws_lc_ed25519_key_len_invariant", cases);
        }
    }
}
