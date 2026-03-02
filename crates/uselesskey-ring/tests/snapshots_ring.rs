//! Insta snapshot tests for uselesskey-ring adapter.
//!
//! These tests snapshot public key material produced by deterministic keys
//! to detect unintended changes in adapter output.

mod testutil;

use serde::Serialize;
use testutil::fx;

#[derive(Serialize)]
struct RingKeySnapshot {
    algorithm: &'static str,
    public_key_hex: String,
    public_key_len: usize,
}

#[cfg(feature = "rsa")]
mod rsa_snapshots {
    use super::*;
    use uselesskey_ring::RingRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn snapshot_ring_rsa_2048_public_key() {
        let fx = fx();
        let keypair = fx.rsa("snapshot-rsa", RsaSpec::rs256());
        let ring_kp = keypair.rsa_key_pair_ring();

        let pub_bytes = ring_kp.public().as_ref();

        let result = RingKeySnapshot {
            algorithm: "RSA-2048",
            public_key_hex: hex::encode(pub_bytes),
            public_key_len: pub_bytes.len(),
        };

        insta::assert_yaml_snapshot!("ring_rsa_2048_public_key", result, {
            ".public_key_hex" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_ring_rsa_modulus_len() {
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
                let ring_kp = kp.rsa_key_pair_ring();
                RsaModulusInfo {
                    label,
                    bits,
                    modulus_len: ring_kp.public().modulus_len(),
                }
            })
            .collect();

        insta::assert_yaml_snapshot!("ring_rsa_modulus_lengths", cases);
    }

    #[test]
    fn snapshot_ring_rsa_4096_public_key() {
        let fx = fx();
        let keypair = fx.rsa("snapshot-rsa-4096", RsaSpec::new(4096));
        let ring_kp = keypair.rsa_key_pair_ring();

        let pub_bytes = ring_kp.public().as_ref();

        let result = RingKeySnapshot {
            algorithm: "RSA-4096",
            public_key_hex: hex::encode(pub_bytes),
            public_key_len: pub_bytes.len(),
        };

        insta::assert_yaml_snapshot!("ring_rsa_4096_public_key", result, {
            ".public_key_hex" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_ring_rsa_deterministic_same_label() {
        let fx = fx();

        #[derive(Serialize)]
        struct DeterminismCheck {
            label: &'static str,
            first_modulus_len: usize,
            second_modulus_len: usize,
            first_pub_len: usize,
            second_pub_len: usize,
            lengths_match: bool,
        }

        let kp1 = fx.rsa("determinism-check", RsaSpec::rs256());
        let kp2 = fx.rsa("determinism-check", RsaSpec::rs256());
        let r1 = kp1.rsa_key_pair_ring();
        let r2 = kp2.rsa_key_pair_ring();

        let result = DeterminismCheck {
            label: "determinism-check",
            first_modulus_len: r1.public().modulus_len(),
            second_modulus_len: r2.public().modulus_len(),
            first_pub_len: r1.public().as_ref().len(),
            second_pub_len: r2.public().as_ref().len(),
            lengths_match: r1.public().as_ref().len() == r2.public().as_ref().len(),
        };

        insta::assert_yaml_snapshot!("ring_rsa_deterministic_same_label", result);
    }
}

#[cfg(feature = "ecdsa")]
mod ecdsa_snapshots {
    use super::*;
    use ring::signature::KeyPair;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ring::RingEcdsaKeyPairExt;

    #[test]
    fn snapshot_ring_ecdsa_p256_public_key() {
        let fx = fx();
        let keypair = fx.ecdsa("snapshot-ecdsa-p256", EcdsaSpec::es256());
        let ring_kp = keypair.ecdsa_key_pair_ring();

        let pub_bytes = ring_kp.public_key().as_ref();

        let result = RingKeySnapshot {
            algorithm: "ECDSA-P256",
            public_key_hex: hex::encode(pub_bytes),
            public_key_len: pub_bytes.len(),
        };

        insta::assert_yaml_snapshot!("ring_ecdsa_p256_public_key", result, {
            ".public_key_hex" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_ring_ecdsa_p384_public_key() {
        let fx = fx();
        let keypair = fx.ecdsa("snapshot-ecdsa-p384", EcdsaSpec::es384());
        let ring_kp = keypair.ecdsa_key_pair_ring();

        let pub_bytes = ring_kp.public_key().as_ref();

        let result = RingKeySnapshot {
            algorithm: "ECDSA-P384",
            public_key_hex: hex::encode(pub_bytes),
            public_key_len: pub_bytes.len(),
        };

        insta::assert_yaml_snapshot!("ring_ecdsa_p384_public_key", result, {
            ".public_key_hex" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_ring_ecdsa_key_sizes() {
        let fx = fx();

        #[derive(Serialize)]
        struct EcdsaSizeInfo {
            curve: &'static str,
            public_key_len: usize,
        }

        let cases: Vec<EcdsaSizeInfo> = vec![
            {
                let kp = fx.ecdsa("sizes-p256", EcdsaSpec::es256());
                let ring_kp = kp.ecdsa_key_pair_ring();
                EcdsaSizeInfo {
                    curve: "P-256",
                    public_key_len: ring_kp.public_key().as_ref().len(),
                }
            },
            {
                let kp = fx.ecdsa("sizes-p384", EcdsaSpec::es384());
                let ring_kp = kp.ecdsa_key_pair_ring();
                EcdsaSizeInfo {
                    curve: "P-384",
                    public_key_len: ring_kp.public_key().as_ref().len(),
                }
            },
        ];

        insta::assert_yaml_snapshot!("ring_ecdsa_key_sizes", cases);
    }

    #[test]
    fn snapshot_ring_ecdsa_different_labels() {
        let fx = fx();

        #[derive(Serialize)]
        struct EcdsaLabelCheck {
            curve: &'static str,
            label_a_pub_len: usize,
            label_b_pub_len: usize,
            same_curve_same_size: bool,
        }

        let kp_a = fx.ecdsa("label-a-p256", EcdsaSpec::es256());
        let kp_b = fx.ecdsa("label-b-p256", EcdsaSpec::es256());
        let ring_a = kp_a.ecdsa_key_pair_ring();
        let ring_b = kp_b.ecdsa_key_pair_ring();

        let result = EcdsaLabelCheck {
            curve: "P-256",
            label_a_pub_len: ring_a.public_key().as_ref().len(),
            label_b_pub_len: ring_b.public_key().as_ref().len(),
            same_curve_same_size: ring_a.public_key().as_ref().len()
                == ring_b.public_key().as_ref().len(),
        };

        insta::assert_yaml_snapshot!("ring_ecdsa_different_labels", result);
    }
}

#[cfg(feature = "ed25519")]
mod ed25519_snapshots {
    use super::*;
    use ring::signature::KeyPair;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_ring::RingEd25519KeyPairExt;

    #[test]
    fn snapshot_ring_ed25519_public_key() {
        let fx = fx();
        let keypair = fx.ed25519("snapshot-ed25519", Ed25519Spec::new());
        let ring_kp = keypair.ed25519_key_pair_ring();

        let pub_bytes = ring_kp.public_key().as_ref();

        let result = RingKeySnapshot {
            algorithm: "Ed25519",
            public_key_hex: hex::encode(pub_bytes),
            public_key_len: pub_bytes.len(),
        };

        insta::assert_yaml_snapshot!("ring_ed25519_public_key", result, {
            ".public_key_hex" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_ring_ed25519_key_len_invariant() {
        let fx = fx();

        #[derive(Serialize)]
        struct Ed25519LenInfo {
            label: &'static str,
            public_key_len: usize,
        }

        let cases: Vec<Ed25519LenInfo> = ["ed-label-a", "ed-label-b", "ed-label-c"]
            .into_iter()
            .map(|label| {
                let kp = fx.ed25519(label, Ed25519Spec::new());
                let ring_kp = kp.ed25519_key_pair_ring();
                Ed25519LenInfo {
                    label,
                    public_key_len: ring_kp.public_key().as_ref().len(),
                }
            })
            .collect();

        insta::assert_yaml_snapshot!("ring_ed25519_key_len_invariant", cases);
    }
}
