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
            bits: u32,
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
}
