//! Insta snapshot tests for uselesskey-rustcrypto adapter.
//!
//! These tests snapshot key material shapes produced by deterministic keys
//! to detect unintended changes in adapter output.

mod testutil;

use serde::Serialize;
use testutil::fx;

#[derive(Serialize)]
struct RustCryptoKeySnapshot {
    algorithm: &'static str,
    public_key_hex: String,
    public_key_len: usize,
}

#[cfg(feature = "rsa")]
mod rsa_snapshots {
    use super::*;
    use rsa::traits::PublicKeyParts;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustcrypto::RustCryptoRsaExt;

    #[test]
    fn snapshot_rustcrypto_rsa_2048_public_key() {
        let fx = fx();
        let keypair = fx.rsa("snapshot-rsa", RsaSpec::rs256());

        let public_key = keypair.rsa_public_key();
        let modulus_bits = public_key.n().bits();

        #[derive(Serialize)]
        struct RsaInfo {
            algorithm: &'static str,
            modulus_bits: u32,
            e_hex: String,
        }

        let result = RsaInfo {
            algorithm: "RSA-2048",
            modulus_bits: modulus_bits as u32,
            e_hex: format!("{:x}", public_key.e()),
        };

        insta::assert_yaml_snapshot!("rustcrypto_rsa_2048_public_key", result);
    }

    #[test]
    fn snapshot_rustcrypto_rsa_key_sizes() {
        let fx = fx();

        #[derive(Serialize)]
        struct RsaSizeInfo {
            label: &'static str,
            bits: usize,
            modulus_bits: u32,
        }

        let cases: Vec<RsaSizeInfo> = [(2048, "rsa-2048"), (4096, "rsa-4096")]
            .into_iter()
            .map(|(bits, label)| {
                let kp = fx.rsa(label, RsaSpec::new(bits));
                let public_key = kp.rsa_public_key();
                RsaSizeInfo {
                    label,
                    bits,
                    modulus_bits: public_key.n().bits() as u32,
                }
            })
            .collect();

        insta::assert_yaml_snapshot!("rustcrypto_rsa_key_sizes", cases);
    }

    #[test]
    fn snapshot_rustcrypto_rsa_4096_public_key() {
        let fx = fx();
        let keypair = fx.rsa("snapshot-rsa-4096", RsaSpec::new(4096));

        let public_key = keypair.rsa_public_key();
        let modulus_bits = public_key.n().bits();

        #[derive(Serialize)]
        struct RsaInfo {
            algorithm: &'static str,
            modulus_bits: u32,
            e_hex: String,
        }

        let result = RsaInfo {
            algorithm: "RSA-4096",
            modulus_bits: modulus_bits as u32,
            e_hex: format!("{:x}", public_key.e()),
        };

        insta::assert_yaml_snapshot!("rustcrypto_rsa_4096_public_key", result);
    }
}

#[cfg(feature = "ecdsa")]
mod ecdsa_snapshots {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_rustcrypto::RustCryptoEcdsaExt;

    #[test]
    fn snapshot_rustcrypto_ecdsa_p256_verifying_key() {
        let fx = fx();
        let keypair = fx.ecdsa("snapshot-ecdsa-p256", EcdsaSpec::es256());

        let vk = keypair.p256_verifying_key();
        let point = vk.to_encoded_point(false);
        let pub_bytes = point.as_bytes();

        let result = RustCryptoKeySnapshot {
            algorithm: "ECDSA-P256",
            public_key_hex: hex::encode(pub_bytes),
            public_key_len: pub_bytes.len(),
        };

        insta::assert_yaml_snapshot!("rustcrypto_ecdsa_p256_verifying_key", result, {
            ".public_key_hex" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_rustcrypto_ecdsa_p384_verifying_key() {
        let fx = fx();
        let keypair = fx.ecdsa("snapshot-ecdsa-p384", EcdsaSpec::es384());

        let vk = keypair.p384_verifying_key();
        let point = vk.to_encoded_point(false);
        let pub_bytes = point.as_bytes();

        let result = RustCryptoKeySnapshot {
            algorithm: "ECDSA-P384",
            public_key_hex: hex::encode(pub_bytes),
            public_key_len: pub_bytes.len(),
        };

        insta::assert_yaml_snapshot!("rustcrypto_ecdsa_p384_verifying_key", result, {
            ".public_key_hex" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_rustcrypto_ecdsa_key_sizes() {
        let fx = fx();

        #[derive(Serialize)]
        struct EcdsaSizeInfo {
            curve: &'static str,
            verifying_key_len: usize,
        }

        let cases: Vec<EcdsaSizeInfo> = vec![
            {
                let kp = fx.ecdsa("sizes-p256", EcdsaSpec::es256());
                let vk = kp.p256_verifying_key();
                let point = vk.to_encoded_point(false);
                EcdsaSizeInfo {
                    curve: "P-256",
                    verifying_key_len: point.as_bytes().len(),
                }
            },
            {
                let kp = fx.ecdsa("sizes-p384", EcdsaSpec::es384());
                let vk = kp.p384_verifying_key();
                let point = vk.to_encoded_point(false);
                EcdsaSizeInfo {
                    curve: "P-384",
                    verifying_key_len: point.as_bytes().len(),
                }
            },
        ];

        insta::assert_yaml_snapshot!("rustcrypto_ecdsa_key_sizes", cases);
    }
}

#[cfg(feature = "ed25519")]
mod ed25519_snapshots {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rustcrypto::RustCryptoEd25519Ext;

    #[test]
    fn snapshot_rustcrypto_ed25519_verifying_key() {
        let fx = fx();
        let keypair = fx.ed25519("snapshot-ed25519", Ed25519Spec::new());

        let vk = keypair.ed25519_verifying_key();
        let pub_bytes = vk.as_bytes();

        let result = RustCryptoKeySnapshot {
            algorithm: "Ed25519",
            public_key_hex: hex::encode(pub_bytes),
            public_key_len: pub_bytes.len(),
        };

        insta::assert_yaml_snapshot!("rustcrypto_ed25519_verifying_key", result, {
            ".public_key_hex" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_rustcrypto_ed25519_key_len_invariant() {
        let fx = fx();

        #[derive(Serialize)]
        struct Ed25519LenInfo {
            label: &'static str,
            verifying_key_len: usize,
        }

        let cases: Vec<Ed25519LenInfo> = ["ed-len-a", "ed-len-b", "ed-len-c"]
            .into_iter()
            .map(|label| {
                let kp = fx.ed25519(label, Ed25519Spec::new());
                let vk = kp.ed25519_verifying_key();
                Ed25519LenInfo {
                    label,
                    verifying_key_len: vk.as_bytes().len(),
                }
            })
            .collect();

        insta::assert_yaml_snapshot!("rustcrypto_ed25519_key_len_invariant", cases);
    }
}

#[cfg(feature = "hmac")]
mod hmac_snapshots {
    use super::*;
    use hmac::Mac;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    use uselesskey_rustcrypto::RustCryptoHmacExt;

    #[test]
    fn snapshot_rustcrypto_hmac_sha256_tag() {
        let fx = fx();
        let secret = fx.hmac("snapshot-hmac", HmacSpec::hs256());

        let mut mac = secret.hmac_sha256();
        mac.update(b"snapshot-test-message");
        let tag = mac.finalize().into_bytes();

        #[derive(Serialize)]
        struct HmacInfo {
            algorithm: &'static str,
            tag_hex: String,
            tag_len: usize,
        }

        let result = HmacInfo {
            algorithm: "HMAC-SHA256",
            tag_hex: hex::encode(tag),
            tag_len: tag.len(),
        };

        insta::assert_yaml_snapshot!("rustcrypto_hmac_sha256_tag", result, {
            ".tag_hex" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_rustcrypto_hmac_sha384_tag() {
        let fx = fx();
        let secret = fx.hmac("snapshot-hmac-384", HmacSpec::hs384());

        let mut mac = secret.hmac_sha384();
        mac.update(b"snapshot-test-message");
        let tag = mac.finalize().into_bytes();

        #[derive(Serialize)]
        struct HmacInfo {
            algorithm: &'static str,
            tag_hex: String,
            tag_len: usize,
        }

        let result = HmacInfo {
            algorithm: "HMAC-SHA384",
            tag_hex: hex::encode(tag),
            tag_len: tag.len(),
        };

        insta::assert_yaml_snapshot!("rustcrypto_hmac_sha384_tag", result, {
            ".tag_hex" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_rustcrypto_hmac_sha512_tag() {
        let fx = fx();
        let secret = fx.hmac("snapshot-hmac-512", HmacSpec::hs512());

        let mut mac = secret.hmac_sha512();
        mac.update(b"snapshot-test-message");
        let tag = mac.finalize().into_bytes();

        #[derive(Serialize)]
        struct HmacInfo {
            algorithm: &'static str,
            tag_hex: String,
            tag_len: usize,
        }

        let result = HmacInfo {
            algorithm: "HMAC-SHA512",
            tag_hex: hex::encode(tag),
            tag_len: tag.len(),
        };

        insta::assert_yaml_snapshot!("rustcrypto_hmac_sha512_tag", result, {
            ".tag_hex" => "[REDACTED]",
        });
    }

    #[test]
    fn snapshot_rustcrypto_hmac_all_tag_sizes() {
        let fx = fx();

        #[derive(Serialize)]
        struct HmacTagSize {
            algorithm: &'static str,
            tag_len: usize,
        }

        let cases: Vec<HmacTagSize> = vec![
            {
                let secret = fx.hmac("tag-sizes-256", HmacSpec::hs256());
                let mut mac = secret.hmac_sha256();
                mac.update(b"test");
                HmacTagSize {
                    algorithm: "HMAC-SHA256",
                    tag_len: mac.finalize().into_bytes().len(),
                }
            },
            {
                let secret = fx.hmac("tag-sizes-384", HmacSpec::hs384());
                let mut mac = secret.hmac_sha384();
                mac.update(b"test");
                HmacTagSize {
                    algorithm: "HMAC-SHA384",
                    tag_len: mac.finalize().into_bytes().len(),
                }
            },
            {
                let secret = fx.hmac("tag-sizes-512", HmacSpec::hs512());
                let mut mac = secret.hmac_sha512();
                mac.update(b"test");
                HmacTagSize {
                    algorithm: "HMAC-SHA512",
                    tag_len: mac.finalize().into_bytes().len(),
                }
            },
        ];

        insta::assert_yaml_snapshot!("rustcrypto_hmac_all_tag_sizes", cases);
    }
}
