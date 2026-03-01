//! Insta snapshot tests for cross-backend interop metadata.
//!
//! These tests perform real sign/verify round-trips across crypto backends
//! and snapshot **only metadata** (algorithm, backend names, signature sizes).
//! Key material is never snapshotted.

use std::sync::OnceLock;

use serde::Serialize;
use uselesskey_core::{Factory, Seed};

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> &'static Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-interop-test-seed-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
}

// ---------------------------------------------------------------------------
// ASN.1 helpers (duplicated from interop.rs — each test file is a separate
// crate, so sharing helpers requires a lib target or a `mod` include).
// ---------------------------------------------------------------------------

/// Extract the raw public key bytes from a DER-encoded SPKI structure.
fn extract_public_key_from_spki(spki_der: &[u8]) -> &[u8] {
    let (_, rest) = skip_tag_and_length(spki_der);
    let (inner_len, rest) = skip_tag_and_length(rest);
    let rest = &rest[inner_len..];
    assert_eq!(rest[0], 0x03, "expected BIT STRING tag");
    let (bit_string_len, rest) = skip_tag_and_length(rest);
    assert_eq!(rest[0], 0x00, "expected 0 unused bits");
    &rest[1..bit_string_len]
}

fn skip_tag_and_length(data: &[u8]) -> (usize, &[u8]) {
    let data = &data[1..];
    if data[0] & 0x80 == 0 {
        let len = data[0] as usize;
        (len, &data[1..])
    } else {
        let num_bytes = (data[0] & 0x7f) as usize;
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }
        (len, &data[1 + num_bytes..])
    }
}

// ---------------------------------------------------------------------------
// Shared snapshot struct
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct InteropRoundTrip {
    key_type: &'static str,
    algorithm: &'static str,
    signer_backend: &'static str,
    verifier_backend: &'static str,
    signature_len: usize,
    success: bool,
}

// ===========================================================================
// Ring → RustCrypto  (reverse of the existing interop.rs direction)
// ===========================================================================

mod ring_to_p256 {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use ring::rand::SystemRandom;
    use ring::signature as ring_sig;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn ring_sign_p256_verify() {
        let fx = fx();
        let keypair = fx.ecdsa("snap-interop-ecdsa-r2p", EcdsaSpec::es256());

        let rng = SystemRandom::new();
        let key_pair = ring_sig::EcdsaKeyPair::from_pkcs8(
            &ring_sig::ECDSA_P256_SHA256_ASN1_SIGNING,
            keypair.private_key_pkcs8_der(),
            &rng,
        )
        .expect("ring should parse ECDSA PKCS#8");

        let message = b"ring-to-p256 interop snapshot test";
        let sig = key_pair
            .sign(&rng, message)
            .expect("ring ECDSA signing should succeed");

        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let verifying_key =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(raw_pubkey).expect("valid P-256 point");
        let der_sig =
            p256::ecdsa::DerSignature::from_bytes(sig.as_ref()).expect("valid DER signature");
        verifying_key
            .verify(message, &der_sig)
            .expect("p256 should verify ring-signed ECDSA signature");

        let result = InteropRoundTrip {
            key_type: "ECDSA",
            algorithm: "P-256/SHA-256",
            signer_backend: "ring",
            verifier_backend: "p256 (RustCrypto)",
            signature_len: sig.as_ref().len(),
            success: true,
        };
        insta::assert_yaml_snapshot!("ring_to_p256_ecdsa_round_trip", result, {
            // Ring uses random nonces for ECDSA, so DER signature length varies.
            ".signature_len" => "[VARIABLE_DER_LEN]",
        });
    }
}

mod ring_to_dalek {
    use super::*;
    use ed25519_dalek::Verifier;
    use ring::signature as ring_sig;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn ring_sign_dalek_verify() {
        let fx = fx();
        let keypair = fx.ed25519("snap-interop-ed25519-r2d", Ed25519Spec::new());

        let key_pair =
            ring_sig::Ed25519KeyPair::from_pkcs8_maybe_unchecked(keypair.private_key_pkcs8_der())
                .expect("ring should parse Ed25519 PKCS#8");

        let message = b"ring-to-dalek interop snapshot test";
        let sig = key_pair.sign(message);

        let raw_public_key = extract_public_key_from_spki(keypair.public_key_spki_der());
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
            raw_public_key
                .try_into()
                .expect("Ed25519 key should be 32 bytes"),
        )
        .expect("valid Ed25519 public key");
        let dalek_sig = ed25519_dalek::Signature::from_bytes(
            sig.as_ref()
                .try_into()
                .expect("Ed25519 sig should be 64 bytes"),
        );
        verifying_key
            .verify(message, &dalek_sig)
            .expect("dalek should verify ring-signed Ed25519 signature");

        let result = InteropRoundTrip {
            key_type: "Ed25519",
            algorithm: "Ed25519",
            signer_backend: "ring",
            verifier_backend: "ed25519-dalek",
            signature_len: sig.as_ref().len(),
            success: true,
        };
        insta::assert_yaml_snapshot!("ring_to_dalek_ed25519_round_trip", result);
    }
}

mod ring_to_rsa_crate {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature as ring_sig;
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::signature::Verifier;
    use sha2::Sha256;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn ring_sign_rsa_crate_verify() {
        let fx = fx();
        let keypair = fx.rsa("snap-interop-rsa-r2rc", RsaSpec::rs256());

        let key_pair = ring_sig::RsaKeyPair::from_pkcs8(keypair.private_key_pkcs8_der())
            .expect("ring should parse RSA PKCS#8");

        let rng = SystemRandom::new();
        let message = b"ring-to-rsa-crate interop snapshot test";
        let mut sig_buf = vec![0u8; key_pair.public().modulus_len()];
        key_pair
            .sign(&ring_sig::RSA_PKCS1_SHA256, &rng, message, &mut sig_buf)
            .expect("ring RSA signing should succeed");

        // The raw public key inside the SPKI BIT STRING is PKCS#1 DER.
        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key =
            rsa::RsaPublicKey::from_pkcs1_der(raw_pubkey).expect("valid RSA PKCS#1 DER");
        let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
        let rsa_sig =
            rsa::pkcs1v15::Signature::try_from(sig_buf.as_slice()).expect("valid RSA signature");
        verifying_key
            .verify(message, &rsa_sig)
            .expect("rsa crate should verify ring-signed RSA signature");

        let result = InteropRoundTrip {
            key_type: "RSA",
            algorithm: "RSA-PKCS1v15-SHA256",
            signer_backend: "ring",
            verifier_backend: "rsa (RustCrypto)",
            signature_len: sig_buf.len(),
            success: true,
        };
        insta::assert_yaml_snapshot!("ring_to_rsa_crate_round_trip", result);
    }
}

// ===========================================================================
// RustCrypto → Ring  (snapshot metadata for the existing direction)
// ===========================================================================

mod p256_to_ring {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::DecodePrivateKey;
    use ring::signature::{self, UnparsedPublicKey};
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn p256_sign_ring_verify_snapshot() {
        let fx = fx();
        let keypair = fx.ecdsa("snap-interop-ecdsa-p2r", EcdsaSpec::es256());

        let signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(keypair.private_key_pkcs8_der())
            .expect("valid P-256 PKCS#8 DER");
        let message = b"p256-to-ring interop snapshot test";
        let sig: p256::ecdsa::DerSignature = signing_key.sign(message);

        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, raw_pubkey);
        public_key
            .verify(message, sig.as_bytes())
            .expect("ring should verify p256-signed signature");

        let result = InteropRoundTrip {
            key_type: "ECDSA",
            algorithm: "P-256/SHA-256",
            signer_backend: "p256 (RustCrypto)",
            verifier_backend: "ring",
            signature_len: sig.as_bytes().len(),
            success: true,
        };
        insta::assert_yaml_snapshot!("p256_to_ring_ecdsa_round_trip", result);
    }
}

mod dalek_to_ring {
    use super::*;
    use ed25519_dalek::Signer;
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    use ring::signature::{self, UnparsedPublicKey};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn dalek_sign_ring_verify_snapshot() {
        let fx = fx();
        let keypair = fx.ed25519("snap-interop-ed25519-d2r", Ed25519Spec::new());

        let signing_key =
            ed25519_dalek::SigningKey::from_pkcs8_der(keypair.private_key_pkcs8_der())
                .expect("valid Ed25519 PKCS#8 DER");
        let message = b"dalek-to-ring interop snapshot test";
        let sig = signing_key.sign(message);

        let raw_public_key = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key = UnparsedPublicKey::new(&signature::ED25519, raw_public_key);
        public_key
            .verify(message, sig.to_bytes().as_ref())
            .expect("ring should verify dalek-signed Ed25519 signature");

        let result = InteropRoundTrip {
            key_type: "Ed25519",
            algorithm: "Ed25519",
            signer_backend: "ed25519-dalek",
            verifier_backend: "ring",
            signature_len: sig.to_bytes().len(),
            success: true,
        };
        insta::assert_yaml_snapshot!("dalek_to_ring_ed25519_round_trip", result);
    }
}

mod rsa_crate_to_ring {
    use super::*;
    use ring::signature::{self, UnparsedPublicKey};
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::SignatureEncoding;
    use rsa::signature::Signer;
    use sha2::Sha256;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rsa_crate_sign_ring_verify_snapshot() {
        let fx = fx();
        let keypair = fx.rsa("snap-interop-rsa-rc2r", RsaSpec::rs256());

        let private_key = rsa::RsaPrivateKey::from_pkcs8_der(keypair.private_key_pkcs8_der())
            .expect("valid RSA PKCS#8 DER");
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let message = b"rsa-crate-to-ring interop snapshot test";
        let sig = signing_key.sign(message);

        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key = UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, raw_pubkey);
        public_key
            .verify(message, &sig.to_bytes())
            .expect("ring should verify rsa-crate-signed signature");

        let result = InteropRoundTrip {
            key_type: "RSA",
            algorithm: "RSA-PKCS1v15-SHA256",
            signer_backend: "rsa (RustCrypto)",
            verifier_backend: "ring",
            signature_len: sig.to_bytes().len(),
            success: true,
        };
        insta::assert_yaml_snapshot!("rsa_crate_to_ring_round_trip", result);
    }
}

// ===========================================================================
// Interop compatibility matrix — summary of all tested adapter pairs
// ===========================================================================

mod interop_matrix {
    use super::*;

    #[derive(Serialize)]
    struct InteropPair {
        key_type: &'static str,
        algorithm: &'static str,
        signer: &'static str,
        verifier: &'static str,
    }

    #[derive(Serialize)]
    struct InteropMatrixSnapshot {
        total_pairs: usize,
        key_types: Vec<&'static str>,
        backends: Vec<&'static str>,
        pairs: Vec<InteropPair>,
    }

    #[test]
    fn interop_compatibility_matrix() {
        let pairs = vec![
            InteropPair {
                key_type: "ECDSA",
                algorithm: "P-256/SHA-256",
                signer: "p256 (RustCrypto)",
                verifier: "ring",
            },
            InteropPair {
                key_type: "ECDSA",
                algorithm: "P-256/SHA-256",
                signer: "ring",
                verifier: "p256 (RustCrypto)",
            },
            InteropPair {
                key_type: "Ed25519",
                algorithm: "Ed25519",
                signer: "ed25519-dalek",
                verifier: "ring",
            },
            InteropPair {
                key_type: "Ed25519",
                algorithm: "Ed25519",
                signer: "ring",
                verifier: "ed25519-dalek",
            },
            InteropPair {
                key_type: "RSA",
                algorithm: "RSA-PKCS1v15-SHA256",
                signer: "rsa (RustCrypto)",
                verifier: "ring",
            },
            InteropPair {
                key_type: "RSA",
                algorithm: "RSA-PKCS1v15-SHA256",
                signer: "ring",
                verifier: "rsa (RustCrypto)",
            },
        ];

        let matrix = InteropMatrixSnapshot {
            total_pairs: pairs.len(),
            key_types: vec!["ECDSA", "Ed25519", "RSA"],
            backends: vec![
                "ring",
                "p256 (RustCrypto)",
                "ed25519-dalek",
                "rsa (RustCrypto)",
            ],
            pairs,
        };

        insta::assert_yaml_snapshot!("interop_compatibility_matrix", matrix);
    }
}
