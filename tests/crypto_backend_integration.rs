//! Crypto Backend Integration Tests
//!
//! Tests crypto operations using the ring backend:
//! - RSA sign/verify with ring
//! - ECDSA sign/verify with ring
//! - Ed25519 sign/verify with ring
//! - Verify deterministic behavior across factory instances

mod testutil;

use testutil::fx;

// =========================================================================
// RSA Ring Tests
// =========================================================================

#[cfg(feature = "crypto-backend")]
mod rsa_cross_backend_tests {
    use super::*;

    use ring::{
        rand::SystemRandom as RingRng,
        signature::{self as ring_sig, UnparsedPublicKey as RingUnparsedPublicKey},
    };
    use uselesskey_ring::RingRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn test_rsa_ring_sign_verify() {
        let fx = fx();
        let rsa_keypair = fx.rsa("cross-backend-rsa", RsaSpec::rs256());

        // Convert to ring backend
        let ring_keypair = rsa_keypair.rsa_key_pair_ring();

        // Sign with ring
        let msg = b"test message for ring RSA sign/verify";
        let ring_rng = RingRng::new();
        let mut sig = vec![0u8; ring_keypair.public().modulus_len()];
        ring_keypair
            .sign(&ring_sig::RSA_PKCS1_SHA256, &ring_rng, msg, &mut sig)
            .expect("Failed to sign with ring");

        // Verify with ring
        let public_key_bytes = ring_keypair.public().as_ref();
        let ring_pubkey =
            RingUnparsedPublicKey::new(&ring_sig::RSA_PKCS1_2048_8192_SHA256, public_key_bytes);
        ring_pubkey
            .verify(msg, &sig)
            .expect("Failed to verify ring signature");
    }

    #[test]
    fn test_rsa_ring_determinism() {
        let fx1 = fx();
        let fx2 = fx();

        // Generate same key from same seed
        let rsa1 = fx1.rsa("deterministic-cross", RsaSpec::rs256());
        let rsa2 = fx2.rsa("deterministic-cross", RsaSpec::rs256());

        // Convert to ring backend
        let ring1 = rsa1.rsa_key_pair_ring();
        let ring2 = rsa2.rsa_key_pair_ring();

        // Public keys should be identical
        assert_eq!(
            ring1.public().as_ref(),
            ring2.public().as_ref(),
            "Ring public keys should be identical"
        );
    }

    #[test]
    fn test_rsa_ring_different_key_sizes() {
        let fx = fx();
        let key_sizes = [2048, 3072, 4096];

        for bits in key_sizes {
            let rsa_keypair = fx.rsa(format!("cross-backend-{bits}-bit"), RsaSpec::new(bits));

            // Convert to ring backend
            let ring_keypair = rsa_keypair.rsa_key_pair_ring();

            // Sign and verify with ring
            let msg = format!("test message for {bits}-bit key");
            let ring_rng = RingRng::new();
            let mut sig = vec![0u8; ring_keypair.public().modulus_len()];
            ring_keypair
                .sign(
                    &ring_sig::RSA_PKCS1_SHA256,
                    &ring_rng,
                    msg.as_bytes(),
                    &mut sig,
                )
                .expect("Failed to sign with ring");

            let public_key_bytes = ring_keypair.public().as_ref();
            let ring_pubkey =
                RingUnparsedPublicKey::new(&ring_sig::RSA_PKCS1_2048_8192_SHA256, public_key_bytes);
            ring_pubkey
                .verify(msg.as_bytes(), &sig)
                .expect("Failed to verify ring signature");
        }
    }
}

// =========================================================================
// ECDSA Ring Tests
// =========================================================================

#[cfg(feature = "crypto-backend")]
mod ecdsa_cross_backend_tests {
    use super::*;

    use ring::{
        rand::SystemRandom as RingRng,
        signature::{self as ring_sig, KeyPair, UnparsedPublicKey as RingUnparsedPublicKey},
    };
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ring::RingEcdsaKeyPairExt;

    #[test]
    fn test_ecdsa_p256_ring_sign_verify() {
        let fx = fx();
        let ecdsa_keypair = fx.ecdsa("cross-backend-ecdsa-p256", EcdsaSpec::Es256);

        // Convert to ring backend
        let ring_keypair = ecdsa_keypair.ecdsa_key_pair_ring();

        // Sign with ring
        let msg = b"test message for ECDSA P-256 ring sign/verify";
        let ring_rng = RingRng::new();
        let sig = ring_keypair
            .sign(&ring_rng, msg)
            .expect("Failed to sign with ring");

        // Verify with ring
        let public_key_bytes = ring_keypair.public_key().as_ref();
        let ring_pubkey =
            RingUnparsedPublicKey::new(&ring_sig::ECDSA_P256_SHA256_ASN1, public_key_bytes);
        ring_pubkey
            .verify(msg, sig.as_ref())
            .expect("Failed to verify ring P-256 signature");
    }

    #[test]
    fn test_ecdsa_p384_ring_sign_verify() {
        let fx = fx();
        let ecdsa_keypair = fx.ecdsa("cross-backend-ecdsa-p384", EcdsaSpec::Es384);

        // Convert to ring backend
        let ring_keypair = ecdsa_keypair.ecdsa_key_pair_ring();

        // Sign with ring
        let msg = b"test message for ECDSA P-384 ring sign/verify";
        let ring_rng = RingRng::new();
        let sig = ring_keypair
            .sign(&ring_rng, msg)
            .expect("Failed to sign with ring");

        // Verify with ring
        let public_key_bytes = ring_keypair.public_key().as_ref();
        let ring_pubkey =
            RingUnparsedPublicKey::new(&ring_sig::ECDSA_P384_SHA384_ASN1, public_key_bytes);
        ring_pubkey
            .verify(msg, sig.as_ref())
            .expect("Failed to verify ring P-384 signature");
    }

    #[test]
    fn test_ecdsa_ring_determinism() {
        let fx1 = fx();
        let fx2 = fx();

        // Generate same key from same seed
        let ecdsa1 = fx1.ecdsa("deterministic-ecdsa", EcdsaSpec::Es256);
        let ecdsa2 = fx2.ecdsa("deterministic-ecdsa", EcdsaSpec::Es256);

        // Convert to ring backend
        let ring1 = ecdsa1.ecdsa_key_pair_ring();
        let ring2 = ecdsa2.ecdsa_key_pair_ring();

        // Public keys should be identical
        assert_eq!(
            ring1.public_key().as_ref(),
            ring2.public_key().as_ref(),
            "Ring ECDSA public keys should be identical"
        );
    }
}

// =========================================================================
// Ed25519 Ring Tests
// =========================================================================

#[cfg(feature = "crypto-backend")]
mod ed25519_cross_backend_tests {
    use super::*;

    use ring::signature::{self as ring_sig, KeyPair, UnparsedPublicKey as RingUnparsedPublicKey};
    use uselesskey_ed25519::Ed25519FactoryExt;
    use uselesskey_ring::RingEd25519KeyPairExt;

    #[test]
    fn test_ed25519_ring_sign_verify() {
        let fx = fx();
        let ed25519_keypair = fx.ed25519(
            "cross-backend-ed25519",
            uselesskey_ed25519::Ed25519Spec::new(),
        );

        // Convert to ring backend
        let ring_keypair = ed25519_keypair.ed25519_key_pair_ring();

        // Sign with ring (Ed25519KeyPair::sign returns Signature directly, not Result)
        let msg = b"test message for Ed25519 ring sign/verify";
        let sig = ring_keypair.sign(msg);

        // Verify with ring
        let public_key_bytes = ring_keypair.public_key().as_ref();
        let ring_pubkey = RingUnparsedPublicKey::new(&ring_sig::ED25519, public_key_bytes);
        ring_pubkey
            .verify(msg, sig.as_ref())
            .expect("Failed to verify ring Ed25519 signature");
    }

    #[test]
    fn test_ed25519_ring_determinism() {
        let fx1 = fx();
        let fx2 = fx();

        // Generate same key from same seed
        let ed25519_1 = fx1.ed25519(
            "deterministic-ed25519",
            uselesskey_ed25519::Ed25519Spec::new(),
        );
        let ed25519_2 = fx2.ed25519(
            "deterministic-ed25519",
            uselesskey_ed25519::Ed25519Spec::new(),
        );

        // Convert to ring backend
        let ring1 = ed25519_1.ed25519_key_pair_ring();
        let ring2 = ed25519_2.ed25519_key_pair_ring();

        // Public keys should be identical
        assert_eq!(
            ring1.public_key().as_ref(),
            ring2.public_key().as_ref(),
            "Ring Ed25519 public keys should be identical"
        );
    }
}

// =========================================================================
// Deterministic Behavior Tests
// =========================================================================

#[cfg(feature = "crypto-backend")]
mod deterministic_behavior_tests {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::Ed25519FactoryExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn test_deterministic_key_generation() {
        let fx1 = fx();
        let fx2 = fx();

        // RSA
        let rsa1 = fx1.rsa("deterministic-rsa", RsaSpec::rs256());
        let rsa2 = fx2.rsa("deterministic-rsa", RsaSpec::rs256());
        assert_eq!(
            rsa1.private_key_pkcs8_der(),
            rsa2.private_key_pkcs8_der(),
            "RSA keys should be identical"
        );

        // ECDSA
        let ecdsa1 = fx1.ecdsa("deterministic-ecdsa", EcdsaSpec::Es256);
        let ecdsa2 = fx2.ecdsa("deterministic-ecdsa", EcdsaSpec::Es256);
        assert_eq!(
            ecdsa1.private_key_pkcs8_der(),
            ecdsa2.private_key_pkcs8_der(),
            "ECDSA keys should be identical"
        );

        // Ed25519
        let ed1 = fx1.ed25519(
            "deterministic-ed25519",
            uselesskey_ed25519::Ed25519Spec::new(),
        );
        let ed2 = fx2.ed25519(
            "deterministic-ed25519",
            uselesskey_ed25519::Ed25519Spec::new(),
        );
        assert_eq!(
            ed1.private_key_pkcs8_der(),
            ed2.private_key_pkcs8_der(),
            "Ed25519 keys should be identical"
        );
    }

    #[test]
    fn test_different_labels_produce_different_keys() {
        let fx = fx();

        let rsa1 = fx.rsa("label-1", RsaSpec::rs256());
        let rsa2 = fx.rsa("label-2", RsaSpec::rs256());
        assert_ne!(
            rsa1.private_key_pkcs8_der(),
            rsa2.private_key_pkcs8_der(),
            "Different labels should produce different RSA keys"
        );

        let ecdsa1 = fx.ecdsa("label-1", EcdsaSpec::Es256);
        let ecdsa2 = fx.ecdsa("label-2", EcdsaSpec::Es256);
        assert_ne!(
            ecdsa1.private_key_pkcs8_der(),
            ecdsa2.private_key_pkcs8_der(),
            "Different labels should produce different ECDSA keys"
        );

        let ed1 = fx.ed25519("label-1", uselesskey_ed25519::Ed25519Spec::new());
        let ed2 = fx.ed25519("label-2", uselesskey_ed25519::Ed25519Spec::new());
        assert_ne!(
            ed1.private_key_pkcs8_der(),
            ed2.private_key_pkcs8_der(),
            "Different labels should produce different Ed25519 keys"
        );
    }
}
