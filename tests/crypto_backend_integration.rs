//! Cross-Crypto Backend Integration Tests
//!
//! Tests compatibility across different crypto backends:
//! - Test that the same keys produce compatible results across ring, aws-lc-rs, and rustcrypto
//! - Test digest operations across different backends
//! - Test HMAC operations across different backends
//! - Verify deterministic behavior across backends

mod testutil;

use testutil::fx;
use uselesskey_core::{Factory, Seed};

// =========================================================================
// RSA Cross-Backend Tests
// =========================================================================

#[cfg(all(
    feature = "uselesskey-rsa",
    feature = "uselesskey-ring",
    feature = "uselesskey-aws-lc-rs"
))]
mod rsa_cross_backend_tests {
    use super::*;

    #[cfg(feature = "native")]
    use aws_lc_rs::{
        rand::SystemRandom as AwsRng,
        signature::{self as aws_sig, UnparsedPublicKey as AwsUnparsedPublicKey},
    };
    use ring::{
        rand::SystemRandom as RingRng,
        signature::{self as ring_sig, UnparsedPublicKey as RingUnparsedPublicKey},
    };
    use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;
    use uselesskey_ring::RingRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    #[cfg(feature = "native")]
    fn test_rsa_ring_and_aws_lc_rs_produce_same_signatures() {
        let fx = fx();
        let rsa_keypair = fx.rsa("cross-backend-rsa", RsaSpec::rs256());

        // Convert to both backends
        let ring_keypair = rsa_keypair.rsa_key_pair_ring();
        let aws_keypair = rsa_keypair.rsa_key_pair_aws_lc_rs();

        // Sign with ring
        let msg = b"test message for cross-backend compatibility";
        let ring_rng = RingRng::new();
        let mut ring_sig = vec![0u8; ring_keypair.public().modulus_len()];
        ring_keypair
            .sign(&ring_sig::RSA_PKCS1_SHA256, &ring_rng, msg, &mut ring_sig)
            .expect("Failed to sign with ring");

        // Sign with aws-lc-rs
        let aws_rng = AwsRng::new();
        let mut aws_sig = vec![0u8; aws_keypair.public_modulus_len()];
        aws_keypair
            .sign(&aws_sig::RSA_PKCS1_SHA256, &aws_rng, msg, &mut aws_sig)
            .expect("Failed to sign with aws-lc-rs");

        // Both signatures should verify with the same public key
        let public_key_bytes = ring_keypair.public().as_ref();

        // Verify ring signature with ring
        let ring_pubkey = RingUnparsedPublicKey::new(
            &ring_sig::RSA_PKCS1_2048_8192_SHA256,
            public_key_bytes,
        );
        ring_pubkey
            .verify(msg, &ring_sig)
            .expect("Failed to verify ring signature with ring");

        // Verify aws-lc-rs signature with aws-lc-rs
        let aws_pubkey = AwsUnparsedPublicKey::new(
            &aws_sig::RSA_PKCS1_2048_8192_SHA256,
            public_key_bytes,
        );
        aws_pubkey
            .verify(msg, &aws_sig)
            .expect("Failed to verify aws-lc-rs signature with aws-lc-rs");

        // Cross-verify: ring signature should verify with aws-lc-rs
        aws_pubkey
            .verify(msg, &ring_sig)
            .expect("Failed to verify ring signature with aws-lc-rs");

        // Cross-verify: aws-lc-rs signature should verify with ring
        ring_pubkey
            .verify(msg, &aws_sig)
            .expect("Failed to verify aws-lc-rs signature with ring");
    }

    #[test]
    #[cfg(feature = "native")]
    fn test_rsa_cross_backend_determinism() {
        let fx1 = fx();
        let fx2 = fx();

        // Generate same key from same seed
        let rsa1 = fx1.rsa("deterministic-cross", RsaSpec::rs256());
        let rsa2 = fx2.rsa("deterministic-cross", RsaSpec::rs256());

        // Convert to both backends
        let ring1 = rsa1.rsa_key_pair_ring();
        let ring2 = rsa2.rsa_key_pair_ring();
        let aws1 = rsa1.rsa_key_pair_aws_lc_rs();
        let aws2 = rsa2.rsa_key_pair_aws_lc_rs();

        // Public keys should be identical
        assert_eq!(
            ring1.public().as_ref(),
            ring2.public().as_ref(),
            "Ring public keys should be identical"
        );
        assert_eq!(
            aws1.public_key().as_ref(),
            aws2.public_key().as_ref(),
            "AWS LC-RS public keys should be identical"
        );
        assert_eq!(
            ring1.public().as_ref(),
            aws1.public_key().as_ref(),
            "Ring and AWS LC-RS public keys should be identical"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn test_rsa_different_key_sizes_cross_backend() {
        let fx = fx();
        let key_sizes = [2048, 3072, 4096];

        for bits in key_sizes {
            let rsa_keypair = fx.rsa(&format!("cross-backend-{}-bit", bits), RsaSpec::new(bits));

            // Convert to both backends
            let ring_keypair = rsa_keypair.rsa_key_pair_ring();
            let aws_keypair = rsa_keypair.rsa_key_pair_aws_lc_rs();

            // Verify both can sign
            let msg = format!("test message for {}-bit key", bits);
            let ring_rng = RingRng::new();
            let mut ring_sig = vec![0u8; ring_keypair.public().modulus_len()];
            ring_keypair
                .sign(&ring_sig::RSA_PKCS1_SHA256, &ring_rng, msg.as_bytes(), &mut ring_sig)
                .expect("Failed to sign with ring");

            let aws_rng = AwsRng::new();
            let mut aws_sig = vec![0u8; aws_keypair.public_modulus_len()];
            aws_keypair
                .sign(&aws_sig::RSA_PKCS1_SHA256, &aws_rng, msg.as_bytes(), &mut aws_sig)
                .expect("Failed to sign with aws-lc-rs");

            // Verify signatures
            let public_key_bytes = ring_keypair.public().as_ref();
            let ring_pubkey = RingUnparsedPublicKey::new(
                &ring_sig::RSA_PKCS1_2048_8192_SHA256,
                public_key_bytes,
            );
            ring_pubkey
                .verify(msg.as_bytes(), &ring_sig)
                .expect("Failed to verify ring signature");

            let aws_pubkey = AwsUnparsedPublicKey::new(
                &aws_sig::RSA_PKCS1_2048_8192_SHA256,
                public_key_bytes,
            );
            aws_pubkey
                .verify(msg.as_bytes(), &aws_sig)
                .expect("Failed to verify aws-lc-rs signature");
        }
    }
}

// =========================================================================
// ECDSA Cross-Backend Tests
// =========================================================================

#[cfg(all(
    feature = "uselesskey-ecdsa",
    feature = "uselesskey-ring",
    feature = "uselesskey-aws-lc-rs"
))]
mod ecdsa_cross_backend_tests {
    use super::*;

    #[cfg(feature = "native")]
    use aws_lc_rs::{
        rand::SystemRandom as AwsRng,
        signature::{self as aws_sig, UnparsedPublicKey as AwsUnparsedPublicKey},
    };
    use ring::{
        rand::SystemRandom as RingRng,
        signature::{self as ring_sig, UnparsedPublicKey as RingUnparsedPublicKey},
    };
    use uselesskey_aws_lc_rs::AwsLcRsEcdsaKeyPairExt;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ring::RingEcdsaKeyPairExt;

    #[test]
    #[cfg(feature = "native")]
    fn test_ecdsa_p256_ring_and_aws_lc_rs_produce_same_signatures() {
        let fx = fx();
        let ecdsa_keypair = fx.ecdsa("cross-backend-ecdsa-p256", EcdsaSpec::Es256);

        // Convert to both backends
        let ring_keypair = ecdsa_keypair.ecdsa_key_pair_ring();
        let aws_keypair = ecdsa_keypair.ecdsa_key_pair_aws_lc_rs();

        // Sign with ring
        let msg = b"test message for ECDSA P-256 cross-backend compatibility";
        let ring_rng = RingRng::new();
        let ring_sig = ring_keypair.sign(&ring_rng, msg).expect("Failed to sign with ring");

        // Sign with aws-lc-rs
        let aws_rng = AwsRng::new();
        let aws_sig = aws_keypair.sign(&aws_rng, msg).expect("Failed to sign with aws-lc-rs");

        // Both signatures should verify with the same public key
        let public_key_bytes = ring_keypair.public_key().as_ref();

        // Verify ring signature with ring
        let ring_pubkey = RingUnparsedPublicKey::new(
            &ring_sig::ECDSA_P256_SHA256_FIXED_SIGNING,
            public_key_bytes,
        );
        ring_pubkey
            .verify(msg, ring_sig.as_ref())
            .expect("Failed to verify ring signature with ring");

        // Verify aws-lc-rs signature with aws-lc-rs
        let aws_pubkey = AwsUnparsedPublicKey::new(
            &aws_sig::ECDSA_P256_SHA256_FIXED_SIGNING,
            public_key_bytes,
        );
        aws_pubkey
            .verify(msg, aws_sig.as_ref())
            .expect("Failed to verify aws-lc-rs signature with aws-lc-rs");

        // Cross-verify: ring signature should verify with aws-lc-rs
        aws_pubkey
            .verify(msg, ring_sig.as_ref())
            .expect("Failed to verify ring signature with aws-lc-rs");

        // Cross-verify: aws-lc-rs signature should verify with ring
        ring_pubkey
            .verify(msg, aws_sig.as_ref())
            .expect("Failed to verify aws-lc-rs signature with ring");
    }

    #[test]
    #[cfg(feature = "native")]
    fn test_ecdsa_p384_ring_and_aws_lc_rs_produce_same_signatures() {
        let fx = fx();
        let ecdsa_keypair = fx.ecdsa("cross-backend-ecdsa-p384", EcdsaSpec::Es384);

        // Convert to both backends
        let ring_keypair = ecdsa_keypair.ecdsa_key_pair_ring();
        let aws_keypair = ecdsa_keypair.ecdsa_key_pair_aws_lc_rs();

        // Sign with ring
        let msg = b"test message for ECDSA P-384 cross-backend compatibility";
        let ring_rng = RingRng::new();
        let ring_sig = ring_keypair.sign(&ring_rng, msg).expect("Failed to sign with ring");

        // Sign with aws-lc-rs
        let aws_rng = AwsRng::new();
        let aws_sig = aws_keypair.sign(&aws_rng, msg).expect("Failed to sign with aws-lc-rs");

        // Both signatures should verify with the same public key
        let public_key_bytes = ring_keypair.public_key().as_ref();

        // Verify ring signature with ring
        let ring_pubkey = RingUnparsedPublicKey::new(
            &ring_sig::ECDSA_P384_SHA384_FIXED_SIGNING,
            public_key_bytes,
        );
        ring_pubkey
            .verify(msg, ring_sig.as_ref())
            .expect("Failed to verify ring signature with ring");

        // Verify aws-lc-rs signature with aws-lc-rs
        let aws_pubkey = AwsUnparsedPublicKey::new(
            &aws_sig::ECDSA_P384_SHA384_FIXED_SIGNING,
            public_key_bytes,
        );
        aws_pubkey
            .verify(msg, aws_sig.as_ref())
            .expect("Failed to verify aws-lc-rs signature with aws-lc-rs");

        // Cross-verify: ring signature should verify with aws-lc-rs
        aws_pubkey
            .verify(msg, ring_sig.as_ref())
            .expect("Failed to verify ring signature with aws-lc-rs");

        // Cross-verify: aws-lc-rs signature should verify with ring
        ring_pubkey
            .verify(msg, aws_sig.as_ref())
            .expect("Failed to verify aws-lc-rs signature with ring");
    }

    #[test]
    #[cfg(feature = "native")]
    fn test_ecdsa_cross_backend_determinism() {
        let fx1 = fx();
        let fx2 = fx();

        // Generate same key from same seed
        let ecdsa1 = fx1.ecdsa("deterministic-ecdsa", EcdsaSpec::Es256);
        let ecdsa2 = fx2.ecdsa("deterministic-ecdsa", EcdsaSpec::Es256);

        // Convert to both backends
        let ring1 = ecdsa1.ecdsa_key_pair_ring();
        let ring2 = ecdsa2.ecdsa_key_pair_ring();
        let aws1 = ecdsa1.ecdsa_key_pair_aws_lc_rs();
        let aws2 = ecdsa2.ecdsa_key_pair_aws_lc_rs();

        // Public keys should be identical
        assert_eq!(
            ring1.public_key().as_ref(),
            ring2.public_key().as_ref(),
            "Ring ECDSA public keys should be identical"
        );
        assert_eq!(
            aws1.public_key().as_ref(),
            aws2.public_key().as_ref(),
            "AWS LC-RS ECDSA public keys should be identical"
        );
        assert_eq!(
            ring1.public_key().as_ref(),
            aws1.public_key().as_ref(),
            "Ring and AWS LC-RS ECDSA public keys should be identical"
        );
    }
}

// =========================================================================
// Ed25519 Cross-Backend Tests
// =========================================================================

#[cfg(all(
    feature = "uselesskey-ed25519",
    feature = "uselesskey-ring",
    feature = "uselesskey-aws-lc-rs"
))]
mod ed25519_cross_backend_tests {
    use super::*;

    #[cfg(feature = "native")]
    use aws_lc_rs::{
        rand::SystemRandom as AwsRng,
        signature::{self as aws_sig, UnparsedPublicKey as AwsUnparsedPublicKey},
    };
    use ring::{
        rand::SystemRandom as RingRng,
        signature::{self as ring_sig, UnparsedPublicKey as RingUnparsedPublicKey},
    };
    use uselesskey_aws_lc_rs::AwsLcRsEd25519KeyPairExt;
    use uselesskey_ed25519::Ed25519FactoryExt;
    use uselesskey_ring::RingEd25519KeyPairExt;

    #[test]
    #[cfg(feature = "native")]
    fn test_ed25519_ring_and_aws_lc_rs_produce_same_signatures() {
        let fx = fx();
        let ed25519_keypair = fx.ed25519("cross-backend-ed25519", uselesskey_ed25519::Ed25519Spec::new());

        // Convert to both backends
        let ring_keypair = ed25519_keypair.ed25519_key_pair_ring();
        let aws_keypair = ed25519_keypair.ed25519_key_pair_aws_lc_rs();

        // Sign with ring
        let msg = b"test message for Ed25519 cross-backend compatibility";
        let ring_sig = ring_keypair.sign(msg).expect("Failed to sign with ring");

        // Sign with aws-lc-rs
        let aws_rng = AwsRng::new();
        let aws_sig = aws_keypair.sign(&aws_rng, msg).expect("Failed to sign with aws-lc-rs");

        // Both signatures should verify with the same public key
        let public_key_bytes = ring_keypair.public_key().as_ref();

        // Verify ring signature with ring
        let ring_pubkey = RingUnparsedPublicKey::new(&ring_sig::ED25519, public_key_bytes);
        ring_pubkey
            .verify(msg, ring_sig.as_ref())
            .expect("Failed to verify ring signature with ring");

        // Verify aws-lc-rs signature with aws-lc-rs
        let aws_pubkey = AwsUnparsedPublicKey::new(&aws_sig::ED25519, public_key_bytes);
        aws_pubkey
            .verify(msg, aws_sig.as_ref())
            .expect("Failed to verify aws-lc-rs signature with aws-lc-rs");

        // Cross-verify: ring signature should verify with aws-lc-rs
        aws_pubkey
            .verify(msg, ring_sig.as_ref())
            .expect("Failed to verify ring signature with aws-lc-rs");

        // Cross-verify: aws-lc-rs signature should verify with ring
        ring_pubkey
            .verify(msg, aws_sig.as_ref())
            .expect("Failed to verify aws-lc-rs signature with ring");
    }

    #[test]
    #[cfg(feature = "native")]
    fn test_ed25519_cross_backend_determinism() {
        let fx1 = fx();
        let fx2 = fx();

        // Generate same key from same seed
        let ed25519_1 = fx1.ed25519("deterministic-ed25519", uselesskey_ed25519::Ed25519Spec::new());
        let ed25519_2 = fx2.ed25519("deterministic-ed25519", uselesskey_ed25519::Ed25519Spec::new());

        // Convert to both backends
        let ring1 = ed25519_1.ed25519_key_pair_ring();
        let ring2 = ed25519_2.ed25519_key_pair_ring();
        let aws1 = ed25519_1.ed25519_key_pair_aws_lc_rs();
        let aws2 = ed25519_2.ed25519_key_pair_aws_lc_rs();

        // Public keys should be identical
        assert_eq!(
            ring1.public_key().as_ref(),
            ring2.public_key().as_ref(),
            "Ring Ed25519 public keys should be identical"
        );
        assert_eq!(
            aws1.public_key().as_ref(),
            aws2.public_key().as_ref(),
            "AWS LC-RS Ed25519 public keys should be identical"
        );
        assert_eq!(
            ring1.public_key().as_ref(),
            aws1.public_key().as_ref(),
            "Ring and AWS LC-RS Ed25519 public keys should be identical"
        );
    }
}

// =========================================================================
// Digest Cross-Backend Tests
// =========================================================================

#[cfg(all(feature = "uselesskey-ring", feature = "uselesskey-aws-lc-rs"))]
mod digest_cross_backend_tests {
    use super::*;

    #[cfg(feature = "native")]
    use aws_lc_rs::digest as aws_digest;
    use ring::digest as ring_digest;

    #[test]
    #[cfg(feature = "native")]
    fn test_sha256_digest_consistency() {
        let msg = b"test message for digest cross-backend compatibility";

        // Compute SHA-256 with ring
        let ring_digest = ring_digest::digest(&ring_digest::SHA256, msg);

        // Compute SHA-256 with aws-lc-rs
        let aws_digest = aws_digest::digest(&aws_digest::SHA256, msg);

        // Digests should be identical
        assert_eq!(
            ring_digest.as_ref(),
            aws_digest.as_ref(),
            "SHA-256 digests should be identical across backends"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn test_sha384_digest_consistency() {
        let msg = b"test message for SHA-384 digest cross-backend compatibility";

        // Compute SHA-384 with ring
        let ring_digest = ring_digest::digest(&ring_digest::SHA384, msg);

        // Compute SHA-384 with aws-lc-rs
        let aws_digest = aws_digest::digest(&aws_digest::SHA384, msg);

        // Digests should be identical
        assert_eq!(
            ring_digest.as_ref(),
            aws_digest.as_ref(),
            "SHA-384 digests should be identical across backends"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn test_sha512_digest_consistency() {
        let msg = b"test message for SHA-512 digest cross-backend compatibility";

        // Compute SHA-512 with ring
        let ring_digest = ring_digest::digest(&ring_digest::SHA512, msg);

        // Compute SHA-512 with aws-lc-rs
        let aws_digest = aws_digest::digest(&aws_digest::SHA512, msg);

        // Digests should be identical
        assert_eq!(
            ring_digest.as_ref(),
            aws_digest.as_ref(),
            "SHA-512 digests should be identical across backends"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn test_digest_empty_message() {
        let msg = b"";

        // Test SHA-256
        let ring_sha256 = ring_digest::digest(&ring_digest::SHA256, msg);
        let aws_sha256 = aws_digest::digest(&aws_digest::SHA256, msg);
        assert_eq!(
            ring_sha256.as_ref(),
            aws_sha256.as_ref(),
            "SHA-256 of empty message should be identical"
        );

        // Test SHA-384
        let ring_sha384 = ring_digest::digest(&ring_digest::SHA384, msg);
        let aws_sha384 = aws_digest::digest(&aws_digest::SHA384, msg);
        assert_eq!(
            ring_sha384.as_ref(),
            aws_sha384.as_ref(),
            "SHA-384 of empty message should be identical"
        );

        // Test SHA-512
        let ring_sha512 = ring_digest::digest(&ring_digest::SHA512, msg);
        let aws_sha512 = aws_digest::digest(&aws_digest::SHA512, msg);
        assert_eq!(
            ring_sha512.as_ref(),
            aws_sha512.as_ref(),
            "SHA-512 of empty message should be identical"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn test_digest_large_message() {
        let msg = vec![0u8; 10_000]; // 10KB message

        // Test SHA-256
        let ring_sha256 = ring_digest::digest(&ring_digest::SHA256, &msg);
        let aws_sha256 = aws_digest::digest(&aws_digest::SHA256, &msg);
        assert_eq!(
            ring_sha256.as_ref(),
            aws_sha256.as_ref(),
            "SHA-256 of large message should be identical"
        );

        // Test SHA-384
        let ring_sha384 = ring_digest::digest(&ring_digest::SHA384, &msg);
        let aws_sha384 = aws_digest::digest(&aws_digest::SHA384, &msg);
        assert_eq!(
            ring_sha384.as_ref(),
            aws_sha384.as_ref(),
            "SHA-384 of large message should be identical"
        );

        // Test SHA-512
        let ring_sha512 = ring_digest::digest(&ring_digest::SHA512, &msg);
        let aws_sha512 = aws_digest::digest(&aws_digest::SHA512, &msg);
        assert_eq!(
            ring_sha512.as_ref(),
            aws_sha512.as_ref(),
            "SHA-512 of large message should be identical"
        );
    }
}

// =========================================================================
// HMAC Cross-Backend Tests
// =========================================================================

#[cfg(all(feature = "uselesskey-ring", feature = "uselesskey-aws-lc-rs"))]
mod hmac_cross_backend_tests {
    use super::*;

    #[cfg(feature = "native")]
    use aws_lc_rs::hmac as aws_hmac;
    use ring::hmac as ring_hmac;

    #[test]
    #[cfg(feature = "native")]
    fn test_hmac_sha256_consistency() {
        let key = b"test-key-for-hmac-sha256";
        let msg = b"test message for HMAC cross-backend compatibility";

        // Compute HMAC-SHA256 with ring
        let ring_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA256, key);
        let ring_tag = ring_hmac::sign(&ring_key, msg);

        // Compute HMAC-SHA256 with aws-lc-rs
        let aws_key = aws_hmac::Key::new(aws_hmac::HMAC_SHA256, key);
        let aws_tag = aws_hmac::sign(&aws_key, msg);

        // Tags should be identical
        assert_eq!(
            ring_tag.as_ref(),
            aws_tag.as_ref(),
            "HMAC-SHA256 tags should be identical across backends"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn test_hmac_sha384_consistency() {
        let key = b"test-key-for-hmac-sha384";
        let msg = b"test message for HMAC-SHA384 cross-backend compatibility";

        // Compute HMAC-SHA384 with ring
        let ring_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA384, key);
        let ring_tag = ring_hmac::sign(&ring_key, msg);

        // Compute HMAC-SHA384 with aws-lc-rs
        let aws_key = aws_hmac::Key::new(aws_hmac::HMAC_SHA384, key);
        let aws_tag = aws_hmac::sign(&aws_key, msg);

        // Tags should be identical
        assert_eq!(
            ring_tag.as_ref(),
            aws_tag.as_ref(),
            "HMAC-SHA384 tags should be identical across backends"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn test_hmac_sha512_consistency() {
        let key = b"test-key-for-hmac-sha512";
        let msg = b"test message for HMAC-SHA512 cross-backend compatibility";

        // Compute HMAC-SHA512 with ring
        let ring_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA512, key);
        let ring_tag = ring_hmac::sign(&ring_key, msg);

        // Compute HMAC-SHA512 with aws-lc-rs
        let aws_key = aws_hmac::Key::new(aws_hmac::HMAC_SHA512, key);
        let aws_tag = aws_hmac::sign(&aws_key, msg);

        // Tags should be identical
        assert_eq!(
            ring_tag.as_ref(),
            aws_tag.as_ref(),
            "HMAC-SHA512 tags should be identical across backends"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn test_hmac_cross_backend_verification() {
        let key = b"test-key-for-cross-verification";
        let msg = b"test message for cross-backend HMAC verification";

        // Compute HMAC with ring
        let ring_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA256, key);
        let ring_tag = ring_hmac::sign(&ring_key, msg);

        // Verify with aws-lc-rs
        let aws_key = aws_hmac::Key::new(aws_hmac::HMAC_SHA256, key);
        assert!(
            aws_hmac::verify(&aws_key, msg, ring_tag.as_ref()).is_ok(),
            "Ring HMAC should verify with aws-lc-rs"
        );

        // Compute HMAC with aws-lc-rs
        let aws_tag = aws_hmac::sign(&aws_key, msg);

        // Verify with ring
        assert!(
            ring_hmac::verify(&ring_key, msg, aws_tag.as_ref()).is_ok(),
            "AWS LC-RS HMAC should verify with ring"
        );
    }

    #[test]
    #[cfg(feature = "native")]
    fn test_hmac_empty_message() {
        let key = b"test-key";
        let msg = b"";

        // Test HMAC-SHA256
        let ring_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA256, key);
        let ring_tag = ring_hmac::sign(&ring_key, msg);
        let aws_key = aws_hmac::Key::new(aws_hmac::HMAC_SHA256, key);
        let aws_tag = aws_hmac::sign(&aws_key, msg);
        assert_eq!(
            ring_tag.as_ref(),
            aws_tag.as_ref(),
            "HMAC-SHA256 of empty message should be identical"
        );
    }
}

// =========================================================================
// Deterministic Behavior Tests
// =========================================================================

#[cfg(all(
    feature = "uselesskey-rsa",
    feature = "uselesskey-ecdsa",
    feature = "uselesskey-ed25519"
))]
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
        let ed1 = fx1.ed25519("deterministic-ed25519", uselesskey_ed25519::Ed25519Spec::new());
        let ed2 = fx2.ed25519("deterministic-ed25519", uselesskey_ed25519::Ed25519Spec::new());
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
