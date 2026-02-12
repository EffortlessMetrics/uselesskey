//! Comprehensive tests for uselesskey-ring integration
//! 
//! Tests cover:
//! - Ring-specific key conversions for RSA, ECDSA, Ed25519
//! - Digest operations using ring
//! - HMAC operations with ring
//! - Edge cases and error handling
//! - Deterministic key behavior
//! - Cross-key validation failures

mod testutil;

use ring::{
    digest,
    hmac::{self, Key as HmacKey},
    rand::SystemRandom,
    signature::{self, KeyPair, UnparsedPublicKey},
};
use testutil::fx;
use uselesskey_core::{Factory, Seed};
use uselesskey_ring::{
    RingEcdsaKeyPairExt, RingEd25519KeyPairExt, RingRsaKeyPairExt,
};

#[cfg(feature = "rsa")]
mod rsa_ring_tests {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn test_rsa_key_pair_conversion() {
        let fx = fx();
        let rsa_keypair = fx.rsa("test-rsa", RsaSpec::rs256());
        
        // Convert to ring key pair
        let ring_keypair = rsa_keypair.rsa_key_pair_ring();
        
        // Verify the key pair is valid by attempting to sign
        let msg = b"test message";
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; ring_keypair.public().modulus_len()];
        
        ring_keypair
            .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("Failed to sign with ring RSA key pair");
        
        // Verify the signature
        let public_key_bytes = ring_keypair.public().as_ref();
        let public_key = UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            public_key_bytes,
        );
        public_key.verify(msg, &sig).expect("Failed to verify signature");
    }

    #[test]
    fn test_rsa_different_key_sizes() {
        let test_cases = [
            (2048, "rsa-2048"),
            (3072, "rsa-3072"),
            (4096, "rsa-4096"),
        ];

        for (bits, label) in test_cases {
            let fx = fx();
            let rsa_keypair = fx.rsa(label, RsaSpec::new(bits));
            let ring_keypair = rsa_keypair.rsa_key_pair_ring();

            let msg = format!("test message for {}-bit key", bits);
            let rng = SystemRandom::new();
            let mut sig = vec![0u8; ring_keypair.public().modulus_len()];
            
            ring_keypair
                .sign(&signature::RSA_PKCS1_SHA256, &rng, msg.as_bytes(), &mut sig)
                .unwrap_or_else(|e| panic!("Failed to sign with {}-bit key: {:?}", bits, e));

            let public_key_bytes = ring_keypair.public().as_ref();
            let public_key = UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                public_key_bytes,
            );
            public_key
                .verify(msg.as_bytes(), &sig)
                .unwrap_or_else(|e| panic!("Failed to verify {}-bit signature: {:?}", bits, e));
        }
    }

    #[test]
    fn test_rsa_deterministic_keys() {
        let seed = Seed::from_env_value("rsa-deterministic-test-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let rsa1 = fx1.rsa("deterministic-test", RsaSpec::rs256());
        let rsa2 = fx2.rsa("deterministic-test", RsaSpec::rs256());

        let ring1 = rsa1.rsa_key_pair_ring();
        let ring2 = rsa2.rsa_key_pair_ring();

        // Keys should be identical
        assert_eq!(
            rsa1.private_key_pkcs8_pem(),
            rsa2.private_key_pkcs8_pem(),
            "Deterministic RSA keys should be identical"
        );

        // Test signing with deterministic keys
        let msg = b"deterministic test message";
        let rng = SystemRandom::new();
        let mut sig1 = vec![0u8; ring1.public().modulus_len()];
        let mut sig2 = vec![0u8; ring2.public().modulus_len()];
        
        ring1.sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig1).unwrap();
        ring2.sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig2).unwrap();
        
        // Note: RSA signatures might be identical or different depending on the implementation
        // The important thing is that both signatures verify correctly
        
        // But both should verify correctly
        let public_key_bytes = ring1.public().as_ref();
        let public_key = UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            public_key_bytes,
        );
        
        public_key.verify(msg, &sig1).expect("First signature should verify");
        public_key.verify(msg, &sig2).expect("Second signature should verify");
    }

    #[test]
    fn test_rsa_cross_key_verification_fails() {
        let fx = fx();
        let rsa_a = fx.rsa("key-a", RsaSpec::rs256());
        let rsa_b = fx.rsa("key-b", RsaSpec::rs256());

        let ring_a = rsa_a.rsa_key_pair_ring();
        let ring_b = rsa_b.rsa_key_pair_ring();

        let msg = b"test message";
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; ring_a.public().modulus_len()];
        
        ring_a.sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig).unwrap();

        // Try to verify with key B's public key
        let public_key_bytes = ring_b.public().as_ref();
        let public_key = UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            public_key_bytes,
        );
        
        let result = public_key.verify(msg, &sig);
        assert!(result.is_err(), "Verification with wrong key should fail");
    }

    #[test]
    fn test_rsa_signature_tampering_fails() {
        let fx = fx();
        let rsa_keypair = fx.rsa("tamper-test", RsaSpec::rs256());
        let ring_keypair = rsa_keypair.rsa_key_pair_ring();

        let msg = b"original message";
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; ring_keypair.public().modulus_len()];
        
        ring_keypair.sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig).unwrap();

        // Tamper with the signature
        if let Some(last_byte) = sig.last_mut() {
            *last_byte = last_byte.wrapping_add(1);
        }

        let public_key_bytes = ring_keypair.public().as_ref();
        let public_key = UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            public_key_bytes,
        );
        
        let result = public_key.verify(msg, &sig);
        assert!(result.is_err(), "Verification with tampered signature should fail");
    }
}

#[cfg(feature = "ecdsa")]
mod ecdsa_ring_tests {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn test_ecdsa_p256_key_pair_conversion() {
        let fx = fx();
        let ecdsa_keypair = fx.ecdsa("test-ecdsa-p256", EcdsaSpec::es256());
        
        // Convert to ring key pair
        let ring_keypair = ecdsa_keypair.ecdsa_key_pair_ring();
        
        // Verify the key pair is valid by attempting to sign
        let msg = b"test message";
        let rng = SystemRandom::new();
        let sig = ring_keypair.sign(&rng, msg).expect("Failed to sign with ring ECDSA key pair");
        
        // Verify the signature
        let public_key_bytes = ring_keypair.public_key().as_ref();
        let public_key = UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            public_key_bytes,
        );
        public_key.verify(msg, sig.as_ref()).expect("Failed to verify signature");
    }

    #[test]
    fn test_ecdsa_p384_key_pair_conversion() {
        let fx = fx();
        let ecdsa_keypair = fx.ecdsa("test-ecdsa-p384", EcdsaSpec::es384());
        
        // Convert to ring key pair
        let ring_keypair = ecdsa_keypair.ecdsa_key_pair_ring();
        
        // Verify the key pair is valid by attempting to sign
        let msg = b"test message";
        let rng = SystemRandom::new();
        let sig = ring_keypair.sign(&rng, msg).expect("Failed to sign with ring ECDSA key pair");
        
        // Verify the signature
        let public_key_bytes = ring_keypair.public_key().as_ref();
        let public_key = UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_ASN1,
            public_key_bytes,
        );
        public_key.verify(msg, sig.as_ref()).expect("Failed to verify signature");
    }

    #[test]
    fn test_ecdsa_deterministic_keys() {
        let seed = Seed::from_env_value("ecdsa-deterministic-test-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let ecdsa1 = fx1.ecdsa("deterministic-test", EcdsaSpec::es256());
        let ecdsa2 = fx2.ecdsa("deterministic-test", EcdsaSpec::es256());

        let ring1 = ecdsa1.ecdsa_key_pair_ring();
        let ring2 = ecdsa2.ecdsa_key_pair_ring();

        // Keys should be identical
        assert_eq!(
            ecdsa1.private_key_pkcs8_pem(),
            ecdsa2.private_key_pkcs8_pem(),
            "Deterministic ECDSA keys should be identical"
        );

        // Test signing with deterministic keys (should produce different signatures due to random nonce)
        let msg = b"deterministic test message";
        let rng = SystemRandom::new();
        let sig1 = ring1.sign(&rng, msg).unwrap();
        let sig2 = ring2.sign(&rng, msg).unwrap();
        
        // Signatures should be different due to random nonce
        assert_ne!(sig1.as_ref(), sig2.as_ref(), "ECDSA signatures should be different due to random nonce");
        
        // But both should verify correctly with their respective public keys
        let public_key_bytes1 = ring1.public_key().as_ref();
        let public_key1 = UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            public_key_bytes1,
        );
        public_key1.verify(msg, sig1.as_ref()).expect("First signature should verify");
        
        let public_key_bytes2 = ring2.public_key().as_ref();
        let public_key2 = UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            public_key_bytes2,
        );
        public_key2.verify(msg, sig2.as_ref()).expect("Second signature should verify");
    }

    #[test]
    fn test_ecdsa_cross_key_verification_fails() {
        let fx = fx();
        let ecdsa_a = fx.ecdsa("key-a", EcdsaSpec::es256());
        let ecdsa_b = fx.ecdsa("key-b", EcdsaSpec::es256());

        let ring_a = ecdsa_a.ecdsa_key_pair_ring();
        let ring_b = ecdsa_b.ecdsa_key_pair_ring();

        let msg = b"test message";
        let rng = SystemRandom::new();
        let sig = ring_a.sign(&rng, msg).unwrap();

        // Try to verify with key B's public key
        let public_key_bytes = ring_b.public_key().as_ref();
        let public_key = UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            public_key_bytes,
        );
        
        let result = public_key.verify(msg, sig.as_ref());
        assert!(result.is_err(), "Verification with wrong key should fail");
    }

    #[test]
    fn test_ecdsa_message_tampering_fails() {
        let fx = fx();
        let ecdsa_keypair = fx.ecdsa("tamper-test", EcdsaSpec::es256());
        let ring_keypair = ecdsa_keypair.ecdsa_key_pair_ring();

        let original_msg = b"original message";
        let tampered_msg = b"tampered message";
        let rng = SystemRandom::new();
        let sig = ring_keypair.sign(&rng, original_msg).unwrap();

        let public_key_bytes = ring_keypair.public_key().as_ref();
        let public_key = UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            public_key_bytes,
        );
        
        // Original message should verify
        public_key.verify(original_msg, sig.as_ref()).expect("Original message should verify");
        
        // Tampered message should not verify
        let result = public_key.verify(tampered_msg, sig.as_ref());
        assert!(result.is_err(), "Tampered message should not verify");
    }
}

#[cfg(feature = "ed25519")]
mod ed25519_ring_tests {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn test_ed25519_key_pair_conversion() {
        let fx = fx();
        let ed25519_keypair = fx.ed25519("test-ed25519", Ed25519Spec::new());
        
        // Convert to ring key pair
        let ring_keypair = ed25519_keypair.ed25519_key_pair_ring();
        
        // Verify the key pair is valid by attempting to sign
        let msg = b"test message";
        let sig = ring_keypair.sign(msg);
        
        // Verify the signature
        let public_key_bytes = ring_keypair.public_key().as_ref();
        let public_key = UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
        public_key.verify(msg, sig.as_ref()).expect("Failed to verify signature");
    }

    #[test]
    fn test_ed25519_deterministic_keys() {
        let seed = Seed::from_env_value("ed25519-deterministic-test-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let ed25519_1 = fx1.ed25519("deterministic-test", Ed25519Spec::new());
        let ed25519_2 = fx2.ed25519("deterministic-test", Ed25519Spec::new());

        let ring1 = ed25519_1.ed25519_key_pair_ring();
        let ring2 = ed25519_2.ed25519_key_pair_ring();

        // Keys should be identical
        assert_eq!(
            ed25519_1.private_key_pkcs8_pem(),
            ed25519_2.private_key_pkcs8_pem(),
            "Deterministic Ed25519 keys should be identical"
        );

        // Test signing with deterministic keys (Ed25519 signatures are deterministic)
        let msg = b"deterministic test message";
        let sig1 = ring1.sign(msg);
        let sig2 = ring2.sign(msg);
        
        // Ed25519 signatures should be identical for identical keys and messages
        assert_eq!(sig1.as_ref(), sig2.as_ref(), "Ed25519 signatures should be identical");
        
        // Both should verify correctly
        let public_key_bytes = ring1.public_key().as_ref();
        let public_key = UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
        public_key.verify(msg, sig1.as_ref()).expect("First signature should verify");
        public_key.verify(msg, sig2.as_ref()).expect("Second signature should verify");
    }

    #[test]
    fn test_ed25519_cross_key_verification_fails() {
        let fx = fx();
        let ed25519_a = fx.ed25519("key-a", Ed25519Spec::new());
        let ed25519_b = fx.ed25519("key-b", Ed25519Spec::new());

        let ring_a = ed25519_a.ed25519_key_pair_ring();
        let ring_b = ed25519_b.ed25519_key_pair_ring();

        let msg = b"test message";
        let sig = ring_a.sign(msg);

        // Try to verify with key B's public key
        let public_key_bytes = ring_b.public_key().as_ref();
        let public_key = UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
        
        let result = public_key.verify(msg, sig.as_ref());
        assert!(result.is_err(), "Verification with wrong key should fail");
    }

    #[test]
    fn test_ed25519_message_tampering_fails() {
        let fx = fx();
        let ed25519_keypair = fx.ed25519("tamper-test", Ed25519Spec::new());
        let ring_keypair = ed25519_keypair.ed25519_key_pair_ring();

        let original_msg = b"original message";
        let tampered_msg = b"tampered message";
        let sig = ring_keypair.sign(original_msg);

        let public_key_bytes = ring_keypair.public_key().as_ref();
        let public_key = UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
        
        // Original message should verify
        public_key.verify(original_msg, sig.as_ref()).expect("Original message should verify");
        
        // Tampered message should not verify
        let result = public_key.verify(tampered_msg, sig.as_ref());
        assert!(result.is_err(), "Tampered message should not verify");
    }
}

mod digest_tests {
    use super::*;

    #[test]
    fn test_sha256_digest() {
        let msg = b"test message for digest";
        let digest = digest::digest(&digest::SHA256, msg);
        
        // We don't need to assert the exact value, just that it's consistent
        let digest2 = digest::digest(&digest::SHA256, msg);
        assert_eq!(digest.as_ref(), digest2.as_ref(), "Digest should be deterministic");
        
        // Different messages should produce different digests
        let different_msg = b"different message";
        let different_digest = digest::digest(&digest::SHA256, different_msg);
        assert_ne!(digest.as_ref(), different_digest.as_ref(), "Different messages should produce different digests");
    }

    #[test]
    fn test_sha384_digest() {
        let msg = b"test message for sha384";
        let digest = digest::digest(&digest::SHA384, msg);
        
        // Test determinism
        let digest2 = digest::digest(&digest::SHA384, msg);
        assert_eq!(digest.as_ref(), digest2.as_ref(), "SHA384 digest should be deterministic");
        
        // Test different algorithms produce different results
        let sha256_digest = digest::digest(&digest::SHA256, msg);
        assert_ne!(digest.as_ref(), sha256_digest.as_ref(), "Different algorithms should produce different digests");
    }

    #[test]
    fn test_sha512_digest() {
        let msg = b"test message for sha512";
        let digest = digest::digest(&digest::SHA512, msg);
        
        // Test determinism
        let digest2 = digest::digest(&digest::SHA512, msg);
        assert_eq!(digest.as_ref(), digest2.as_ref(), "SHA512 digest should be deterministic");
        
        // Test different algorithms produce different results
        let sha256_digest = digest::digest(&digest::SHA256, msg);
        assert_ne!(digest.as_ref(), sha256_digest.as_ref(), "Different algorithms should produce different digests");
    }
}

mod hmac_tests {
    use super::*;

    #[test]
    fn test_hmac_sha256() {
        let key = HmacKey::new(hmac::HMAC_SHA256, b"test-key-32-bytes-long!!");
        let msg = b"test message for hmac";
        
        let tag = hmac::sign(&key, msg);
        
        // Verify the HMAC
        hmac::verify(&key, msg, tag.as_ref()).expect("HMAC verification should succeed");
        
        // Test that different messages produce different tags
        let different_msg = b"different message";
        let different_tag = hmac::sign(&key, different_msg);
        assert_ne!(tag.as_ref(), different_tag.as_ref(), "Different messages should produce different HMAC tags");
    }

    #[test]
    fn test_hmac_sha384() {
        let key = HmacKey::new(hmac::HMAC_SHA384, b"test-key-48-bytes-long!!!!!!!!!!");
        let msg = b"test message for hmac sha384";
        
        let tag = hmac::sign(&key, msg);
        
        // Verify the HMAC
        hmac::verify(&key, msg, tag.as_ref()).expect("HMAC verification should succeed");
        
        // Test that different keys produce different tags
        let different_key = HmacKey::new(hmac::HMAC_SHA384, b"different-key-48-bytes-long!!!!!!!!!!");
        let different_tag = hmac::sign(&different_key, msg);
        assert_ne!(tag.as_ref(), different_tag.as_ref(), "Different keys should produce different HMAC tags");
    }

    #[test]
    fn test_hmac_sha512() {
        let key = HmacKey::new(hmac::HMAC_SHA512, b"test-key-64-bytes-long!!!!!!!!!!!!!!!!!!!!!!");
        let msg = b"test message for hmac sha512";
        
        let tag = hmac::sign(&key, msg);
        
        // Verify the HMAC
        hmac::verify(&key, msg, tag.as_ref()).expect("HMAC verification should succeed");
    }

    #[test]
    fn test_hmac_verification_fails_with_wrong_key() {
        let key1 = HmacKey::new(hmac::HMAC_SHA256, b"key1-32-bytes-long!!!!!!");
        let key2 = HmacKey::new(hmac::HMAC_SHA256, b"key2-32-bytes-long!!!!!!");
        let msg = b"test message";
        
        let tag = hmac::sign(&key1, msg);
        
        // Verification should fail with wrong key
        let result = hmac::verify(&key2, msg, tag.as_ref());
        assert!(result.is_err(), "HMAC verification should fail with wrong key");
    }

    #[test]
    fn test_hmac_verification_fails_with_tampered_message() {
        let key = HmacKey::new(hmac::HMAC_SHA256, b"test-key-32-bytes-long!!");
        let original_msg = b"original message";
        let tampered_msg = b"tampered message";
        
        let tag = hmac::sign(&key, original_msg);
        
        // Original message should verify
        hmac::verify(&key, original_msg, tag.as_ref()).expect("Original message should verify");
        
        // Tampered message should not verify
        let result = hmac::verify(&key, tampered_msg, tag.as_ref());
        assert!(result.is_err(), "HMAC verification should fail with tampered message");
    }
}

#[cfg(all(feature = "rsa", feature = "ecdsa"))]
mod cross_algorithm_tests {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn test_cross_algorithm_signature_verification_fails() {
        let fx = fx();
        let rsa_keypair = fx.rsa("test-rsa", RsaSpec::rs256());
        let ecdsa_keypair = fx.ecdsa("test-ecdsa", EcdsaSpec::es256());

        let msg = b"test message";
        
        // Sign with RSA
        let ring_rsa = rsa_keypair.rsa_key_pair_ring();
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; ring_rsa.public().modulus_len()];
        ring_rsa.sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig).unwrap();

        // Try to verify with ECDSA public key
        let ring_ecdsa = ecdsa_keypair.ecdsa_key_pair_ring();
        let ecdsa_public_key_bytes = ring_ecdsa.public_key().as_ref();
        let ecdsa_public_key = UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            ecdsa_public_key_bytes,
        );
        
        let result = ecdsa_public_key.verify(msg, &sig);
        assert!(result.is_err(), "Cross-algorithm verification should fail");
    }
}