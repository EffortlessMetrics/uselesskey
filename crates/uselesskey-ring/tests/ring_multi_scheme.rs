//! Multi-scheme and cross-factory integration tests for uselesskey-ring.
//!
//! Tests cover:
//! - RSA with multiple signing/verification schemes (PSS, SHA-384, SHA-512)
//! - Empty and large message signing for all key types
//! - Cross-factory deterministic verification (sign factory1, verify factory2)
//! - Signature stability for deterministic Ed25519

mod testutil;

use testutil::fx;
use uselesskey_core::{Factory, Seed};

// =========================================================================
// RSA multiple signing/verification schemes
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_multi_scheme {
    use super::*;
    use ring::{rand::SystemRandom, signature};
    use uselesskey_ring::RingRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rsa_pss_sha256_sign_verify() {
        let kp = fx()
            .rsa("ring-pss-256", RsaSpec::rs256())
            .rsa_key_pair_ring();
        let rng = SystemRandom::new();
        let msg = b"pss sha256";
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(&signature::RSA_PSS_SHA256, &rng, msg, &mut sig)
            .expect("sign PSS-SHA256");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PSS_2048_8192_SHA256,
            kp.public().as_ref(),
        );
        pk.verify(msg, &sig).expect("verify PSS-SHA256");
    }

    #[test]
    fn rsa_pss_sha384_sign_verify() {
        let kp = fx()
            .rsa("ring-pss-384", RsaSpec::rs256())
            .rsa_key_pair_ring();
        let rng = SystemRandom::new();
        let msg = b"pss sha384";
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(&signature::RSA_PSS_SHA384, &rng, msg, &mut sig)
            .expect("sign PSS-SHA384");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PSS_2048_8192_SHA384,
            kp.public().as_ref(),
        );
        pk.verify(msg, &sig).expect("verify PSS-SHA384");
    }

    #[test]
    fn rsa_pss_sha512_sign_verify() {
        let kp = fx()
            .rsa("ring-pss-512", RsaSpec::rs256())
            .rsa_key_pair_ring();
        let rng = SystemRandom::new();
        let msg = b"pss sha512";
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(&signature::RSA_PSS_SHA512, &rng, msg, &mut sig)
            .expect("sign PSS-SHA512");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PSS_2048_8192_SHA512,
            kp.public().as_ref(),
        );
        pk.verify(msg, &sig).expect("verify PSS-SHA512");
    }

    #[test]
    fn rsa_pkcs1_sha384_sign_verify() {
        let kp = fx()
            .rsa("ring-sha384", RsaSpec::rs256())
            .rsa_key_pair_ring();
        let rng = SystemRandom::new();
        let msg = b"pkcs1 sha384";
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(&signature::RSA_PKCS1_SHA384, &rng, msg, &mut sig)
            .expect("sign PKCS1-SHA384");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA384,
            kp.public().as_ref(),
        );
        pk.verify(msg, &sig).expect("verify PKCS1-SHA384");
    }

    #[test]
    fn rsa_pkcs1_sha512_sign_verify() {
        let kp = fx()
            .rsa("ring-sha512", RsaSpec::rs256())
            .rsa_key_pair_ring();
        let rng = SystemRandom::new();
        let msg = b"pkcs1 sha512";
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(&signature::RSA_PKCS1_SHA512, &rng, msg, &mut sig)
            .expect("sign PKCS1-SHA512");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA512,
            kp.public().as_ref(),
        );
        pk.verify(msg, &sig).expect("verify PKCS1-SHA512");
    }

    #[test]
    fn rsa_empty_message_sign_verify() {
        let kp = fx()
            .rsa("ring-rsa-empty", RsaSpec::rs256())
            .rsa_key_pair_ring();
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(&signature::RSA_PKCS1_SHA256, &rng, b"", &mut sig)
            .expect("sign empty");
        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            kp.public().as_ref(),
        );
        pk.verify(b"", &sig).expect("verify empty");
    }

    #[test]
    fn rsa_large_message_sign_verify() {
        let kp = fx()
            .rsa("ring-rsa-large", RsaSpec::rs256())
            .rsa_key_pair_ring();
        let rng = SystemRandom::new();
        let msg = vec![0xABu8; 64 * 1024];
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(&signature::RSA_PKCS1_SHA256, &rng, &msg, &mut sig)
            .expect("sign large");
        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            kp.public().as_ref(),
        );
        pk.verify(&msg, &sig).expect("verify large");
    }

    /// Sign with factory1's key, verify with factory2's key (same seed).
    #[test]
    fn cross_factory_rsa_deterministic_verify() {
        let seed = Seed::from_env_value("ring-cross-fac-rsa").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.rsa("cross-fac", RsaSpec::rs256()).rsa_key_pair_ring();
        let kp2 = fx2.rsa("cross-fac", RsaSpec::rs256()).rsa_key_pair_ring();

        let rng = SystemRandom::new();
        let msg = b"cross factory rsa";
        let mut sig = vec![0u8; kp1.public().modulus_len()];
        kp1.sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .unwrap();

        // Verify with factory2's public key
        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            kp2.public().as_ref(),
        );
        pk.verify(msg, &sig).expect("cross-factory verify");
    }
}

// =========================================================================
// ECDSA empty/large message and cross-factory
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_edge_cases {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{self, KeyPair},
    };
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ring::RingEcdsaKeyPairExt;

    #[test]
    fn ecdsa_p256_empty_message() {
        let kp = fx()
            .ecdsa("ring-ec-empty", EcdsaSpec::es256())
            .ecdsa_key_pair_ring();
        let rng = SystemRandom::new();
        let sig = kp.sign(&rng, b"").unwrap();
        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            kp.public_key().as_ref(),
        );
        pk.verify(b"", sig.as_ref()).expect("verify empty");
    }

    #[test]
    fn ecdsa_p384_empty_message() {
        let kp = fx()
            .ecdsa("ring-p384-empty", EcdsaSpec::es384())
            .ecdsa_key_pair_ring();
        let rng = SystemRandom::new();
        let sig = kp.sign(&rng, b"").unwrap();
        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_ASN1,
            kp.public_key().as_ref(),
        );
        pk.verify(b"", sig.as_ref()).expect("verify empty");
    }

    #[test]
    fn ecdsa_large_message() {
        let kp = fx()
            .ecdsa("ring-ec-large", EcdsaSpec::es256())
            .ecdsa_key_pair_ring();
        let rng = SystemRandom::new();
        let msg = vec![0xCDu8; 64 * 1024];
        let sig = kp.sign(&rng, &msg).unwrap();
        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            kp.public_key().as_ref(),
        );
        pk.verify(&msg, sig.as_ref()).expect("verify large");
    }

    #[test]
    fn cross_factory_ecdsa_deterministic_verify() {
        let seed = Seed::from_env_value("ring-cross-fac-ec").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1
            .ecdsa("cross-fac-ec", EcdsaSpec::es256())
            .ecdsa_key_pair_ring();
        let kp2 = fx2
            .ecdsa("cross-fac-ec", EcdsaSpec::es256())
            .ecdsa_key_pair_ring();

        let rng = SystemRandom::new();
        let msg = b"cross factory ecdsa";
        let sig = kp1.sign(&rng, msg).unwrap();

        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            kp2.public_key().as_ref(),
        );
        pk.verify(msg, sig.as_ref()).expect("cross-factory verify");
    }
}

// =========================================================================
// Ed25519 empty/large message and cross-factory
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_edge_cases {
    use super::*;
    use ring::signature::{self, KeyPair};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_ring::RingEd25519KeyPairExt;

    #[test]
    fn ed25519_empty_message() {
        let kp = fx()
            .ed25519("ring-ed-empty", Ed25519Spec::new())
            .ed25519_key_pair_ring();
        let sig = kp.sign(b"");
        let pk = signature::UnparsedPublicKey::new(&signature::ED25519, kp.public_key().as_ref());
        pk.verify(b"", sig.as_ref()).expect("verify empty");
    }

    #[test]
    fn ed25519_large_message() {
        let kp = fx()
            .ed25519("ring-ed-large", Ed25519Spec::new())
            .ed25519_key_pair_ring();
        let msg = vec![0xEFu8; 64 * 1024];
        let sig = kp.sign(&msg);
        let pk = signature::UnparsedPublicKey::new(&signature::ED25519, kp.public_key().as_ref());
        pk.verify(&msg, sig.as_ref()).expect("verify large");
    }

    #[test]
    fn cross_factory_ed25519_deterministic_verify() {
        let seed = Seed::from_env_value("ring-cross-fac-ed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1
            .ed25519("cross-fac-ed", Ed25519Spec::new())
            .ed25519_key_pair_ring();
        let kp2 = fx2
            .ed25519("cross-fac-ed", Ed25519Spec::new())
            .ed25519_key_pair_ring();

        let msg = b"cross factory ed25519";
        let sig = kp1.sign(msg);

        let pk = signature::UnparsedPublicKey::new(&signature::ED25519, kp2.public_key().as_ref());
        pk.verify(msg, sig.as_ref()).expect("cross-factory verify");
    }

    /// Ed25519 is deterministic: same key + same message = same signature.
    #[test]
    fn ed25519_signature_is_deterministic() {
        let kp = fx()
            .ed25519("ring-ed-det-sig", Ed25519Spec::new())
            .ed25519_key_pair_ring();
        let msg = b"deterministic sig";
        let sig1 = kp.sign(msg);
        let sig2 = kp.sign(msg);
        assert_eq!(sig1.as_ref(), sig2.as_ref());
    }
}
