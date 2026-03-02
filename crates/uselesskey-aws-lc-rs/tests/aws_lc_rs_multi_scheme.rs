//! Multi-scheme and cross-factory integration tests for uselesskey-aws-lc-rs.
//!
//! Tests cover:
//! - RSA with SHA-384 and SHA-512 signing/verification schemes
//! - Cross-factory deterministic verification for all key types
//! - Signature size validation
//! - Multiple messages with the same key

mod testutil;

#[cfg(all(feature = "native", any(not(windows), has_nasm)))]
use testutil::fx;
#[cfg(all(feature = "native", any(not(windows), has_nasm)))]
use uselesskey_core::{Factory, Seed};

// =========================================================================
// RSA multiple signing/verification schemes
// =========================================================================

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "rsa"))]
mod rsa_multi_scheme {
    use super::*;
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{self, KeyPair},
    };
    use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rsa_pkcs1_sha384_sign_verify() {
        let kp = fx()
            .rsa("aws-sha384", RsaSpec::rs256())
            .rsa_key_pair_aws_lc_rs();
        let rng = SystemRandom::new();
        let msg = b"pkcs1 sha384";
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(&signature::RSA_PKCS1_SHA384, &rng, msg, &mut sig)
            .expect("sign");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA384,
            kp.public_key().as_ref(),
        );
        pk.verify(msg, &sig).expect("verify");
    }

    #[test]
    fn rsa_pkcs1_sha512_sign_verify() {
        let kp = fx()
            .rsa("aws-sha512", RsaSpec::rs256())
            .rsa_key_pair_aws_lc_rs();
        let rng = SystemRandom::new();
        let msg = b"pkcs1 sha512";
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(&signature::RSA_PKCS1_SHA512, &rng, msg, &mut sig)
            .expect("sign");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA512,
            kp.public_key().as_ref(),
        );
        pk.verify(msg, &sig).expect("verify");
    }

    #[test]
    fn rsa_pss_sha384_sign_verify() {
        let kp = fx()
            .rsa("aws-pss384", RsaSpec::rs256())
            .rsa_key_pair_aws_lc_rs();
        let rng = SystemRandom::new();
        let msg = b"pss sha384";
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(&signature::RSA_PSS_SHA384, &rng, msg, &mut sig)
            .expect("sign");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PSS_2048_8192_SHA384,
            kp.public_key().as_ref(),
        );
        pk.verify(msg, &sig).expect("verify");
    }

    #[test]
    fn rsa_pss_sha512_sign_verify() {
        let kp = fx()
            .rsa("aws-pss512", RsaSpec::rs256())
            .rsa_key_pair_aws_lc_rs();
        let rng = SystemRandom::new();
        let msg = b"pss sha512";
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(&signature::RSA_PSS_SHA512, &rng, msg, &mut sig)
            .expect("sign");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PSS_2048_8192_SHA512,
            kp.public_key().as_ref(),
        );
        pk.verify(msg, &sig).expect("verify");
    }

    /// Signature length must equal modulus length for RSA.
    #[test]
    fn rsa_signature_length_matches_modulus() {
        for (bits, label) in [(2048, "aws-siglen-2k"), (4096, "aws-siglen-4k")] {
            let kp = fx().rsa(label, RsaSpec::new(bits)).rsa_key_pair_aws_lc_rs();
            let rng = SystemRandom::new();
            let mut sig = vec![0u8; kp.public_modulus_len()];
            kp.sign(&signature::RSA_PKCS1_SHA256, &rng, b"len-check", &mut sig)
                .unwrap();
            assert_eq!(
                sig.len(),
                bits / 8,
                "signature length must match {bits}-bit key"
            );
        }
    }

    #[test]
    fn rsa_multiple_messages_same_key() {
        let kp = fx()
            .rsa("aws-multi-msg", RsaSpec::rs256())
            .rsa_key_pair_aws_lc_rs();
        let rng = SystemRandom::new();

        for i in 0..5 {
            let msg = format!("message-{i}");
            let mut sig = vec![0u8; kp.public_modulus_len()];
            kp.sign(&signature::RSA_PKCS1_SHA256, &rng, msg.as_bytes(), &mut sig)
                .unwrap();

            let pk = signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                kp.public_key().as_ref(),
            );
            pk.verify(msg.as_bytes(), &sig)
                .unwrap_or_else(|_| panic!("verify message-{i}"));
        }
    }

    #[test]
    fn cross_factory_rsa_deterministic_verify() {
        let seed = Seed::from_env_value("aws-cross-fac-rsa").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1
            .rsa("cross-rsa", RsaSpec::rs256())
            .rsa_key_pair_aws_lc_rs();
        let kp2 = fx2
            .rsa("cross-rsa", RsaSpec::rs256())
            .rsa_key_pair_aws_lc_rs();

        let rng = SystemRandom::new();
        let msg = b"cross-factory-aws-rsa";
        let mut sig = vec![0u8; kp1.public_modulus_len()];
        kp1.sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .unwrap();

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            kp2.public_key().as_ref(),
        );
        pk.verify(msg, &sig).expect("cross-factory rsa verify");
    }
}

// =========================================================================
// ECDSA cross-factory and multi-message
// =========================================================================

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ecdsa"))]
mod ecdsa_multi_scheme {
    use super::*;
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{self, KeyPair},
    };
    use uselesskey_aws_lc_rs::AwsLcRsEcdsaKeyPairExt;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn ecdsa_p256_multiple_messages() {
        let kp = fx()
            .ecdsa("aws-ec-multi", EcdsaSpec::es256())
            .ecdsa_key_pair_aws_lc_rs();
        let rng = SystemRandom::new();

        for i in 0..5 {
            let msg = format!("ec-msg-{i}");
            let sig = kp.sign(&rng, msg.as_bytes()).unwrap();

            let pk = signature::UnparsedPublicKey::new(
                &signature::ECDSA_P256_SHA256_ASN1,
                kp.public_key().as_ref(),
            );
            pk.verify(msg.as_bytes(), sig.as_ref())
                .unwrap_or_else(|_| panic!("verify ec-msg-{i}"));
        }
    }

    #[test]
    fn cross_factory_ecdsa_deterministic_verify() {
        let seed = Seed::from_env_value("aws-cross-fac-ec").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1
            .ecdsa("cross-ec", EcdsaSpec::es256())
            .ecdsa_key_pair_aws_lc_rs();
        let kp2 = fx2
            .ecdsa("cross-ec", EcdsaSpec::es256())
            .ecdsa_key_pair_aws_lc_rs();

        let rng = SystemRandom::new();
        let sig = kp1.sign(&rng, b"cross-factory-ec").unwrap();

        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            kp2.public_key().as_ref(),
        );
        pk.verify(b"cross-factory-ec", sig.as_ref())
            .expect("cross-factory ecdsa verify");
    }
}

// =========================================================================
// Ed25519 cross-factory
// =========================================================================

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ed25519"))]
mod ed25519_multi_scheme {
    use super::*;
    use aws_lc_rs::signature::{self, KeyPair};
    use uselesskey_aws_lc_rs::AwsLcRsEd25519KeyPairExt;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn ed25519_multiple_messages() {
        let kp = fx()
            .ed25519("aws-ed-multi", Ed25519Spec::new())
            .ed25519_key_pair_aws_lc_rs();

        for i in 0..5 {
            let msg = format!("ed-msg-{i}");
            let sig = kp.sign(msg.as_bytes());

            let pk =
                signature::UnparsedPublicKey::new(&signature::ED25519, kp.public_key().as_ref());
            pk.verify(msg.as_bytes(), sig.as_ref())
                .unwrap_or_else(|_| panic!("verify ed-msg-{i}"));
        }
    }

    #[test]
    fn cross_factory_ed25519_deterministic_verify() {
        let seed = Seed::from_env_value("aws-cross-fac-ed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1
            .ed25519("cross-ed", Ed25519Spec::new())
            .ed25519_key_pair_aws_lc_rs();
        let kp2 = fx2
            .ed25519("cross-ed", Ed25519Spec::new())
            .ed25519_key_pair_aws_lc_rs();

        let sig = kp1.sign(b"cross-factory-ed");
        let pk = signature::UnparsedPublicKey::new(&signature::ED25519, kp2.public_key().as_ref());
        pk.verify(b"cross-factory-ed", sig.as_ref())
            .expect("cross-factory ed25519 verify");
    }

    /// Ed25519 same key+message must produce identical signatures.
    #[test]
    fn ed25519_signature_determinism() {
        let kp = fx()
            .ed25519("aws-ed-det-sig", Ed25519Spec::new())
            .ed25519_key_pair_aws_lc_rs();

        let sig1 = kp.sign(b"deterministic");
        let sig2 = kp.sign(b"deterministic");
        assert_eq!(sig1.as_ref(), sig2.as_ref());
    }
}
