//! Integration tests for uselesskey-aws-lc-rs adapter.
//!
//! Covers key conversion, signing/verification round-trips, error handling for
//! invalid inputs, and all supported algorithms (RSA, ECDSA P-256/P-384, Ed25519).

mod testutil;

#[cfg(all(feature = "native", any(not(windows), has_nasm)))]
use testutil::fx;

// =========================================================================
// RSA integration
// =========================================================================

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "rsa"))]
mod rsa_integration {
    use super::*;
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{self, KeyPair},
    };
    use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;
    use uselesskey_core::{Factory, Seed};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rsa_2048_sign_verify_roundtrip() {
        let fx = fx();
        let kp = fx.rsa("int-rsa-2048", RsaSpec::new(2048));
        let aws_kp = kp.rsa_key_pair_aws_lc_rs();

        let msg = b"rsa 2048 integration roundtrip";
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; aws_kp.public_modulus_len()];
        aws_kp
            .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("sign");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            aws_kp.public_key().as_ref(),
        );
        pk.verify(msg, &sig).expect("verify");
    }

    #[test]
    fn rsa_3072_sign_verify_roundtrip() {
        let fx = fx();
        let kp = fx.rsa("int-rsa-3072", RsaSpec::new(3072));
        let aws_kp = kp.rsa_key_pair_aws_lc_rs();

        let msg = b"rsa 3072 integration roundtrip";
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; aws_kp.public_modulus_len()];
        aws_kp
            .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("sign");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            aws_kp.public_key().as_ref(),
        );
        pk.verify(msg, &sig).expect("verify");
    }

    #[test]
    fn rsa_4096_sign_verify_roundtrip() {
        let fx = fx();
        let kp = fx.rsa("int-rsa-4096", RsaSpec::new(4096));
        let aws_kp = kp.rsa_key_pair_aws_lc_rs();

        let msg = b"rsa 4096 integration roundtrip";
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; aws_kp.public_modulus_len()];
        aws_kp
            .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("sign");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            aws_kp.public_key().as_ref(),
        );
        pk.verify(msg, &sig).expect("verify");
    }

    #[test]
    fn rsa_pss_sha256_sign_verify() {
        let fx = fx();
        let kp = fx.rsa("int-rsa-pss", RsaSpec::rs256());
        let aws_kp = kp.rsa_key_pair_aws_lc_rs();

        let msg = b"rsa pss integration";
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; aws_kp.public_modulus_len()];
        aws_kp
            .sign(&signature::RSA_PSS_SHA256, &rng, msg, &mut sig)
            .expect("sign with PSS");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PSS_2048_8192_SHA256,
            aws_kp.public_key().as_ref(),
        );
        pk.verify(msg, &sig).expect("verify PSS");
    }

    #[test]
    fn rsa_modulus_len_matches_spec() {
        let fx = fx();
        for (bits, label) in [(2048, "int-mod-2k"), (4096, "int-mod-4k")] {
            let kp = fx.rsa(label, RsaSpec::new(bits));
            let aws_kp = kp.rsa_key_pair_aws_lc_rs();
            assert_eq!(
                aws_kp.public_modulus_len(),
                bits / 8,
                "modulus_len should match {bits}-bit spec"
            );
        }
    }

    #[test]
    fn rsa_deterministic_conversion_is_stable() {
        let seed = Seed::from_env_value("int-aws-rsa-det").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.rsa("int-det-rsa", RsaSpec::rs256());
        let kp2 = fx2.rsa("int-det-rsa", RsaSpec::rs256());

        let aws1 = kp1.rsa_key_pair_aws_lc_rs();
        let aws2 = kp2.rsa_key_pair_aws_lc_rs();

        assert_eq!(
            aws1.public_key().as_ref(),
            aws2.public_key().as_ref(),
            "Deterministic keys should yield identical aws-lc-rs public keys"
        );
    }

    #[test]
    fn rsa_empty_message_sign_verify() {
        let fx = fx();
        let kp = fx.rsa("int-rsa-empty", RsaSpec::rs256());
        let aws_kp = kp.rsa_key_pair_aws_lc_rs();

        let msg = b"";
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; aws_kp.public_modulus_len()];
        aws_kp
            .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("sign empty msg");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            aws_kp.public_key().as_ref(),
        );
        pk.verify(msg, &sig).expect("verify empty msg");
    }

    #[test]
    fn rsa_large_message_sign_verify() {
        let fx = fx();
        let kp = fx.rsa("int-rsa-large", RsaSpec::rs256());
        let aws_kp = kp.rsa_key_pair_aws_lc_rs();

        let msg = vec![0xABu8; 64 * 1024];
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; aws_kp.public_modulus_len()];
        aws_kp
            .sign(&signature::RSA_PKCS1_SHA256, &rng, &msg, &mut sig)
            .expect("sign large msg");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            aws_kp.public_key().as_ref(),
        );
        pk.verify(&msg, &sig).expect("verify large msg");
    }

    #[test]
    fn rsa_invalid_signature_rejected() {
        let fx = fx();
        let kp = fx.rsa("int-rsa-invalid-sig", RsaSpec::rs256());
        let aws_kp = kp.rsa_key_pair_aws_lc_rs();

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            aws_kp.public_key().as_ref(),
        );
        // All-zeros is not a valid signature
        let bad_sig = vec![0u8; aws_kp.public_modulus_len()];
        assert!(
            pk.verify(b"any message", &bad_sig).is_err(),
            "All-zero signature should be rejected"
        );
    }

    #[test]
    fn rsa_truncated_signature_rejected() {
        let fx = fx();
        let kp = fx.rsa("int-rsa-trunc-sig", RsaSpec::rs256());
        let aws_kp = kp.rsa_key_pair_aws_lc_rs();

        let msg = b"truncation test";
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; aws_kp.public_modulus_len()];
        aws_kp
            .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("sign");

        // Truncate the signature
        let truncated = &sig[..sig.len() / 2];
        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            aws_kp.public_key().as_ref(),
        );
        assert!(
            pk.verify(msg, truncated).is_err(),
            "Truncated signature should be rejected"
        );
    }
}

// =========================================================================
// ECDSA integration
// =========================================================================

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ecdsa"))]
mod ecdsa_integration {
    use super::*;
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{self, KeyPair},
    };
    use uselesskey_aws_lc_rs::AwsLcRsEcdsaKeyPairExt;
    use uselesskey_core::{Factory, Seed};
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn ecdsa_p256_roundtrip() {
        let fx = fx();
        let kp = fx.ecdsa("int-ec-p256", EcdsaSpec::es256());
        let aws_kp = kp.ecdsa_key_pair_aws_lc_rs();

        let msg = b"ecdsa p256 integration";
        let rng = SystemRandom::new();
        let sig = aws_kp.sign(&rng, msg).expect("sign");

        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            aws_kp.public_key().as_ref(),
        );
        pk.verify(msg, sig.as_ref()).expect("verify");
    }

    #[test]
    fn ecdsa_p384_roundtrip() {
        let fx = fx();
        let kp = fx.ecdsa("int-ec-p384", EcdsaSpec::es384());
        let aws_kp = kp.ecdsa_key_pair_aws_lc_rs();

        let msg = b"ecdsa p384 integration";
        let rng = SystemRandom::new();
        let sig = aws_kp.sign(&rng, msg).expect("sign");

        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_ASN1,
            aws_kp.public_key().as_ref(),
        );
        pk.verify(msg, sig.as_ref()).expect("verify");
    }

    #[test]
    fn ecdsa_deterministic_conversion_is_stable() {
        let seed = Seed::from_env_value("int-aws-ecdsa-det").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ecdsa("int-det-ec", EcdsaSpec::es256());
        let kp2 = fx2.ecdsa("int-det-ec", EcdsaSpec::es256());

        let aws1 = kp1.ecdsa_key_pair_aws_lc_rs();
        let aws2 = kp2.ecdsa_key_pair_aws_lc_rs();

        assert_eq!(
            aws1.public_key().as_ref(),
            aws2.public_key().as_ref(),
            "Deterministic ECDSA keys should yield identical aws-lc-rs public keys"
        );
    }

    #[test]
    fn ecdsa_empty_message_sign_verify() {
        let fx = fx();
        let kp = fx.ecdsa("int-ec-empty", EcdsaSpec::es256());
        let aws_kp = kp.ecdsa_key_pair_aws_lc_rs();

        let msg = b"";
        let rng = SystemRandom::new();
        let sig = aws_kp.sign(&rng, msg).expect("sign empty msg");

        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            aws_kp.public_key().as_ref(),
        );
        pk.verify(msg, sig.as_ref()).expect("verify empty msg");
    }

    #[test]
    fn ecdsa_p256_wrong_key_rejects() {
        let fx = fx();
        let kp_a = fx.ecdsa("int-ec-a", EcdsaSpec::es256());
        let kp_b = fx.ecdsa("int-ec-b", EcdsaSpec::es256());

        let aws_a = kp_a.ecdsa_key_pair_aws_lc_rs();
        let aws_b = kp_b.ecdsa_key_pair_aws_lc_rs();

        let rng = SystemRandom::new();
        let sig = aws_a.sign(&rng, b"cross-key test").unwrap();

        let pk_b = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            aws_b.public_key().as_ref(),
        );
        assert!(pk_b.verify(b"cross-key test", sig.as_ref()).is_err());
    }

    #[test]
    fn ecdsa_p384_wrong_key_rejects() {
        let fx = fx();
        let kp_a = fx.ecdsa("int-ec384-a", EcdsaSpec::es384());
        let kp_b = fx.ecdsa("int-ec384-b", EcdsaSpec::es384());

        let aws_a = kp_a.ecdsa_key_pair_aws_lc_rs();
        let aws_b = kp_b.ecdsa_key_pair_aws_lc_rs();

        let rng = SystemRandom::new();
        let sig = aws_a.sign(&rng, b"cross-key p384").unwrap();

        let pk_b = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_ASN1,
            aws_b.public_key().as_ref(),
        );
        assert!(pk_b.verify(b"cross-key p384", sig.as_ref()).is_err());
    }

    #[test]
    fn ecdsa_tampered_message_rejected() {
        let fx = fx();
        let kp = fx.ecdsa("int-ec-tamper", EcdsaSpec::es256());
        let aws_kp = kp.ecdsa_key_pair_aws_lc_rs();

        let rng = SystemRandom::new();
        let sig = aws_kp.sign(&rng, b"original").unwrap();

        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            aws_kp.public_key().as_ref(),
        );
        assert!(pk.verify(b"tampered", sig.as_ref()).is_err());
    }
}

// =========================================================================
// Ed25519 integration
// =========================================================================

#[cfg(all(feature = "native", any(not(windows), has_nasm), feature = "ed25519"))]
mod ed25519_integration {
    use super::*;
    use aws_lc_rs::signature::{self, KeyPair};
    use uselesskey_aws_lc_rs::AwsLcRsEd25519KeyPairExt;
    use uselesskey_core::{Factory, Seed};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let fx = fx();
        let kp = fx.ed25519("int-ed-rt", Ed25519Spec::new());
        let aws_kp = kp.ed25519_key_pair_aws_lc_rs();

        let msg = b"ed25519 integration roundtrip";
        let sig = aws_kp.sign(msg);

        let pk =
            signature::UnparsedPublicKey::new(&signature::ED25519, aws_kp.public_key().as_ref());
        pk.verify(msg, sig.as_ref()).expect("verify");
    }

    #[test]
    fn ed25519_deterministic_signatures_identical() {
        let seed = Seed::from_env_value("int-aws-ed-det").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ed25519("int-ed-sig-det", Ed25519Spec::new());
        let kp2 = fx2.ed25519("int-ed-sig-det", Ed25519Spec::new());

        let aws1 = kp1.ed25519_key_pair_aws_lc_rs();
        let aws2 = kp2.ed25519_key_pair_aws_lc_rs();

        let msg = b"deterministic ed25519 signature";
        let sig1 = aws1.sign(msg);
        let sig2 = aws2.sign(msg);

        assert_eq!(
            sig1.as_ref(),
            sig2.as_ref(),
            "Ed25519 signatures should be deterministic for same key+message"
        );
    }

    #[test]
    fn ed25519_empty_message_sign_verify() {
        let fx = fx();
        let kp = fx.ed25519("int-ed-empty", Ed25519Spec::new());
        let aws_kp = kp.ed25519_key_pair_aws_lc_rs();

        let sig = aws_kp.sign(b"");
        let pk =
            signature::UnparsedPublicKey::new(&signature::ED25519, aws_kp.public_key().as_ref());
        pk.verify(b"", sig.as_ref()).expect("verify empty msg");
    }

    #[test]
    fn ed25519_wrong_key_rejects() {
        let fx = fx();
        let kp_a = fx.ed25519("int-ed-a", Ed25519Spec::new());
        let kp_b = fx.ed25519("int-ed-b", Ed25519Spec::new());

        let aws_a = kp_a.ed25519_key_pair_aws_lc_rs();
        let aws_b = kp_b.ed25519_key_pair_aws_lc_rs();

        let sig = aws_a.sign(b"cross-key ed25519");
        let pk_b =
            signature::UnparsedPublicKey::new(&signature::ED25519, aws_b.public_key().as_ref());
        assert!(pk_b.verify(b"cross-key ed25519", sig.as_ref()).is_err());
    }

    #[test]
    fn ed25519_tampered_message_rejected() {
        let fx = fx();
        let kp = fx.ed25519("int-ed-tamper", Ed25519Spec::new());
        let aws_kp = kp.ed25519_key_pair_aws_lc_rs();

        let sig = aws_kp.sign(b"original");
        let pk =
            signature::UnparsedPublicKey::new(&signature::ED25519, aws_kp.public_key().as_ref());
        pk.verify(b"original", sig.as_ref()).expect("verify ok");
        assert!(pk.verify(b"tampered", sig.as_ref()).is_err());
    }

    #[test]
    fn ed25519_large_message_sign_verify() {
        let fx = fx();
        let kp = fx.ed25519("int-ed-large", Ed25519Spec::new());
        let aws_kp = kp.ed25519_key_pair_aws_lc_rs();

        let msg = vec![0xCDu8; 64 * 1024];
        let sig = aws_kp.sign(&msg);
        let pk =
            signature::UnparsedPublicKey::new(&signature::ED25519, aws_kp.public_key().as_ref());
        pk.verify(&msg, sig.as_ref()).expect("verify large msg");
    }
}

// =========================================================================
// Cross-algorithm: all key types in one test
// =========================================================================

#[cfg(all(
    feature = "native",
    any(not(windows), has_nasm),
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519"
))]
mod all_algorithms {
    use super::*;
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{self, KeyPair},
    };
    use uselesskey_aws_lc_rs::{
        AwsLcRsEcdsaKeyPairExt, AwsLcRsEd25519KeyPairExt, AwsLcRsRsaKeyPairExt,
    };
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn all_key_types_from_same_factory() {
        let fx = fx();
        let rng = SystemRandom::new();
        let msg = b"all key types test";

        // RSA
        let rsa_kp = fx.rsa("int-all-rsa", RsaSpec::rs256());
        let aws_rsa = rsa_kp.rsa_key_pair_aws_lc_rs();
        let mut rsa_sig = vec![0u8; aws_rsa.public_modulus_len()];
        aws_rsa
            .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut rsa_sig)
            .expect("rsa sign");
        let rsa_pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            aws_rsa.public_key().as_ref(),
        );
        rsa_pk.verify(msg, &rsa_sig).expect("rsa verify");

        // ECDSA P-256
        let ec_kp = fx.ecdsa("int-all-ec256", EcdsaSpec::es256());
        let aws_ec = ec_kp.ecdsa_key_pair_aws_lc_rs();
        let ec_sig = aws_ec.sign(&rng, msg).expect("ecdsa sign");
        let ec_pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            aws_ec.public_key().as_ref(),
        );
        ec_pk.verify(msg, ec_sig.as_ref()).expect("ecdsa verify");

        // ECDSA P-384
        let ec384_kp = fx.ecdsa("int-all-ec384", EcdsaSpec::es384());
        let aws_ec384 = ec384_kp.ecdsa_key_pair_aws_lc_rs();
        let ec384_sig = aws_ec384.sign(&rng, msg).expect("ecdsa384 sign");
        let ec384_pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_ASN1,
            aws_ec384.public_key().as_ref(),
        );
        ec384_pk
            .verify(msg, ec384_sig.as_ref())
            .expect("ecdsa384 verify");

        // Ed25519
        let ed_kp = fx.ed25519("int-all-ed", Ed25519Spec::new());
        let aws_ed = ed_kp.ed25519_key_pair_aws_lc_rs();
        let ed_sig = aws_ed.sign(msg);
        let ed_pk =
            signature::UnparsedPublicKey::new(&signature::ED25519, aws_ed.public_key().as_ref());
        ed_pk.verify(msg, ed_sig.as_ref()).expect("ed25519 verify");
    }

    #[test]
    fn cross_algorithm_verification_always_fails() {
        let fx = fx();
        let rng = SystemRandom::new();

        let rsa_kp = fx
            .rsa("int-cross-rsa", RsaSpec::rs256())
            .rsa_key_pair_aws_lc_rs();
        let ec_kp = fx
            .ecdsa("int-cross-ec", EcdsaSpec::es256())
            .ecdsa_key_pair_aws_lc_rs();
        let ed_kp = fx
            .ed25519("int-cross-ed", Ed25519Spec::new())
            .ed25519_key_pair_aws_lc_rs();

        // RSA sig with ECDSA verifier
        let mut rsa_sig = vec![0u8; rsa_kp.public_modulus_len()];
        rsa_kp
            .sign(&signature::RSA_PKCS1_SHA256, &rng, b"msg", &mut rsa_sig)
            .unwrap();
        let ec_pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            ec_kp.public_key().as_ref(),
        );
        assert!(ec_pk.verify(b"msg", &rsa_sig).is_err());

        // Ed25519 sig with ECDSA verifier
        let ed_sig = ed_kp.sign(b"msg");
        assert!(ec_pk.verify(b"msg", ed_sig.as_ref()).is_err());

        // ECDSA sig with Ed25519 verifier
        let ec_sig = ec_kp.sign(&rng, b"msg").unwrap();
        let ed_pk =
            signature::UnparsedPublicKey::new(&signature::ED25519, ed_kp.public_key().as_ref());
        assert!(ed_pk.verify(b"msg", ec_sig.as_ref()).is_err());
    }
}
