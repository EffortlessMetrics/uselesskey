//! Comprehensive tests for uselesskey-rustcrypto integration
//!
//! Tests cover:
//! - RustCrypto-specific key conversions for RSA, ECDSA, Ed25519
//! - Sign/verify roundtrips
//! - HMAC sign/verify workflows
//! - Deterministic key behavior
//! - Cross-key verification failures
//! - Message and signature tampering detection
//! - Error handling for curve mismatches

mod testutil;

// =========================================================================
// RSA
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_rustcrypto_tests {
    use crate::testutil::fx;
    use rsa::pkcs1v15::{SigningKey, VerifyingKey};
    use rsa::signature::{SignatureEncoding, Signer, Verifier};
    use sha2::Sha256;
    use uselesskey_core::{Factory, Seed};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustcrypto::RustCryptoRsaExt;

    #[test]
    fn test_rsa_private_key_conversion() {
        let fx = fx();
        let keypair = fx.rsa("rsa-conv", RsaSpec::rs256());
        let private_key = keypair.rsa_private_key();

        // Validate by signing (will panic if key is invalid)
        let signing_key = SigningKey::<Sha256>::new_unprefixed(private_key);
        let _sig = signing_key.sign(b"smoke test");
    }

    #[test]
    fn test_rsa_public_key_conversion() {
        let fx = fx();
        let keypair = fx.rsa("rsa-pub-conv", RsaSpec::rs256());
        let public_key = keypair.rsa_public_key();

        // Public key modulus should match private key's
        let private_key = keypair.rsa_private_key();
        assert_eq!(
            rsa::RsaPublicKey::from(private_key),
            public_key,
            "Public key derived from extension should match private key's public component"
        );
    }

    #[test]
    fn test_rsa_sign_verify_roundtrip() {
        let fx = fx();
        let keypair = fx.rsa("rsa-roundtrip", RsaSpec::rs256());

        let signing_key = SigningKey::<Sha256>::new_unprefixed(keypair.rsa_private_key());
        let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(keypair.rsa_public_key());

        let msg = b"hello rustcrypto world";
        let signature = signing_key.sign(msg);

        verifying_key
            .verify(msg, &signature)
            .expect("RSA sign/verify roundtrip should succeed");
    }

    #[test]
    fn test_rsa_different_key_sizes() {
        let test_cases = [(2048, "rsa-2048"), (3072, "rsa-3072"), (4096, "rsa-4096")];

        for (bits, label) in test_cases {
            let fx = fx();
            let keypair = fx.rsa(label, RsaSpec::new(bits));

            let signing_key = SigningKey::<Sha256>::new_unprefixed(keypair.rsa_private_key());
            let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(keypair.rsa_public_key());

            let msg = format!("test message for {bits}-bit key");
            let signature = signing_key.sign(msg.as_bytes());

            verifying_key
                .verify(msg.as_bytes(), &signature)
                .unwrap_or_else(|e| panic!("Failed to verify {bits}-bit RSA signature: {e}"));
        }
    }

    #[test]
    fn test_rsa_deterministic_keys() {
        let seed = Seed::from_env_value("rsa-det-rustcrypto-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.rsa("det-rsa", RsaSpec::rs256());
        let kp2 = fx2.rsa("det-rsa", RsaSpec::rs256());

        assert_eq!(
            kp1.private_key_pkcs8_der(),
            kp2.private_key_pkcs8_der(),
            "Deterministic RSA keys should produce identical DER"
        );

        // Both keys should produce valid signatures verifiable by the other
        let signing1 = SigningKey::<Sha256>::new_unprefixed(kp1.rsa_private_key());
        let verifying2 = VerifyingKey::<Sha256>::new_unprefixed(kp2.rsa_public_key());

        let sig = signing1.sign(b"deterministic");
        verifying2
            .verify(b"deterministic", &sig)
            .expect("Cross-factory verify should work for deterministic keys");
    }

    #[test]
    fn test_rsa_cross_key_verification_fails() {
        let fx = fx();
        let kp_a = fx.rsa("rsa-key-a", RsaSpec::rs256());
        let kp_b = fx.rsa("rsa-key-b", RsaSpec::rs256());

        let signing_key_a = SigningKey::<Sha256>::new_unprefixed(kp_a.rsa_private_key());
        let verifying_key_b = VerifyingKey::<Sha256>::new_unprefixed(kp_b.rsa_public_key());

        let sig = signing_key_a.sign(b"signed by A");
        let result = verifying_key_b.verify(b"signed by A", &sig);
        assert!(
            result.is_err(),
            "Verification with wrong RSA key should fail"
        );
    }

    #[test]
    fn test_rsa_signature_tampering_detected() {
        let fx = fx();
        let keypair = fx.rsa("rsa-tamper", RsaSpec::rs256());

        let signing_key = SigningKey::<Sha256>::new_unprefixed(keypair.rsa_private_key());
        let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(keypair.rsa_public_key());

        let sig = signing_key.sign(b"original");
        let mut sig_bytes = sig.to_vec();
        // Flip a bit in the signature
        if let Some(last) = sig_bytes.last_mut() {
            *last = last.wrapping_add(1);
        }

        let tampered_sig =
            rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).expect("parse tampered sig");
        let result = verifying_key.verify(b"original", &tampered_sig);
        assert!(result.is_err(), "Tampered RSA signature should not verify");
    }

    #[test]
    fn test_rsa_message_tampering_detected() {
        let fx = fx();
        let keypair = fx.rsa("rsa-msg-tamper", RsaSpec::rs256());

        let signing_key = SigningKey::<Sha256>::new_unprefixed(keypair.rsa_private_key());
        let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(keypair.rsa_public_key());

        let sig = signing_key.sign(b"original message");

        verifying_key
            .verify(b"original message", &sig)
            .expect("original should verify");

        let result = verifying_key.verify(b"tampered message", &sig);
        assert!(result.is_err(), "Tampered message should not verify");
    }
}

// =========================================================================
// ECDSA
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_rustcrypto_tests {
    use crate::testutil::fx;
    use uselesskey_core::{Factory, Seed};
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_rustcrypto::RustCryptoEcdsaExt;

    #[test]
    fn test_p256_sign_verify_roundtrip() {
        use p256::ecdsa::signature::{Signer, Verifier};

        let fx = fx();
        let keypair = fx.ecdsa("p256-roundtrip", EcdsaSpec::es256());

        let signing_key = keypair.p256_signing_key();
        let verifying_key = keypair.p256_verifying_key();

        let msg = b"hello P-256 rustcrypto";
        let signature: p256::ecdsa::Signature = signing_key.sign(msg);

        verifying_key
            .verify(msg, &signature)
            .expect("P-256 sign/verify roundtrip should succeed");
    }

    #[test]
    fn test_p384_sign_verify_roundtrip() {
        use p384::ecdsa::signature::{Signer, Verifier};

        let fx = fx();
        let keypair = fx.ecdsa("p384-roundtrip", EcdsaSpec::es384());

        let signing_key = keypair.p384_signing_key();
        let verifying_key = keypair.p384_verifying_key();

        let msg = b"hello P-384 rustcrypto";
        let signature: p384::ecdsa::Signature = signing_key.sign(msg);

        verifying_key
            .verify(msg, &signature)
            .expect("P-384 sign/verify roundtrip should succeed");
    }

    #[test]
    fn test_ecdsa_deterministic_keys_p256() {
        use p256::ecdsa::signature::{Signer, Verifier};

        let seed = Seed::from_env_value("ecdsa-det-rustcrypto-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ecdsa("det-p256", EcdsaSpec::es256());
        let kp2 = fx2.ecdsa("det-p256", EcdsaSpec::es256());

        assert_eq!(
            kp1.private_key_pkcs8_der(),
            kp2.private_key_pkcs8_der(),
            "Deterministic P-256 keys should produce identical DER"
        );

        // Signature from key1 should verify with key2's verifying key
        let sig: p256::ecdsa::Signature = kp1.p256_signing_key().sign(b"deterministic");
        kp2.p256_verifying_key()
            .verify(b"deterministic", &sig)
            .expect("Cross-factory P-256 verify should work for deterministic keys");
    }

    #[test]
    fn test_ecdsa_deterministic_keys_p384() {
        use p384::ecdsa::signature::{Signer, Verifier};

        let seed = Seed::from_env_value("ecdsa-det-rustcrypto-p384-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ecdsa("det-p384", EcdsaSpec::es384());
        let kp2 = fx2.ecdsa("det-p384", EcdsaSpec::es384());

        assert_eq!(
            kp1.private_key_pkcs8_der(),
            kp2.private_key_pkcs8_der(),
            "Deterministic P-384 keys should produce identical DER"
        );

        let sig: p384::ecdsa::Signature = kp1.p384_signing_key().sign(b"deterministic-384");
        kp2.p384_verifying_key()
            .verify(b"deterministic-384", &sig)
            .expect("Cross-factory P-384 verify should work for deterministic keys");
    }

    #[test]
    fn test_p256_cross_key_verification_fails() {
        use p256::ecdsa::signature::{Signer, Verifier};

        let fx = fx();
        let kp_a = fx.ecdsa("p256-key-a", EcdsaSpec::es256());
        let kp_b = fx.ecdsa("p256-key-b", EcdsaSpec::es256());

        let sig: p256::ecdsa::Signature = kp_a.p256_signing_key().sign(b"signed by A");
        let result = kp_b.p256_verifying_key().verify(b"signed by A", &sig);
        assert!(
            result.is_err(),
            "P-256 verification with wrong key should fail"
        );
    }

    #[test]
    fn test_p384_cross_key_verification_fails() {
        use p384::ecdsa::signature::{Signer, Verifier};

        let fx = fx();
        let kp_a = fx.ecdsa("p384-key-a", EcdsaSpec::es384());
        let kp_b = fx.ecdsa("p384-key-b", EcdsaSpec::es384());

        let sig: p384::ecdsa::Signature = kp_a.p384_signing_key().sign(b"signed by A");
        let result = kp_b.p384_verifying_key().verify(b"signed by A", &sig);
        assert!(
            result.is_err(),
            "P-384 verification with wrong key should fail"
        );
    }

    #[test]
    fn test_p256_message_tampering_detected() {
        use p256::ecdsa::signature::{Signer, Verifier};

        let fx = fx();
        let keypair = fx.ecdsa("p256-tamper", EcdsaSpec::es256());

        let sig: p256::ecdsa::Signature = keypair.p256_signing_key().sign(b"original message");

        keypair
            .p256_verifying_key()
            .verify(b"original message", &sig)
            .expect("original should verify");

        let result = keypair
            .p256_verifying_key()
            .verify(b"tampered message", &sig);
        assert!(
            result.is_err(),
            "Tampered message should not verify with P-256"
        );
    }

    #[test]
    fn test_p384_message_tampering_detected() {
        use p384::ecdsa::signature::{Signer, Verifier};

        let fx = fx();
        let keypair = fx.ecdsa("p384-tamper", EcdsaSpec::es384());

        let sig: p384::ecdsa::Signature = keypair.p384_signing_key().sign(b"original message");

        keypair
            .p384_verifying_key()
            .verify(b"original message", &sig)
            .expect("original should verify");

        let result = keypair
            .p384_verifying_key()
            .verify(b"tampered message", &sig);
        assert!(
            result.is_err(),
            "Tampered message should not verify with P-384"
        );
    }

    #[test]
    #[should_panic(expected = "expected P-384")]
    fn test_p384_method_on_p256_key_panics() {
        let fx = fx();
        let keypair = fx.ecdsa("wrong-curve-256", EcdsaSpec::es256());
        let _ = keypair.p384_signing_key();
    }

    #[test]
    #[should_panic(expected = "expected P-256")]
    fn test_p256_method_on_p384_key_panics() {
        let fx = fx();
        let keypair = fx.ecdsa("wrong-curve-384", EcdsaSpec::es384());
        let _ = keypair.p256_signing_key();
    }

    #[test]
    #[should_panic(expected = "expected P-384")]
    fn test_p384_verifying_key_on_p256_key_panics() {
        let fx = fx();
        let keypair = fx.ecdsa("wrong-curve-vk-256", EcdsaSpec::es256());
        let _ = keypair.p384_verifying_key();
    }

    #[test]
    #[should_panic(expected = "expected P-256")]
    fn test_p256_verifying_key_on_p384_key_panics() {
        let fx = fx();
        let keypair = fx.ecdsa("wrong-curve-vk-384", EcdsaSpec::es384());
        let _ = keypair.p256_verifying_key();
    }
}

// =========================================================================
// Ed25519
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_rustcrypto_tests {
    use crate::testutil::fx;
    use ed25519_dalek::{Signer, Verifier};
    use uselesskey_core::{Factory, Seed};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rustcrypto::RustCryptoEd25519Ext;

    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
        let fx = fx();
        let keypair = fx.ed25519("ed-roundtrip", Ed25519Spec::new());

        let signing_key = keypair.ed25519_signing_key();
        let verifying_key = keypair.ed25519_verifying_key();

        let msg = b"hello ed25519 rustcrypto";
        let signature = signing_key.sign(msg);

        verifying_key
            .verify(msg, &signature)
            .expect("Ed25519 sign/verify roundtrip should succeed");
    }

    #[test]
    fn test_ed25519_deterministic_keys() {
        let seed = Seed::from_env_value("ed25519-det-rustcrypto-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ed25519("det-ed25519", Ed25519Spec::new());
        let kp2 = fx2.ed25519("det-ed25519", Ed25519Spec::new());

        assert_eq!(
            kp1.private_key_pkcs8_der(),
            kp2.private_key_pkcs8_der(),
            "Deterministic Ed25519 keys should produce identical DER"
        );

        // Ed25519 signatures are deterministic, so same key + same message → same signature
        let sig1 = kp1.ed25519_signing_key().sign(b"deterministic");
        let sig2 = kp2.ed25519_signing_key().sign(b"deterministic");
        assert_eq!(
            sig1.to_bytes(),
            sig2.to_bytes(),
            "Ed25519 signatures from identical keys should be identical"
        );

        // Cross-verify
        kp2.ed25519_verifying_key()
            .verify(b"deterministic", &sig1)
            .expect("Cross-factory Ed25519 verify should work for deterministic keys");
    }

    #[test]
    fn test_ed25519_cross_key_verification_fails() {
        let fx = fx();
        let kp_a = fx.ed25519("ed-key-a", Ed25519Spec::new());
        let kp_b = fx.ed25519("ed-key-b", Ed25519Spec::new());

        let sig = kp_a.ed25519_signing_key().sign(b"signed by A");
        let result = kp_b.ed25519_verifying_key().verify(b"signed by A", &sig);
        assert!(
            result.is_err(),
            "Ed25519 verification with wrong key should fail"
        );
    }

    #[test]
    fn test_ed25519_message_tampering_detected() {
        let fx = fx();
        let keypair = fx.ed25519("ed-tamper", Ed25519Spec::new());

        let sig = keypair.ed25519_signing_key().sign(b"original message");

        keypair
            .ed25519_verifying_key()
            .verify(b"original message", &sig)
            .expect("original should verify");

        let result = keypair
            .ed25519_verifying_key()
            .verify(b"tampered message", &sig);
        assert!(
            result.is_err(),
            "Tampered message should not verify with Ed25519"
        );
    }

    #[test]
    fn test_ed25519_signature_tampering_detected() {
        let fx = fx();
        let keypair = fx.ed25519("ed-sig-tamper", Ed25519Spec::new());

        let sig = keypair.ed25519_signing_key().sign(b"test message");
        let mut sig_bytes = sig.to_bytes();
        // Flip a bit
        sig_bytes[0] ^= 0x01;

        let tampered_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let result = keypair
            .ed25519_verifying_key()
            .verify(b"test message", &tampered_sig);
        assert!(
            result.is_err(),
            "Tampered Ed25519 signature should not verify"
        );
    }

    #[test]
    fn test_ed25519_verifying_key_matches_signing_key() {
        let fx = fx();
        let keypair = fx.ed25519("ed-key-match", Ed25519Spec::new());

        let signing_key = keypair.ed25519_signing_key();
        let verifying_key = keypair.ed25519_verifying_key();

        assert_eq!(
            signing_key.verifying_key(),
            verifying_key,
            "Verifying key from extension should match signing key's verifying key"
        );
    }
}

// =========================================================================
// HMAC
// =========================================================================

#[cfg(feature = "hmac")]
mod hmac_rustcrypto_tests {
    use crate::testutil::fx;
    use hmac::Mac;
    use uselesskey_core::{Factory, Seed};
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    use uselesskey_rustcrypto::RustCryptoHmacExt;

    #[test]
    fn test_hmac_sha256_sign_verify() {
        let fx = fx();
        let secret = fx.hmac("hmac-256", HmacSpec::hs256());

        let mut mac = secret.hmac_sha256();
        mac.update(b"test message");
        let tag = mac.finalize();

        let mut verifier = secret.hmac_sha256();
        verifier.update(b"test message");
        verifier
            .verify(&tag.into_bytes())
            .expect("HMAC-SHA256 verify should succeed");
    }

    #[test]
    fn test_hmac_sha384_sign_verify() {
        let fx = fx();
        let secret = fx.hmac("hmac-384", HmacSpec::hs384());

        let mut mac = secret.hmac_sha384();
        mac.update(b"test message");
        let tag = mac.finalize();

        let mut verifier = secret.hmac_sha384();
        verifier.update(b"test message");
        verifier
            .verify(&tag.into_bytes())
            .expect("HMAC-SHA384 verify should succeed");
    }

    #[test]
    fn test_hmac_sha512_sign_verify() {
        let fx = fx();
        let secret = fx.hmac("hmac-512", HmacSpec::hs512());

        let mut mac = secret.hmac_sha512();
        mac.update(b"test message");
        let tag = mac.finalize();

        let mut verifier = secret.hmac_sha512();
        verifier.update(b"test message");
        verifier
            .verify(&tag.into_bytes())
            .expect("HMAC-SHA512 verify should succeed");
    }

    #[test]
    fn test_hmac_wrong_message_fails() {
        let fx = fx();
        let secret = fx.hmac("hmac-wrong-msg", HmacSpec::hs256());

        let mut mac = secret.hmac_sha256();
        mac.update(b"original message");
        let tag = mac.finalize();

        let mut verifier = secret.hmac_sha256();
        verifier.update(b"tampered message");
        let result = verifier.verify(&tag.into_bytes());
        assert!(
            result.is_err(),
            "HMAC verify should fail with tampered message"
        );
    }

    #[test]
    fn test_hmac_wrong_key_fails() {
        let fx = fx();
        let secret_a = fx.hmac("hmac-key-a", HmacSpec::hs256());
        let secret_b = fx.hmac("hmac-key-b", HmacSpec::hs256());

        let mut mac = secret_a.hmac_sha256();
        mac.update(b"test message");
        let tag = mac.finalize();

        let mut verifier = secret_b.hmac_sha256();
        verifier.update(b"test message");
        let result = verifier.verify(&tag.into_bytes());
        assert!(result.is_err(), "HMAC verify should fail with wrong key");
    }

    #[test]
    fn test_hmac_deterministic() {
        let seed = Seed::from_env_value("hmac-det-rustcrypto-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let s1 = fx1.hmac("det-hmac", HmacSpec::hs256());
        let s2 = fx2.hmac("det-hmac", HmacSpec::hs256());

        assert_eq!(
            s1.secret_bytes(),
            s2.secret_bytes(),
            "Deterministic HMAC secrets should be identical"
        );

        // Tags from identical secrets should be identical
        let mut mac1 = s1.hmac_sha256();
        mac1.update(b"deterministic");
        let tag1 = mac1.finalize();

        let mut mac2 = s2.hmac_sha256();
        mac2.update(b"deterministic");
        let tag2 = mac2.finalize();

        assert_eq!(
            tag1.into_bytes()[..],
            tag2.into_bytes()[..],
            "HMAC tags from identical deterministic secrets should match"
        );
    }

    #[test]
    fn test_hmac_different_algorithms_produce_different_tags() {
        let fx = fx();
        let secret = fx.hmac("hmac-diff-alg", HmacSpec::hs256());

        let mut mac256 = secret.hmac_sha256();
        mac256.update(b"same message");
        let tag256 = mac256.finalize().into_bytes();

        let mut mac512 = secret.hmac_sha512();
        mac512.update(b"same message");
        let tag512 = mac512.finalize().into_bytes();

        // Different lengths guarantee inequality, but let's be explicit
        assert_ne!(
            tag256.len(),
            tag512.len(),
            "SHA-256 and SHA-512 HMAC tags should have different lengths"
        );
    }
}

// =========================================================================
// Cross-algorithm tests
// =========================================================================

#[cfg(all(feature = "rsa", feature = "ecdsa", feature = "ed25519"))]
mod cross_algorithm_tests {
    use crate::testutil::fx;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustcrypto::{RustCryptoEcdsaExt, RustCryptoEd25519Ext, RustCryptoRsaExt};

    /// Different algorithm keys should all coexist and produce independent fixtures.
    #[test]
    fn test_different_algorithms_independent() {
        let fx = fx();
        let rsa_kp = fx.rsa("cross-algo", RsaSpec::rs256());
        let ecdsa_kp = fx.ecdsa("cross-algo", EcdsaSpec::es256());
        let ed_kp = fx.ed25519("cross-algo", Ed25519Spec::new());

        // All keys should convert without error
        let _rsa_priv = rsa_kp.rsa_private_key();
        let _p256_sign = ecdsa_kp.p256_signing_key();
        let _ed_sign = ed_kp.ed25519_signing_key();

        // Each sign/verify should work independently
        {
            use rsa::signature::{Signer, Verifier};
            let sk =
                rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new_unprefixed(rsa_kp.rsa_private_key());
            let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new_unprefixed(
                rsa_kp.rsa_public_key(),
            );
            let sig = sk.sign(b"cross-algo");
            vk.verify(b"cross-algo", &sig).expect("RSA verify");
        }
        {
            use p256::ecdsa::signature::{Signer, Verifier};
            let sig: p256::ecdsa::Signature = ecdsa_kp.p256_signing_key().sign(b"cross-algo");
            ecdsa_kp
                .p256_verifying_key()
                .verify(b"cross-algo", &sig)
                .expect("P-256 verify");
        }
        {
            use ed25519_dalek::{Signer, Verifier};
            let sig = ed_kp.ed25519_signing_key().sign(b"cross-algo");
            ed_kp
                .ed25519_verifying_key()
                .verify(b"cross-algo", &sig)
                .expect("Ed25519 verify");
        }
    }
}
