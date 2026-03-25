//! Cross-adapter integration tests for uselesskey-rustcrypto.
//!
//! Tests cover:
//! - RSA signature verification through RustCrypto
//! - ECDSA verification through RustCrypto (P-256 and P-384)
//! - Ed25519 sign/verify through ed25519-dalek
//! - Key serialization round-trips (DER -> RustCrypto -> DER)
//! - Deterministic mode consistency

use std::sync::OnceLock;

use uselesskey_core::{Factory, Seed};

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-rustcrypto-adapter-integration-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
    .clone()
}

// =========================================================================
// RSA signature verification through RustCrypto
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_rustcrypto {
    use super::*;
    use rsa::pkcs1v15::{SigningKey, VerifyingKey};
    use rsa::sha2::Sha256;
    use rsa::signature::{Signer, Verifier};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustcrypto::RustCryptoRsaExt;

    #[test]
    fn rsa_sign_verify_roundtrip() {
        let fx = fx();
        let kp = fx.rsa("rc-rsa-rt", RsaSpec::rs256());

        let signing_key = SigningKey::<Sha256>::new_unprefixed(kp.rsa_private_key());
        let signature = signing_key.sign(b"hello rustcrypto");

        let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(kp.rsa_public_key());
        verifying_key
            .verify(b"hello rustcrypto", &signature)
            .expect("verify");
    }

    #[test]
    fn rsa_wrong_message_rejects() {
        let fx = fx();
        let kp = fx.rsa("rc-rsa-reject", RsaSpec::rs256());

        let signing_key = SigningKey::<Sha256>::new_unprefixed(kp.rsa_private_key());
        let signature = signing_key.sign(b"correct");

        let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(kp.rsa_public_key());
        assert!(verifying_key.verify(b"wrong", &signature).is_err());
    }

    #[test]
    fn rsa_wrong_key_rejects() {
        let fx = fx();
        let kp_a = fx.rsa("rc-rsa-a", RsaSpec::rs256());
        let kp_b = fx.rsa("rc-rsa-b", RsaSpec::rs256());

        let signing_key = SigningKey::<Sha256>::new_unprefixed(kp_a.rsa_private_key());
        let signature = signing_key.sign(b"cross-key");

        let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(kp_b.rsa_public_key());
        assert!(verifying_key.verify(b"cross-key", &signature).is_err());
    }

    #[test]
    fn rsa_deterministic_same_keys() {
        let seed = Seed::from_env_value("rc-rsa-det").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.rsa("det-rsa", RsaSpec::rs256());
        let kp2 = fx2.rsa("det-rsa", RsaSpec::rs256());

        assert_eq!(kp1.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());

        // Sign with one, verify with the other (same key)
        let signing_key = SigningKey::<Sha256>::new_unprefixed(kp1.rsa_private_key());
        let signature = signing_key.sign(b"deterministic");

        let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(kp2.rsa_public_key());
        verifying_key
            .verify(b"deterministic", &signature)
            .expect("cross-instance verify");
    }

    #[test]
    fn rsa_key_serialization_roundtrip() {
        use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};

        let fx = fx();
        let kp = fx.rsa("rc-rsa-serde", RsaSpec::rs256());

        let private_key = kp.rsa_private_key();
        let re_encoded = private_key.to_pkcs8_der().expect("encode");
        let decoded = rsa::RsaPrivateKey::from_pkcs8_der(re_encoded.as_bytes()).expect("re-decode");

        // Verify the round-tripped key still works
        let signing_key = SigningKey::<Sha256>::new_unprefixed(decoded);
        let signature = signing_key.sign(b"round-trip");

        let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(kp.rsa_public_key());
        verifying_key
            .verify(b"round-trip", &signature)
            .expect("verify after round-trip");
    }
}

// =========================================================================
// ECDSA verification through RustCrypto
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_rustcrypto {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_rustcrypto::RustCryptoEcdsaExt;

    #[test]
    fn p256_sign_verify_roundtrip() {
        use p256::ecdsa::signature::{Signer, Verifier};

        let fx = fx();
        let kp = fx.ecdsa("rc-p256-rt", EcdsaSpec::es256());

        let signing_key = kp.p256_signing_key();
        let sig: p256::ecdsa::Signature = signing_key.sign(b"p256 hello");

        let verifying_key = kp.p256_verifying_key();
        verifying_key.verify(b"p256 hello", &sig).expect("verify");
    }

    #[test]
    fn p384_sign_verify_roundtrip() {
        use p384::ecdsa::signature::{Signer, Verifier};

        let fx = fx();
        let kp = fx.ecdsa("rc-p384-rt", EcdsaSpec::es384());

        let signing_key = kp.p384_signing_key();
        let sig: p384::ecdsa::Signature = signing_key.sign(b"p384 hello");

        let verifying_key = kp.p384_verifying_key();
        verifying_key.verify(b"p384 hello", &sig).expect("verify");
    }

    #[test]
    fn p256_wrong_message_rejects() {
        use p256::ecdsa::signature::{Signer, Verifier};

        let fx = fx();
        let kp = fx.ecdsa("rc-p256-reject", EcdsaSpec::es256());

        let sig: p256::ecdsa::Signature = kp.p256_signing_key().sign(b"correct");
        assert!(kp.p256_verifying_key().verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn p384_wrong_key_rejects() {
        use p384::ecdsa::signature::{Signer, Verifier};

        let fx = fx();
        let kp_a = fx.ecdsa("rc-p384-a", EcdsaSpec::es384());
        let kp_b = fx.ecdsa("rc-p384-b", EcdsaSpec::es384());

        let sig: p384::ecdsa::Signature = kp_a.p384_signing_key().sign(b"cross-key");
        assert!(
            kp_b.p384_verifying_key()
                .verify(b"cross-key", &sig)
                .is_err()
        );
    }

    #[test]
    fn ecdsa_deterministic_same_keys() {
        let seed = Seed::from_env_value("rc-ecdsa-det").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ecdsa("det-ec", EcdsaSpec::es256());
        let kp2 = fx2.ecdsa("det-ec", EcdsaSpec::es256());

        assert_eq!(kp1.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());
    }

    #[test]
    fn p256_key_serialization_roundtrip() {
        use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};

        let fx = fx();
        let kp = fx.ecdsa("rc-p256-serde", EcdsaSpec::es256());

        let signing_key = kp.p256_signing_key();
        let encoded = signing_key.to_pkcs8_der().expect("encode");
        let decoded = p256::ecdsa::SigningKey::from_pkcs8_der(encoded.as_bytes()).expect("decode");

        // Verify round-tripped key produces valid signatures
        use p256::ecdsa::signature::{Signer, Verifier};
        let sig: p256::ecdsa::Signature = decoded.sign(b"round-trip");
        kp.p256_verifying_key()
            .verify(b"round-trip", &sig)
            .expect("verify after round-trip");
    }

    #[test]
    fn p384_key_serialization_roundtrip() {
        use p384::pkcs8::{DecodePrivateKey, EncodePrivateKey};

        let fx = fx();
        let kp = fx.ecdsa("rc-p384-serde", EcdsaSpec::es384());

        let signing_key = kp.p384_signing_key();
        let encoded = signing_key.to_pkcs8_der().expect("encode");
        let decoded = p384::ecdsa::SigningKey::from_pkcs8_der(encoded.as_bytes()).expect("decode");

        use p384::ecdsa::signature::{Signer, Verifier};
        let sig: p384::ecdsa::Signature = decoded.sign(b"round-trip");
        kp.p384_verifying_key()
            .verify(b"round-trip", &sig)
            .expect("verify after round-trip");
    }

    #[test]
    #[should_panic(expected = "expected P-384")]
    fn p384_on_p256_key_panics() {
        let fx = fx();
        let kp = fx.ecdsa("rc-wrong-curve", EcdsaSpec::es256());
        let _ = kp.p384_signing_key();
    }
}

// =========================================================================
// Ed25519 through ed25519-dalek
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_rustcrypto {
    use super::*;
    use ed25519_dalek::{Signer, Verifier};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rustcrypto::RustCryptoEd25519Ext;

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let fx = fx();
        let kp = fx.ed25519("rc-ed-rt", Ed25519Spec::new());

        let signing_key = kp.ed25519_signing_key();
        let sig = signing_key.sign(b"ed25519 hello");

        let verifying_key = kp.ed25519_verifying_key();
        verifying_key
            .verify(b"ed25519 hello", &sig)
            .expect("verify");
    }

    #[test]
    fn ed25519_wrong_message_rejects() {
        let fx = fx();
        let kp = fx.ed25519("rc-ed-reject", Ed25519Spec::new());

        let sig = kp.ed25519_signing_key().sign(b"correct");
        assert!(kp.ed25519_verifying_key().verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn ed25519_wrong_key_rejects() {
        let fx = fx();
        let kp_a = fx.ed25519("rc-ed-a", Ed25519Spec::new());
        let kp_b = fx.ed25519("rc-ed-b", Ed25519Spec::new());

        let sig = kp_a.ed25519_signing_key().sign(b"cross-key");
        assert!(
            kp_b.ed25519_verifying_key()
                .verify(b"cross-key", &sig)
                .is_err()
        );
    }

    #[test]
    fn ed25519_deterministic_same_keys() {
        let seed = Seed::from_env_value("rc-ed-det").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ed25519("det-ed", Ed25519Spec::new());
        let kp2 = fx2.ed25519("det-ed", Ed25519Spec::new());

        assert_eq!(kp1.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());

        // Deterministic signatures
        let sig1 = kp1.ed25519_signing_key().sign(b"det msg");
        let sig2 = kp2.ed25519_signing_key().sign(b"det msg");
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn ed25519_key_serialization_roundtrip() {
        use ed25519_dalek::pkcs8::DecodePrivateKey;

        let fx = fx();
        let kp = fx.ed25519("rc-ed-serde", Ed25519Spec::new());

        let signing_key = kp.ed25519_signing_key();
        let der_bytes = kp.private_key_pkcs8_der();
        let decoded = ed25519_dalek::SigningKey::from_pkcs8_der(der_bytes).expect("decode");

        assert_eq!(
            signing_key.verifying_key(),
            decoded.verifying_key(),
            "round-tripped key should have same verifying key"
        );
    }
}

// =========================================================================
// HMAC through RustCrypto
// =========================================================================

#[cfg(feature = "hmac")]
mod hmac_rustcrypto {
    use super::*;
    use hmac::Mac;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    use uselesskey_rustcrypto::RustCryptoHmacExt;

    #[test]
    fn hmac_sha256_create_and_verify() {
        let fx = fx();
        let secret = fx.hmac("rc-hmac-256", HmacSpec::hs256());

        let mut mac = secret.hmac_sha256();
        mac.update(b"hmac message");
        let result = mac.finalize();

        let mut mac2 = secret.hmac_sha256();
        mac2.update(b"hmac message");
        mac2.verify(&result.into_bytes()).expect("verify");
    }

    #[test]
    fn hmac_sha384_create_and_verify() {
        let fx = fx();
        let secret = fx.hmac("rc-hmac-384", HmacSpec::hs384());

        let mut mac = secret.hmac_sha384();
        mac.update(b"hmac384 message");
        let result = mac.finalize();

        let mut mac2 = secret.hmac_sha384();
        mac2.update(b"hmac384 message");
        mac2.verify(&result.into_bytes()).expect("verify");
    }

    #[test]
    fn hmac_sha512_create_and_verify() {
        let fx = fx();
        let secret = fx.hmac("rc-hmac-512", HmacSpec::hs512());

        let mut mac = secret.hmac_sha512();
        mac.update(b"hmac512 message");
        let result = mac.finalize();

        let mut mac2 = secret.hmac_sha512();
        mac2.update(b"hmac512 message");
        mac2.verify(&result.into_bytes()).expect("verify");
    }

    #[test]
    fn hmac_different_secrets_produce_different_tags() {
        let fx = fx();
        let s_a = fx.hmac("rc-hmac-a", HmacSpec::hs256());
        let s_b = fx.hmac("rc-hmac-b", HmacSpec::hs256());

        let mut mac_a = s_a.hmac_sha256();
        mac_a.update(b"same message");
        let tag_a = mac_a.finalize().into_bytes();

        let mut mac_b = s_b.hmac_sha256();
        mac_b.update(b"same message");
        let tag_b = mac_b.finalize().into_bytes();

        assert_ne!(tag_a, tag_b);
    }

    #[test]
    fn hmac_wrong_message_rejects() {
        let fx = fx();
        let secret = fx.hmac("rc-hmac-reject", HmacSpec::hs256());

        let mut mac = secret.hmac_sha256();
        mac.update(b"correct");
        let tag = mac.finalize().into_bytes();

        let mut mac2 = secret.hmac_sha256();
        mac2.update(b"wrong");
        assert!(mac2.verify(&tag).is_err());
    }
}
