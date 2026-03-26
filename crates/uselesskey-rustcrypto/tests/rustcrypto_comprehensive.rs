//! Comprehensive integration tests for uselesskey-rustcrypto adapter.
//!
//! Covers: sign-verify round trips, deterministic behavior, debug safety,
//! cross-key-type operations, and edge cases.

mod testutil;

use uselesskey_core::{Factory, Seed};

fn deterministic_factory(seed_str: &str) -> Factory {
    let seed = Seed::from_env_value(seed_str).expect("test seed");
    Factory::deterministic(seed)
}

// =========================================================================
// RSA comprehensive tests
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_comprehensive {
    use super::*;
    use rsa::pkcs1v15::{SigningKey, VerifyingKey};
    use rsa::sha2::Sha256;
    use rsa::signature::{Signer, Verifier};
    use rsa::traits::PublicKeyParts;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustcrypto::RustCryptoRsaExt;

    #[test]
    fn sign_verify_round_trip_multiple_messages() {
        let fx = Factory::random();
        let kp = fx.rsa("roundtrip", RsaSpec::rs256());

        let private = kp.rsa_private_key();
        let public = kp.rsa_public_key();
        let signing = SigningKey::<Sha256>::new_unprefixed(private);
        let verifying = VerifyingKey::<Sha256>::new_unprefixed(public);

        for msg in [b"hello" as &[u8], b"", b"a".repeat(4096).as_slice()] {
            let sig = signing.sign(msg);
            verifying.verify(msg, &sig).expect("round-trip verify");
        }
    }

    #[test]
    fn wrong_message_fails_verification() {
        let fx = Factory::random();
        let kp = fx.rsa("wrongmsg", RsaSpec::rs256());

        let signing = SigningKey::<Sha256>::new_unprefixed(kp.rsa_private_key());
        let verifying = VerifyingKey::<Sha256>::new_unprefixed(kp.rsa_public_key());

        let sig = signing.sign(b"correct");
        assert!(verifying.verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn deterministic_keys_produce_same_rustcrypto_key() {
        let fx1 = deterministic_factory("rc-det-rsa-v1");
        let fx2 = deterministic_factory("rc-det-rsa-v1");

        let pk1 = fx1.rsa("det-rsa", RsaSpec::rs256()).rsa_public_key();
        let pk2 = fx2.rsa("det-rsa", RsaSpec::rs256()).rsa_public_key();

        assert_eq!(pk1.n(), pk2.n(), "modulus must match");
        assert_eq!(pk1.e(), pk2.e(), "exponent must match");
    }

    #[test]
    fn different_labels_produce_different_keys() {
        let fx = deterministic_factory("rc-label-rsa-v1");

        let pk1 = fx.rsa("label-a", RsaSpec::rs256()).rsa_public_key();
        let pk2 = fx.rsa("label-b", RsaSpec::rs256()).rsa_public_key();

        assert_ne!(
            pk1.n(),
            pk2.n(),
            "different labels must produce different keys"
        );
    }

    #[test]
    fn rsa_4096_key_conversion() {
        let fx = Factory::random();
        let kp = fx.rsa("rsa4096", RsaSpec::new(4096));

        let public = kp.rsa_public_key();
        assert!(
            public.n().bits() >= 4096,
            "RSA-4096 key must have >= 4096-bit modulus"
        );

        let signing = SigningKey::<Sha256>::new_unprefixed(kp.rsa_private_key());
        let verifying = VerifyingKey::<Sha256>::new_unprefixed(public);
        let sig = signing.sign(b"4096 test");
        verifying.verify(b"4096 test", &sig).unwrap();
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let fx = Factory::random();
        let kp = fx.rsa("debug-rsa", RsaSpec::rs256());
        let debug_str = format!("{:?}", kp);
        assert!(
            !debug_str.contains("BEGIN"),
            "Debug output must not contain PEM markers"
        );
        let private_hex = hex::encode(kp.private_key_pkcs8_der());
        assert!(
            !debug_str.contains(&private_hex[..32]),
            "Debug output must not contain key bytes"
        );
    }
}

// =========================================================================
// ECDSA comprehensive tests
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_comprehensive {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_rustcrypto::RustCryptoEcdsaExt;

    #[test]
    fn p256_sign_verify_round_trip() {
        use p256::ecdsa::signature::{Signer, Verifier};

        let fx = Factory::random();
        let kp = fx.ecdsa("roundtrip-p256", EcdsaSpec::es256());

        let signing = kp.p256_signing_key();
        let verifying = kp.p256_verifying_key();

        for msg in [b"hello" as &[u8], b"", b"x".repeat(8192).as_slice()] {
            let sig: p256::ecdsa::Signature = signing.sign(msg);
            verifying.verify(msg, &sig).expect("p256 round-trip");
        }
    }

    #[test]
    fn p384_sign_verify_round_trip() {
        use p384::ecdsa::signature::{Signer, Verifier};

        let fx = Factory::random();
        let kp = fx.ecdsa("roundtrip-p384", EcdsaSpec::es384());

        let signing = kp.p384_signing_key();
        let verifying = kp.p384_verifying_key();

        let sig: p384::ecdsa::Signature = signing.sign(b"test");
        verifying.verify(b"test", &sig).unwrap();
    }

    #[test]
    fn p256_wrong_message_fails() {
        use p256::ecdsa::signature::{Signer, Verifier};

        let fx = Factory::random();
        let kp = fx.ecdsa("wrong-p256", EcdsaSpec::es256());
        let sig: p256::ecdsa::Signature = kp.p256_signing_key().sign(b"correct");
        assert!(kp.p256_verifying_key().verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn deterministic_p256_keys_match() {
        let fx1 = deterministic_factory("rc-det-ecdsa-v1");
        let fx2 = deterministic_factory("rc-det-ecdsa-v1");

        let vk1 = fx1.ecdsa("det-ec", EcdsaSpec::es256()).p256_verifying_key();
        let vk2 = fx2.ecdsa("det-ec", EcdsaSpec::es256()).p256_verifying_key();

        assert_eq!(vk1, vk2, "deterministic P-256 keys must match");
    }

    #[test]
    fn different_labels_produce_different_ecdsa_keys() {
        let fx = deterministic_factory("rc-label-ec-v1");

        let vk1 = fx.ecdsa("label-a", EcdsaSpec::es256()).p256_verifying_key();
        let vk2 = fx.ecdsa("label-b", EcdsaSpec::es256()).p256_verifying_key();

        assert_ne!(vk1, vk2, "different labels must produce different keys");
    }

    #[test]
    fn different_curves_produce_different_der() {
        let fx = Factory::random();
        let p256 = fx.ecdsa("curve-test", EcdsaSpec::es256());
        let p384 = fx.ecdsa("curve-test", EcdsaSpec::es384());

        assert_ne!(
            p256.private_key_pkcs8_der(),
            p384.private_key_pkcs8_der(),
            "different curves must have different DER"
        );
    }

    #[test]
    #[should_panic(expected = "expected P-384")]
    fn p384_on_p256_panics() {
        let fx = Factory::random();
        let kp = fx.ecdsa("panic-test", EcdsaSpec::es256());
        let _ = kp.p384_signing_key();
    }

    #[test]
    #[should_panic(expected = "expected P-256")]
    fn p256_on_p384_panics() {
        let fx = Factory::random();
        let kp = fx.ecdsa("panic-test", EcdsaSpec::es384());
        let _ = kp.p256_signing_key();
    }

    #[test]
    fn debug_does_not_leak_ecdsa_material() {
        let fx = Factory::random();
        let kp = fx.ecdsa("debug-ec", EcdsaSpec::es256());
        let debug_str = format!("{:?}", kp);
        assert!(!debug_str.contains("BEGIN"));
    }
}

// =========================================================================
// Ed25519 comprehensive tests
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_comprehensive {
    use super::*;
    use ed25519_dalek::{Signer, Verifier};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rustcrypto::RustCryptoEd25519Ext;

    #[test]
    fn sign_verify_round_trip() {
        let fx = Factory::random();
        let kp = fx.ed25519("roundtrip-ed", Ed25519Spec::new());

        let signing = kp.ed25519_signing_key();
        let verifying = kp.ed25519_verifying_key();

        for msg in [b"hello" as &[u8], b"", b"y".repeat(10000).as_slice()] {
            let sig = signing.sign(msg);
            verifying.verify(msg, &sig).expect("ed25519 round-trip");
        }
    }

    #[test]
    fn wrong_message_fails() {
        let fx = Factory::random();
        let kp = fx.ed25519("wrong-ed", Ed25519Spec::new());
        let sig = kp.ed25519_signing_key().sign(b"correct");
        assert!(kp.ed25519_verifying_key().verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn deterministic_ed25519_keys_match() {
        let fx1 = deterministic_factory("rc-det-ed-v1");
        let fx2 = deterministic_factory("rc-det-ed-v1");

        let vk1 = fx1
            .ed25519("det-ed", Ed25519Spec::new())
            .ed25519_verifying_key();
        let vk2 = fx2
            .ed25519("det-ed", Ed25519Spec::new())
            .ed25519_verifying_key();

        assert_eq!(vk1, vk2, "deterministic Ed25519 keys must match");
    }

    #[test]
    fn different_labels_produce_different_ed25519_keys() {
        let fx = deterministic_factory("rc-label-ed-v1");

        let vk1 = fx
            .ed25519("label-a", Ed25519Spec::new())
            .ed25519_verifying_key();
        let vk2 = fx
            .ed25519("label-b", Ed25519Spec::new())
            .ed25519_verifying_key();

        assert_ne!(vk1, vk2, "different labels must produce different keys");
    }

    #[test]
    fn verifying_key_is_32_bytes() {
        let fx = Factory::random();
        let kp = fx.ed25519("size-ed", Ed25519Spec::new());
        assert_eq!(kp.ed25519_verifying_key().as_bytes().len(), 32);
    }

    #[test]
    fn debug_does_not_leak_ed25519_material() {
        let fx = Factory::random();
        let kp = fx.ed25519("debug-ed", Ed25519Spec::new());
        let debug_str = format!("{:?}", kp);
        assert!(!debug_str.contains("BEGIN"));
    }
}

// =========================================================================
// HMAC comprehensive tests
// =========================================================================

#[cfg(feature = "hmac")]
mod hmac_comprehensive {
    use super::*;
    use hmac::Mac;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    use uselesskey_rustcrypto::RustCryptoHmacExt;

    #[test]
    fn sha256_compute_and_verify() {
        let fx = Factory::random();
        let secret = fx.hmac("cv-256", HmacSpec::hs256());

        let mut mac = secret.hmac_sha256();
        mac.update(b"test data");
        let tag = mac.finalize().into_bytes();

        let mut mac2 = secret.hmac_sha256();
        mac2.update(b"test data");
        mac2.verify(&tag).expect("HMAC-SHA256 verify");
    }

    #[test]
    fn sha384_compute_and_verify() {
        let fx = Factory::random();
        let secret = fx.hmac("cv-384", HmacSpec::hs384());

        let mut mac = secret.hmac_sha384();
        mac.update(b"test data");
        let tag = mac.finalize().into_bytes();

        let mut mac2 = secret.hmac_sha384();
        mac2.update(b"test data");
        mac2.verify(&tag).expect("HMAC-SHA384 verify");
    }

    #[test]
    fn sha512_compute_and_verify() {
        let fx = Factory::random();
        let secret = fx.hmac("cv-512", HmacSpec::hs512());

        let mut mac = secret.hmac_sha512();
        mac.update(b"test data");
        let tag = mac.finalize().into_bytes();

        let mut mac2 = secret.hmac_sha512();
        mac2.update(b"test data");
        mac2.verify(&tag).expect("HMAC-SHA512 verify");
    }

    #[test]
    fn wrong_data_fails_hmac_verify() {
        let fx = Factory::random();
        let secret = fx.hmac("wrong-hmac", HmacSpec::hs256());

        let mut mac = secret.hmac_sha256();
        mac.update(b"correct");
        let tag = mac.finalize().into_bytes();

        let mut mac2 = secret.hmac_sha256();
        mac2.update(b"wrong");
        assert!(mac2.verify(&tag).is_err());
    }

    #[test]
    fn tag_lengths_match_spec() {
        let fx = Factory::random();

        let s256 = fx.hmac("len-256", HmacSpec::hs256());
        let s384 = fx.hmac("len-384", HmacSpec::hs384());
        let s512 = fx.hmac("len-512", HmacSpec::hs512());

        let mut m = s256.hmac_sha256();
        m.update(b"x");
        assert_eq!(m.finalize().into_bytes().len(), 32);

        let mut m = s384.hmac_sha384();
        m.update(b"x");
        assert_eq!(m.finalize().into_bytes().len(), 48);

        let mut m = s512.hmac_sha512();
        m.update(b"x");
        assert_eq!(m.finalize().into_bytes().len(), 64);
    }

    #[test]
    fn deterministic_hmac_produces_same_tag() {
        let fx1 = deterministic_factory("rc-det-hmac-v1");
        let fx2 = deterministic_factory("rc-det-hmac-v1");

        let s1 = fx1.hmac("det-hmac", HmacSpec::hs256());
        let s2 = fx2.hmac("det-hmac", HmacSpec::hs256());

        let mut m1 = s1.hmac_sha256();
        m1.update(b"test");
        let tag1 = m1.finalize().into_bytes();

        let mut m2 = s2.hmac_sha256();
        m2.update(b"test");
        let tag2 = m2.finalize().into_bytes();

        assert_eq!(tag1, tag2, "deterministic HMAC must produce same tag");
    }

    #[test]
    fn different_labels_produce_different_hmac_secrets() {
        let fx = deterministic_factory("rc-label-hmac-v1");

        let s1 = fx.hmac("label-a", HmacSpec::hs256());
        let s2 = fx.hmac("label-b", HmacSpec::hs256());

        assert_ne!(s1.secret_bytes(), s2.secret_bytes());
    }

    #[test]
    fn empty_message_hmac() {
        let fx = Factory::random();
        let secret = fx.hmac("empty-hmac", HmacSpec::hs256());

        let mut mac = secret.hmac_sha256();
        mac.update(b"");
        let tag = mac.finalize().into_bytes();

        // Must produce a valid tag even for empty input
        assert_eq!(tag.len(), 32);
    }
}

// =========================================================================
// Cross-adapter tests
// =========================================================================

#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "hmac"
))]
mod cross_type_tests {
    use super::*;
    use rsa::traits::PublicKeyParts;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustcrypto::{
        RustCryptoEcdsaExt, RustCryptoEd25519Ext, RustCryptoHmacExt, RustCryptoRsaExt,
    };

    #[test]
    fn all_key_types_from_same_factory() {
        let fx = Factory::random();

        // Generate all key types from the same factory
        let rsa = fx.rsa("multi-rsa", RsaSpec::rs256());
        let ecdsa = fx.ecdsa("multi-ecdsa", EcdsaSpec::es256());
        let ed25519 = fx.ed25519("multi-ed25519", Ed25519Spec::new());
        let hmac = fx.hmac("multi-hmac", HmacSpec::hs256());

        // All conversions should succeed
        let _ = rsa.rsa_private_key();
        let _ = ecdsa.p256_signing_key();
        let _ = ed25519.ed25519_signing_key();
        let _ = hmac.hmac_sha256();
    }

    #[test]
    fn deterministic_all_types_stable() {
        let fx1 = deterministic_factory("rc-multi-v1");
        let fx2 = deterministic_factory("rc-multi-v1");

        let rsa1 = fx1.rsa("stable", RsaSpec::rs256()).rsa_public_key();
        let rsa2 = fx2.rsa("stable", RsaSpec::rs256()).rsa_public_key();
        assert_eq!(rsa1.n(), rsa2.n());

        let ec1 = fx1.ecdsa("stable", EcdsaSpec::es256()).p256_verifying_key();
        let ec2 = fx2.ecdsa("stable", EcdsaSpec::es256()).p256_verifying_key();
        assert_eq!(ec1, ec2);

        let ed1 = fx1
            .ed25519("stable", Ed25519Spec::new())
            .ed25519_verifying_key();
        let ed2 = fx2
            .ed25519("stable", Ed25519Spec::new())
            .ed25519_verifying_key();
        assert_eq!(ed1, ed2);

        let h1 = fx1
            .hmac("stable", HmacSpec::hs256())
            .secret_bytes()
            .to_vec();
        let h2 = fx2
            .hmac("stable", HmacSpec::hs256())
            .secret_bytes()
            .to_vec();
        assert_eq!(h1, h2);
    }
}
