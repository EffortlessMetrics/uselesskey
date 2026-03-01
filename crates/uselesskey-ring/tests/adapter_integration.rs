//! Cross-adapter integration tests for uselesskey-ring.
//!
//! Tests cover:
//! - All key types through ring sign/verify round-trip
//! - ECDSA P-256 and P-384 ring compatibility
//! - Ed25519 ring compatibility
//! - Deterministic mode produces same ring keys
//! - Cross-key verification failures

use std::sync::OnceLock;

use uselesskey_core::{Factory, Seed};

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-ring-adapter-integration-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
    .clone()
}

// =========================================================================
// RSA through ring verification
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_ring {
    use super::*;
    use ring::{rand::SystemRandom, signature};
    use uselesskey_ring::RingRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rsa_sign_verify_roundtrip() {
        let fx = fx();
        let kp = fx.rsa("ring-rsa-rt", RsaSpec::rs256());
        let ring_kp = kp.rsa_key_pair_ring();

        let msg = b"ring rsa roundtrip";
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; ring_kp.public().modulus_len()];
        ring_kp
            .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("sign");

        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            ring_kp.public().as_ref(),
        );
        pk.verify(msg, &sig).expect("verify");
    }

    #[test]
    fn rsa_modulus_len_matches_spec() {
        let fx = fx();
        for (bits, label) in [(2048, "rsa-2k"), (4096, "rsa-4k")] {
            let kp = fx.rsa(label, RsaSpec::new(bits));
            let ring_kp = kp.rsa_key_pair_ring();
            assert_eq!(
                ring_kp.public().modulus_len(),
                bits / 8,
                "modulus_len should match {bits}-bit spec"
            );
        }
    }

    #[test]
    fn rsa_deterministic_same_ring_key() {
        let seed = Seed::from_env_value("ring-rsa-det").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.rsa("det-rsa", RsaSpec::rs256());
        let kp2 = fx2.rsa("det-rsa", RsaSpec::rs256());

        assert_eq!(kp1.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());

        // Both sign/verify correctly
        let ring1 = kp1.rsa_key_pair_ring();
        let ring2 = kp2.rsa_key_pair_ring();
        let rng = SystemRandom::new();
        let msg = b"deterministic";
        let mut sig1 = vec![0u8; ring1.public().modulus_len()];
        let mut sig2 = vec![0u8; ring2.public().modulus_len()];
        ring1
            .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig1)
            .unwrap();
        ring2
            .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig2)
            .unwrap();

        // Verify each signature with the other's public key (same key)
        let pk1 = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            ring1.public().as_ref(),
        );
        pk1.verify(msg, &sig2).expect("cross-verify should succeed");
    }

    #[test]
    fn rsa_wrong_key_rejects_signature() {
        let fx = fx();
        let kp_a = fx.rsa("ring-rsa-a", RsaSpec::rs256());
        let kp_b = fx.rsa("ring-rsa-b", RsaSpec::rs256());

        let ring_a = kp_a.rsa_key_pair_ring();
        let ring_b = kp_b.rsa_key_pair_ring();

        let msg = b"mismatch test";
        let rng = SystemRandom::new();
        let mut sig = vec![0u8; ring_a.public().modulus_len()];
        ring_a
            .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .unwrap();

        let pk_b = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            ring_b.public().as_ref(),
        );
        assert!(pk_b.verify(msg, &sig).is_err());
    }
}

// =========================================================================
// ECDSA P-256 and P-384 ring compatibility
// =========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_ring {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{self, KeyPair},
    };
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ring::RingEcdsaKeyPairExt;

    #[test]
    fn ecdsa_p256_sign_verify_roundtrip() {
        let fx = fx();
        let kp = fx.ecdsa("ring-p256-rt", EcdsaSpec::es256());
        let ring_kp = kp.ecdsa_key_pair_ring();

        let msg = b"p256 roundtrip";
        let rng = SystemRandom::new();
        let sig = ring_kp.sign(&rng, msg).expect("sign");

        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            ring_kp.public_key().as_ref(),
        );
        pk.verify(msg, sig.as_ref()).expect("verify");
    }

    #[test]
    fn ecdsa_p384_sign_verify_roundtrip() {
        let fx = fx();
        let kp = fx.ecdsa("ring-p384-rt", EcdsaSpec::es384());
        let ring_kp = kp.ecdsa_key_pair_ring();

        let msg = b"p384 roundtrip";
        let rng = SystemRandom::new();
        let sig = ring_kp.sign(&rng, msg).expect("sign");

        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_ASN1,
            ring_kp.public_key().as_ref(),
        );
        pk.verify(msg, sig.as_ref()).expect("verify");
    }

    #[test]
    fn ecdsa_deterministic_same_ring_key() {
        let seed = Seed::from_env_value("ring-ecdsa-det").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ecdsa("det-ec", EcdsaSpec::es256());
        let kp2 = fx2.ecdsa("det-ec", EcdsaSpec::es256());

        assert_eq!(kp1.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());

        let ring1 = kp1.ecdsa_key_pair_ring();
        let ring2 = kp2.ecdsa_key_pair_ring();
        assert_eq!(ring1.public_key().as_ref(), ring2.public_key().as_ref());
    }

    #[test]
    fn ecdsa_p256_wrong_key_rejects() {
        let fx = fx();
        let kp_a = fx.ecdsa("ring-ec-a", EcdsaSpec::es256());
        let kp_b = fx.ecdsa("ring-ec-b", EcdsaSpec::es256());

        let ring_a = kp_a.ecdsa_key_pair_ring();
        let ring_b = kp_b.ecdsa_key_pair_ring();

        let msg = b"cross-key test";
        let rng = SystemRandom::new();
        let sig = ring_a.sign(&rng, msg).unwrap();

        let pk_b = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            ring_b.public_key().as_ref(),
        );
        assert!(pk_b.verify(msg, sig.as_ref()).is_err());
    }

    #[test]
    fn ecdsa_p384_wrong_key_rejects() {
        let fx = fx();
        let kp_a = fx.ecdsa("ring-p384-a", EcdsaSpec::es384());
        let kp_b = fx.ecdsa("ring-p384-b", EcdsaSpec::es384());

        let ring_a = kp_a.ecdsa_key_pair_ring();
        let ring_b = kp_b.ecdsa_key_pair_ring();

        let msg = b"cross-key p384";
        let rng = SystemRandom::new();
        let sig = ring_a.sign(&rng, msg).unwrap();

        let pk_b = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_ASN1,
            ring_b.public_key().as_ref(),
        );
        assert!(pk_b.verify(msg, sig.as_ref()).is_err());
    }

    #[test]
    fn ecdsa_tampered_message_rejects() {
        let fx = fx();
        let kp = fx.ecdsa("ring-ec-tamper", EcdsaSpec::es256());
        let ring_kp = kp.ecdsa_key_pair_ring();

        let rng = SystemRandom::new();
        let sig = ring_kp.sign(&rng, b"original").unwrap();

        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            ring_kp.public_key().as_ref(),
        );
        assert!(pk.verify(b"tampered", sig.as_ref()).is_err());
    }
}

// =========================================================================
// Ed25519 ring compatibility
// =========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_ring {
    use super::*;
    use ring::signature::{self, KeyPair};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_ring::RingEd25519KeyPairExt;

    #[test]
    fn ed25519_sign_verify_roundtrip() {
        let fx = fx();
        let kp = fx.ed25519("ring-ed-rt", Ed25519Spec::new());
        let ring_kp = kp.ed25519_key_pair_ring();

        let msg = b"ed25519 roundtrip";
        let sig = ring_kp.sign(msg);

        let pk =
            signature::UnparsedPublicKey::new(&signature::ED25519, ring_kp.public_key().as_ref());
        pk.verify(msg, sig.as_ref()).expect("verify");
    }

    #[test]
    fn ed25519_deterministic_same_ring_key() {
        let seed = Seed::from_env_value("ring-ed-det").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ed25519("det-ed", Ed25519Spec::new());
        let kp2 = fx2.ed25519("det-ed", Ed25519Spec::new());

        assert_eq!(kp1.private_key_pkcs8_der(), kp2.private_key_pkcs8_der());

        let ring1 = kp1.ed25519_key_pair_ring();
        let ring2 = kp2.ed25519_key_pair_ring();
        assert_eq!(ring1.public_key().as_ref(), ring2.public_key().as_ref());
    }

    #[test]
    fn ed25519_deterministic_signatures_identical() {
        let seed = Seed::from_env_value("ring-ed-sig-det").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ed25519("ed-sig-det", Ed25519Spec::new());
        let kp2 = fx2.ed25519("ed-sig-det", Ed25519Spec::new());

        let ring1 = kp1.ed25519_key_pair_ring();
        let ring2 = kp2.ed25519_key_pair_ring();

        let msg = b"deterministic signature";
        let sig1 = ring1.sign(msg);
        let sig2 = ring2.sign(msg);
        assert_eq!(
            sig1.as_ref(),
            sig2.as_ref(),
            "Ed25519 signatures should be deterministic"
        );
    }

    #[test]
    fn ed25519_wrong_key_rejects() {
        let fx = fx();
        let kp_a = fx.ed25519("ring-ed-a", Ed25519Spec::new());
        let kp_b = fx.ed25519("ring-ed-b", Ed25519Spec::new());

        let ring_a = kp_a.ed25519_key_pair_ring();
        let ring_b = kp_b.ed25519_key_pair_ring();

        let msg = b"cross-key ed25519";
        let sig = ring_a.sign(msg);

        let pk_b =
            signature::UnparsedPublicKey::new(&signature::ED25519, ring_b.public_key().as_ref());
        assert!(pk_b.verify(msg, sig.as_ref()).is_err());
    }

    #[test]
    fn ed25519_tampered_message_rejects() {
        let fx = fx();
        let kp = fx.ed25519("ring-ed-tamper", Ed25519Spec::new());
        let ring_kp = kp.ed25519_key_pair_ring();

        let sig = ring_kp.sign(b"original");

        let pk =
            signature::UnparsedPublicKey::new(&signature::ED25519, ring_kp.public_key().as_ref());
        pk.verify(b"original", sig.as_ref()).expect("verify ok");
        assert!(pk.verify(b"tampered", sig.as_ref()).is_err());
    }
}

// =========================================================================
// Cross-algorithm: signing with one type, verifying with another fails
// =========================================================================

#[cfg(all(feature = "rsa", feature = "ecdsa", feature = "ed25519"))]
mod cross_algorithm {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{self, KeyPair},
    };
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_ring::{RingEcdsaKeyPairExt, RingEd25519KeyPairExt, RingRsaKeyPairExt};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rsa_sig_fails_ecdsa_verify() {
        let fx = fx();
        let rsa_kp = fx.rsa("cross-rsa", RsaSpec::rs256()).rsa_key_pair_ring();
        let ec_kp = fx
            .ecdsa("cross-ecdsa", EcdsaSpec::es256())
            .ecdsa_key_pair_ring();

        let rng = SystemRandom::new();
        let mut sig = vec![0u8; rsa_kp.public().modulus_len()];
        rsa_kp
            .sign(&signature::RSA_PKCS1_SHA256, &rng, b"msg", &mut sig)
            .unwrap();

        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            ec_kp.public_key().as_ref(),
        );
        assert!(pk.verify(b"msg", &sig).is_err());
    }

    #[test]
    fn ed25519_sig_fails_ecdsa_verify() {
        let fx = fx();
        let ed_kp = fx
            .ed25519("cross-ed", Ed25519Spec::new())
            .ed25519_key_pair_ring();
        let ec_kp = fx
            .ecdsa("cross-ecdsa2", EcdsaSpec::es256())
            .ecdsa_key_pair_ring();

        let sig = ed_kp.sign(b"msg");

        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            ec_kp.public_key().as_ref(),
        );
        assert!(pk.verify(b"msg", sig.as_ref()).is_err());
    }
}
