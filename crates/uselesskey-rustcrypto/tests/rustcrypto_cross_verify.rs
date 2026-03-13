//! Cross-factory and multi-message integration tests for uselesskey-rustcrypto.
//!
//! Tests cover:
//! - RSA PSS signatures via RustCrypto
//! - Cross-factory deterministic verification for all key types
//! - Multiple sequential signatures with the same key
//! - Large message handling
//! - HMAC cross-factory tag verification

mod testutil;

use testutil::fx;
use uselesskey_core::{Factory, Seed};

// =========================================================================
// RSA PSS signatures
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_pss {
    use super::*;
    use rsa::pss::{SigningKey as PssSigningKey, VerifyingKey as PssVerifyingKey};
    use rsa::signature::{RandomizedSigner, Verifier};
    use sha2::Sha256;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustcrypto::RustCryptoRsaExt;

    fn rng() -> rsa::rand_core::OsRng {
        rsa::rand_core::OsRng
    }

    #[test]
    fn rsa_pss_sign_verify_roundtrip() {
        let kp = fx().rsa("rc-pss-rt", RsaSpec::rs256());
        let signing = PssSigningKey::<Sha256>::new(kp.rsa_private_key());
        let sig = signing.sign_with_rng(&mut rng(), b"pss message");

        let verifying = PssVerifyingKey::<Sha256>::new(kp.rsa_public_key());
        verifying.verify(b"pss message", &sig).expect("PSS verify");
    }

    #[test]
    fn rsa_pss_wrong_message_rejects() {
        let kp = fx().rsa("rc-pss-reject", RsaSpec::rs256());
        let signing = PssSigningKey::<Sha256>::new(kp.rsa_private_key());
        let sig = signing.sign_with_rng(&mut rng(), b"correct");

        let verifying = PssVerifyingKey::<Sha256>::new(kp.rsa_public_key());
        assert!(verifying.verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn rsa_pss_cross_key_rejects() {
        let fx = fx();
        let kp_a = fx.rsa("rc-pss-a", RsaSpec::rs256());
        let kp_b = fx.rsa("rc-pss-b", RsaSpec::rs256());

        let sig = PssSigningKey::<Sha256>::new(kp_a.rsa_private_key())
            .sign_with_rng(&mut rng(), b"cross-key");
        let verifying = PssVerifyingKey::<Sha256>::new(kp_b.rsa_public_key());
        assert!(verifying.verify(b"cross-key", &sig).is_err());
    }
}

// =========================================================================
// Cross-factory deterministic verification
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_cross_factory {
    use super::*;
    use rsa::pkcs1v15::{SigningKey, VerifyingKey};
    use rsa::signature::{Signer, Verifier};
    use sha2::Sha256;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustcrypto::RustCryptoRsaExt;

    #[test]
    fn sign_factory1_verify_factory2() {
        let seed = Seed::from_env_value("rc-cross-fac-rsa").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.rsa("cross-rsa", RsaSpec::rs256());
        let kp2 = fx2.rsa("cross-rsa", RsaSpec::rs256());

        let sig =
            SigningKey::<Sha256>::new_unprefixed(kp1.rsa_private_key()).sign(b"cross-factory");
        VerifyingKey::<Sha256>::new_unprefixed(kp2.rsa_public_key())
            .verify(b"cross-factory", &sig)
            .expect("cross-factory verify");
    }
}

#[cfg(feature = "ecdsa")]
mod ecdsa_cross_factory {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_rustcrypto::RustCryptoEcdsaExt;

    #[test]
    fn p256_sign_factory1_verify_factory2() {
        use p256::ecdsa::signature::{Signer, Verifier};

        let seed = Seed::from_env_value("rc-cross-fac-ec").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ecdsa("cross-ec", EcdsaSpec::es256());
        let kp2 = fx2.ecdsa("cross-ec", EcdsaSpec::es256());

        let sig: p256::ecdsa::Signature = kp1.p256_signing_key().sign(b"cross-factory-ec");
        kp2.p256_verifying_key()
            .verify(b"cross-factory-ec", &sig)
            .expect("cross-factory p256 verify");
    }

    #[test]
    fn p384_sign_factory1_verify_factory2() {
        use p384::ecdsa::signature::{Signer, Verifier};

        let seed = Seed::from_env_value("rc-cross-fac-p384").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ecdsa("cross-p384", EcdsaSpec::es384());
        let kp2 = fx2.ecdsa("cross-p384", EcdsaSpec::es384());

        let sig: p384::ecdsa::Signature = kp1.p384_signing_key().sign(b"cross-factory-p384");
        kp2.p384_verifying_key()
            .verify(b"cross-factory-p384", &sig)
            .expect("cross-factory p384 verify");
    }
}

#[cfg(feature = "ed25519")]
mod ed25519_cross_factory {
    use super::*;
    use ed25519_dalek::{Signer, Verifier};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rustcrypto::RustCryptoEd25519Ext;

    #[test]
    fn sign_factory1_verify_factory2() {
        let seed = Seed::from_env_value("rc-cross-fac-ed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let kp1 = fx1.ed25519("cross-ed", Ed25519Spec::new());
        let kp2 = fx2.ed25519("cross-ed", Ed25519Spec::new());

        let sig = kp1.ed25519_signing_key().sign(b"cross-factory-ed");
        kp2.ed25519_verifying_key()
            .verify(b"cross-factory-ed", &sig)
            .expect("cross-factory ed25519 verify");
    }

    /// Ed25519 signatures from the same key are deterministic.
    #[test]
    fn ed25519_deterministic_signatures() {
        let kp = fx().ed25519("rc-ed-det-sig", Ed25519Spec::new());
        let sk = kp.ed25519_signing_key();
        let sig1 = sk.sign(b"deterministic");
        let sig2 = sk.sign(b"deterministic");
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }
}

// =========================================================================
// HMAC cross-factory verification
// =========================================================================

#[cfg(feature = "hmac")]
mod hmac_cross_factory {
    use super::*;
    use hmac::Mac;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    use uselesskey_rustcrypto::RustCryptoHmacExt;

    #[test]
    fn hmac_sha256_cross_factory_tag_matches() {
        let seed = Seed::from_env_value("rc-cross-fac-hmac").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let s1 = fx1.hmac("cross-hmac", HmacSpec::hs256());
        let s2 = fx2.hmac("cross-hmac", HmacSpec::hs256());

        let mut m1 = s1.hmac_sha256();
        m1.update(b"cross-factory-hmac");
        let tag = m1.finalize().into_bytes();

        let mut m2 = s2.hmac_sha256();
        m2.update(b"cross-factory-hmac");
        m2.verify(&tag).expect("cross-factory HMAC verify");
    }
}

// =========================================================================
// Multiple sequential signatures
// =========================================================================

#[cfg(feature = "rsa")]
mod rsa_multi_sig {
    use super::*;
    use rsa::pkcs1v15::{SigningKey, VerifyingKey};
    use rsa::signature::{Signer, Verifier};
    use sha2::Sha256;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustcrypto::RustCryptoRsaExt;

    #[test]
    fn multiple_signatures_all_verify() {
        let kp = fx().rsa("rc-multi-sig", RsaSpec::rs256());
        let signing = SigningKey::<Sha256>::new_unprefixed(kp.rsa_private_key());
        let verifying = VerifyingKey::<Sha256>::new_unprefixed(kp.rsa_public_key());

        for i in 0..5 {
            let msg = format!("message-{i}");
            let sig = signing.sign(msg.as_bytes());
            verifying
                .verify(msg.as_bytes(), &sig)
                .unwrap_or_else(|e| panic!("verify message-{i} failed: {e:?}"));
        }
    }

    #[test]
    fn large_message_sign_verify() {
        let kp = fx().rsa("rc-rsa-large", RsaSpec::rs256());
        let signing = SigningKey::<Sha256>::new_unprefixed(kp.rsa_private_key());
        let verifying = VerifyingKey::<Sha256>::new_unprefixed(kp.rsa_public_key());

        let msg = vec![0xABu8; 64 * 1024];
        let sig = signing.sign(&msg);
        verifying.verify(&msg, &sig).expect("verify large");
    }
}
