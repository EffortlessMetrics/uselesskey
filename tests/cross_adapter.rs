//! Cross-Adapter Compatibility Tests
//!
//! Tests that key material produced by uselesskey can be used interchangeably
//! across different crypto backends (ring and RustCrypto). This validates that
//! the PKCS#8 DER encoding is standard-compliant.

mod testutil;

use testutil::fx;

// =========================================================================
// ECDSA Cross-Adapter (fast — no RSA)
// =========================================================================

#[cfg(feature = "cross-adapter")]
mod ecdsa_cross {
    use super::*;
    use p256::ecdsa::signature::Verifier as _;
    use ring::signature::{self, KeyPair};
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ring::RingEcdsaKeyPairExt;
    use uselesskey_rustcrypto::RustCryptoEcdsaExt;

    #[test]
    fn test_sign_ring_verify_rustcrypto_p256() {
        let fx = fx();
        let kp = fx.ecdsa("cross-ecdsa-p256", EcdsaSpec::es256());

        // Sign with ring
        let ring_kp = kp.ecdsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"cross-adapter test message";
        let ring_sig = ring_kp.sign(&rng, msg).expect("ring sign");

        // ring produces ASN.1 DER ECDSA signatures
        // p256 can verify DER signatures via Signature::from_der
        let verifying_key = kp.p256_verifying_key();
        let p256_sig =
            p256::ecdsa::DerSignature::from_bytes(ring_sig.as_ref()).expect("parse DER signature");
        verifying_key
            .verify(msg, &p256_sig)
            .expect("rustcrypto should verify ring signature");
    }

    #[test]
    fn test_sign_rustcrypto_verify_ring_p256() {
        use p256::ecdsa::signature::Signer as _;

        let fx = fx();
        let kp = fx.ecdsa("cross-ecdsa-p256-rev", EcdsaSpec::es256());

        // Sign with rustcrypto (produces fixed-size r||s by default)
        let signing_key = kp.p256_signing_key();
        let msg = b"cross-adapter reverse test";
        let rc_sig: p256::ecdsa::Signature = signing_key.sign(msg);

        // Convert to DER for ring verification
        let der_sig = rc_sig.to_der();

        // Verify with ring
        let ring_kp = kp.ecdsa_key_pair_ring();
        let public_key_bytes = ring_kp.public_key().as_ref();
        let ring_pub =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key_bytes);
        ring_pub
            .verify(msg, der_sig.as_bytes())
            .expect("ring should verify rustcrypto signature");
    }
}

// =========================================================================
// Ed25519 Cross-Adapter (fast)
// =========================================================================

#[cfg(feature = "cross-adapter")]
mod ed25519_cross {
    use super::*;
    use ed25519_dalek::{Signer as _, Verifier as _};
    use ring::signature::{self, KeyPair};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_ring::RingEd25519KeyPairExt;
    use uselesskey_rustcrypto::RustCryptoEd25519Ext;

    #[test]
    fn test_sign_ring_verify_rustcrypto_ed25519() {
        let fx = fx();
        let kp = fx.ed25519("cross-ed25519", Ed25519Spec::new());

        // Sign with ring
        let ring_kp = kp.ed25519_key_pair_ring();
        let msg = b"ed25519 cross-adapter test";
        let ring_sig = ring_kp.sign(msg);

        // Verify with ed25519-dalek
        let verifying_key = kp.ed25519_verifying_key();
        let dalek_sig =
            ed25519_dalek::Signature::from_bytes(ring_sig.as_ref().try_into().expect("64 bytes"));
        verifying_key
            .verify(msg, &dalek_sig)
            .expect("dalek should verify ring signature");
    }

    #[test]
    fn test_sign_rustcrypto_verify_ring_ed25519() {
        let fx = fx();
        let kp = fx.ed25519("cross-ed25519-rev", Ed25519Spec::new());

        // Sign with ed25519-dalek
        let signing_key = kp.ed25519_signing_key();
        let msg = b"ed25519 reverse cross-adapter test";
        let dalek_sig = signing_key.sign(msg);

        // Verify with ring
        let ring_kp = kp.ed25519_key_pair_ring();
        let public_key_bytes = ring_kp.public_key().as_ref();
        let ring_pub = signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
        ring_pub
            .verify(msg, dalek_sig.to_bytes().as_ref())
            .expect("ring should verify dalek signature");
    }
}

// =========================================================================
// RSA Cross-Adapter (1 RSA key, cached)
// =========================================================================

#[cfg(feature = "cross-adapter")]
mod rsa_cross {
    use super::*;
    use ring::signature;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::{Signer as _, Verifier as _};
    use sha2::Sha256;
    use uselesskey_ring::RingRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustcrypto::RustCryptoRsaExt;

    #[test]
    fn test_sign_ring_verify_rustcrypto_rsa() {
        let fx = fx();
        let kp = fx.rsa("cross-rsa", RsaSpec::rs256());

        // Sign with ring
        let ring_kp = kp.rsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"rsa cross-adapter test";
        let mut sig_buf = vec![0u8; ring_kp.public().modulus_len()];
        ring_kp
            .sign(&signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig_buf)
            .expect("ring sign");

        // Verify with rsa crate (ring uses standard PKCS#1 v1.5 with DigestInfo prefix)
        let public_key = kp.rsa_public_key();
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        let rc_sig = rsa::pkcs1v15::Signature::try_from(sig_buf.as_slice()).expect("parse sig");
        verifying_key
            .verify(msg, &rc_sig)
            .expect("rustcrypto should verify ring RSA signature");
    }

    #[test]
    fn test_sign_rustcrypto_verify_ring_rsa() {
        let fx = fx();
        let kp = fx.rsa("cross-rsa-rev", RsaSpec::rs256());

        // Sign with rsa crate (standard PKCS#1 v1.5 with DigestInfo prefix for ring compat)
        let private_key = kp.rsa_private_key();
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(private_key);
        let msg = b"rsa reverse cross-adapter test";
        let rc_sig = signing_key.sign(msg);

        // Verify with ring
        let ring_kp = kp.rsa_key_pair_ring();
        let public_key_bytes = ring_kp.public().as_ref();
        let ring_pub = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            public_key_bytes,
        );
        let sig_bytes =
            <rsa::pkcs1v15::Signature as rsa::signature::SignatureEncoding>::to_vec(&rc_sig);
        ring_pub
            .verify(msg, &sig_bytes)
            .expect("ring should verify rustcrypto RSA signature");
    }
}

// =========================================================================
// Identity Cross-Adapter (same key → same public key bytes)
// =========================================================================

#[cfg(feature = "cross-adapter")]
mod identity_cross {
    use super::*;
    use ring::signature::KeyPair;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_ring::{RingEcdsaKeyPairExt, RingEd25519KeyPairExt};
    use uselesskey_rustcrypto::{RustCryptoEcdsaExt, RustCryptoEd25519Ext};

    #[test]
    fn test_same_key_across_adapters_ecdsa() {
        let fx = fx();
        let kp = fx.ecdsa("identity-ecdsa", EcdsaSpec::es256());

        // Get public key from ring
        let ring_kp = kp.ecdsa_key_pair_ring();
        let ring_pub = ring_kp.public_key().as_ref();

        // Get public key from rustcrypto
        let rc_vk = kp.p256_verifying_key();
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let rc_pub = rc_vk.as_affine().to_encoded_point(false);
        let rc_pub_bytes = rc_pub.as_bytes();

        // ring and rustcrypto should produce the same uncompressed public key
        assert_eq!(
            ring_pub, rc_pub_bytes,
            "Same ECDSA key should yield identical public key bytes across adapters"
        );
    }

    #[test]
    fn test_same_key_across_adapters_ed25519() {
        let fx = fx();
        let kp = fx.ed25519("identity-ed25519", Ed25519Spec::new());

        // Get public key from ring
        let ring_kp = kp.ed25519_key_pair_ring();
        let ring_pub = ring_kp.public_key().as_ref();

        // Get public key from rustcrypto
        let rc_vk = kp.ed25519_verifying_key();
        let rc_pub = rc_vk.as_bytes();

        assert_eq!(
            ring_pub,
            rc_pub.as_slice(),
            "Same Ed25519 key should yield identical public key bytes across adapters"
        );
    }
}
