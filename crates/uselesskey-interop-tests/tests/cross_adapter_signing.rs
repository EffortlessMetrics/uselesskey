//! Cross-adapter signing interoperability tests.
//!
//! These tests sign with one crypto backend adapter and verify with another,
//! confirming that uselesskey-generated keys produce compatible results across
//! different libraries.

#![cfg(feature = "cross-signing")]

use std::sync::OnceLock;

use uselesskey_core::{Factory, Seed};

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> &'static Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-cross-signing-seed-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
}

// =========================================================================
// ASN.1 helpers
// =========================================================================

fn extract_public_key_from_spki(spki_der: &[u8]) -> &[u8] {
    let (_, rest) = skip_tag_and_length(spki_der);
    let (inner_len, rest) = skip_tag_and_length(rest);
    let rest = &rest[inner_len..];
    assert_eq!(rest[0], 0x03, "expected BIT STRING tag");
    let (bit_string_len, rest) = skip_tag_and_length(rest);
    assert_eq!(rest[0], 0x00, "expected 0 unused bits");
    &rest[1..bit_string_len]
}

fn skip_tag_and_length(data: &[u8]) -> (usize, &[u8]) {
    let data = &data[1..];
    if data[0] & 0x80 == 0 {
        let len = data[0] as usize;
        (len, &data[1..])
    } else {
        let num_bytes = (data[0] & 0x7f) as usize;
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }
        (len, &data[1 + num_bytes..])
    }
}

// =========================================================================
// RSA: ring ↔ RustCrypto
// =========================================================================

mod rsa_cross {
    use super::*;
    use ring::signature as ring_sig;
    use rsa::pkcs1v15;
    use rsa::sha2::Sha256;
    use rsa::signature::{SignatureEncoding, Signer, Verifier};
    use uselesskey_ring::RingRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustcrypto::RustCryptoRsaExt;

    #[test]
    fn ring_sign_rustcrypto_verify() {
        let fx = fx();
        let keypair = fx.rsa("cross-rsa-r2rc", RsaSpec::rs256());

        // Sign with ring
        let ring_kp = keypair.rsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"ring-to-rustcrypto RSA test";
        let mut sig = vec![0u8; ring_kp.public().modulus_len()];
        ring_kp
            .sign(&ring_sig::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("ring sign");

        // Verify with RustCrypto
        let public_key = keypair.rsa_public_key();
        let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
        let signature =
            pkcs1v15::Signature::try_from(sig.as_slice()).expect("valid signature bytes");
        verifying_key
            .verify(msg, &signature)
            .expect("rustcrypto should verify ring-signed RSA signature");
    }

    #[test]
    fn rustcrypto_sign_ring_verify() {
        let fx = fx();
        let keypair = fx.rsa("cross-rsa-rc2r", RsaSpec::rs256());

        // Sign with RustCrypto
        let private_key = keypair.rsa_private_key();
        let signing_key = pkcs1v15::SigningKey::<Sha256>::new(private_key);
        let msg = b"rustcrypto-to-ring RSA test";
        let sig = signing_key.sign(msg);

        // Verify with ring
        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key =
            ring_sig::UnparsedPublicKey::new(&ring_sig::RSA_PKCS1_2048_8192_SHA256, raw_pubkey);
        public_key
            .verify(msg, &sig.to_bytes())
            .expect("ring should verify rustcrypto-signed RSA signature");
    }
}

// =========================================================================
// ECDSA P-256: ring ↔ RustCrypto
// =========================================================================

mod ecdsa_p256_cross {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use ring::signature as ring_sig;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ring::RingEcdsaKeyPairExt;
    use uselesskey_rustcrypto::RustCryptoEcdsaExt;

    #[test]
    fn ring_sign_rustcrypto_verify() {
        let fx = fx();
        let keypair = fx.ecdsa("cross-p256-r2rc", EcdsaSpec::es256());

        // Sign with ring
        let ring_kp = keypair.ecdsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"ring-to-rustcrypto ECDSA P-256 test";
        let sig = ring_kp.sign(&rng, msg).expect("ring sign");

        // Verify with RustCrypto (p256)
        let verifying_key = keypair.p256_verifying_key();
        let der_sig =
            p256::ecdsa::DerSignature::try_from(sig.as_ref()).expect("valid ASN.1 signature");
        verifying_key
            .verify(msg, &der_sig)
            .expect("rustcrypto should verify ring-signed ECDSA P-256 signature");
    }

    #[test]
    fn rustcrypto_sign_ring_verify() {
        let fx = fx();
        let keypair = fx.ecdsa("cross-p256-rc2r", EcdsaSpec::es256());

        // Sign with RustCrypto (p256)
        use p256::ecdsa::signature::Signer;
        let signing_key = keypair.p256_signing_key();
        let msg = b"rustcrypto-to-ring ECDSA P-256 test";
        let sig: p256::ecdsa::DerSignature = signing_key.sign(msg);

        // Verify with ring
        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key =
            ring_sig::UnparsedPublicKey::new(&ring_sig::ECDSA_P256_SHA256_ASN1, raw_pubkey);
        public_key
            .verify(msg, sig.as_bytes())
            .expect("ring should verify rustcrypto-signed ECDSA P-256 signature");
    }
}

// =========================================================================
// Ed25519: ring ↔ RustCrypto
// =========================================================================

mod ed25519_cross {
    use super::*;
    use ed25519_dalek::Verifier;
    use ring::signature as ring_sig;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_ring::RingEd25519KeyPairExt;
    use uselesskey_rustcrypto::RustCryptoEd25519Ext;

    #[test]
    fn ring_sign_rustcrypto_verify() {
        let fx = fx();
        let keypair = fx.ed25519("cross-ed25519-r2rc", Ed25519Spec::new());

        // Sign with ring
        let ring_kp = keypair.ed25519_key_pair_ring();
        let msg = b"ring-to-rustcrypto Ed25519 test";
        let sig = ring_kp.sign(msg);

        // Verify with RustCrypto (ed25519-dalek)
        let verifying_key = keypair.ed25519_verifying_key();
        let dalek_sig =
            ed25519_dalek::Signature::from_slice(sig.as_ref()).expect("valid 64-byte signature");
        verifying_key
            .verify(msg, &dalek_sig)
            .expect("rustcrypto should verify ring-signed Ed25519 signature");
    }

    #[test]
    fn rustcrypto_sign_ring_verify() {
        let fx = fx();
        let keypair = fx.ed25519("cross-ed25519-rc2r", Ed25519Spec::new());

        // Sign with RustCrypto (ed25519-dalek)
        use ed25519_dalek::Signer;
        let signing_key = keypair.ed25519_signing_key();
        let msg = b"rustcrypto-to-ring Ed25519 test";
        let sig = signing_key.sign(msg);

        // Verify with ring
        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key = ring_sig::UnparsedPublicKey::new(&ring_sig::ED25519, raw_pubkey);
        public_key
            .verify(msg, sig.to_bytes().as_ref())
            .expect("ring should verify rustcrypto-signed Ed25519 signature");
    }
}

// =========================================================================
// aws-lc-rs → ring
// =========================================================================

#[cfg(all(feature = "aws-lc-rs-interop", any(not(windows), has_nasm)))]
mod aws_lc_rs_to_ring {
    use super::*;
    use ring::signature as ring_sig;
    use uselesskey_aws_lc_rs::{
        AwsLcRsEcdsaKeyPairExt, AwsLcRsEd25519KeyPairExt, AwsLcRsRsaKeyPairExt,
    };
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rsa_aws_sign_ring_verify() {
        let fx = fx();
        let keypair = fx.rsa("cross-rsa-aws2r", RsaSpec::rs256());

        // Sign with aws-lc-rs
        let aws_kp = keypair.rsa_key_pair_aws_lc_rs();
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let msg = b"aws-lc-rs-to-ring RSA test";
        let mut sig = vec![0u8; aws_kp.public_modulus_len()];
        aws_kp
            .sign(&aws_lc_rs::signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("aws sign");

        // Verify with ring
        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key =
            ring_sig::UnparsedPublicKey::new(&ring_sig::RSA_PKCS1_2048_8192_SHA256, raw_pubkey);
        public_key
            .verify(msg, &sig)
            .expect("ring should verify aws-lc-rs-signed RSA signature");
    }

    #[test]
    fn ecdsa_p256_aws_sign_ring_verify() {
        let fx = fx();
        let keypair = fx.ecdsa("cross-p256-aws2r", EcdsaSpec::es256());

        // Sign with aws-lc-rs
        let aws_kp = keypair.ecdsa_key_pair_aws_lc_rs();
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let msg = b"aws-lc-rs-to-ring ECDSA P-256 test";
        let sig = aws_kp.sign(&rng, msg).expect("aws sign");

        // Verify with ring
        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key =
            ring_sig::UnparsedPublicKey::new(&ring_sig::ECDSA_P256_SHA256_ASN1, raw_pubkey);
        public_key
            .verify(msg, sig.as_ref())
            .expect("ring should verify aws-lc-rs-signed ECDSA P-256 signature");
    }

    #[test]
    fn ed25519_aws_sign_ring_verify() {
        let fx = fx();
        let keypair = fx.ed25519("cross-ed25519-aws2r", Ed25519Spec::new());

        // Sign with aws-lc-rs
        let aws_kp = keypair.ed25519_key_pair_aws_lc_rs();
        let msg = b"aws-lc-rs-to-ring Ed25519 test";
        let sig = aws_kp.sign(msg);

        // Verify with ring
        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key = ring_sig::UnparsedPublicKey::new(&ring_sig::ED25519, raw_pubkey);
        public_key
            .verify(msg, sig.as_ref())
            .expect("ring should verify aws-lc-rs-signed Ed25519 signature");
    }
}

// =========================================================================
// HMAC: ring ↔ RustCrypto
// =========================================================================

mod hmac_cross {
    use super::*;
    use hmac::Mac;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    use uselesskey_rustcrypto::RustCryptoHmacExt;

    #[test]
    fn ring_tag_rustcrypto_verify_sha256() {
        let fx = fx();
        let secret = fx.hmac("cross-hmac-256-r2rc", HmacSpec::hs256());

        // Tag with ring
        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.secret_bytes());
        let msg = b"ring-to-rustcrypto HMAC-SHA256 test";
        let ring_tag = ring::hmac::sign(&ring_key, msg);

        // Verify with RustCrypto
        let mut mac = secret.hmac_sha256();
        mac.update(msg);
        mac.verify_slice(ring_tag.as_ref())
            .expect("rustcrypto should verify ring HMAC-SHA256 tag");
    }

    #[test]
    fn rustcrypto_tag_ring_verify_sha256() {
        let fx = fx();
        let secret = fx.hmac("cross-hmac-256-rc2r", HmacSpec::hs256());

        // Tag with RustCrypto
        let mut mac = secret.hmac_sha256();
        let msg = b"rustcrypto-to-ring HMAC-SHA256 test";
        mac.update(msg);
        let tag = mac.finalize().into_bytes();

        // Verify with ring
        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.secret_bytes());
        ring::hmac::verify(&ring_key, msg, &tag)
            .expect("ring should verify rustcrypto HMAC-SHA256 tag");
    }

    #[test]
    fn ring_tag_rustcrypto_verify_sha384() {
        let fx = fx();
        let secret = fx.hmac("cross-hmac-384-r2rc", HmacSpec::hs384());

        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA384, secret.secret_bytes());
        let msg = b"ring-to-rustcrypto HMAC-SHA384 test";
        let ring_tag = ring::hmac::sign(&ring_key, msg);

        let mut mac = secret.hmac_sha384();
        mac.update(msg);
        mac.verify_slice(ring_tag.as_ref())
            .expect("rustcrypto should verify ring HMAC-SHA384 tag");
    }

    #[test]
    fn rustcrypto_tag_ring_verify_sha384() {
        let fx = fx();
        let secret = fx.hmac("cross-hmac-384-rc2r", HmacSpec::hs384());

        let mut mac = secret.hmac_sha384();
        let msg = b"rustcrypto-to-ring HMAC-SHA384 test";
        mac.update(msg);
        let tag = mac.finalize().into_bytes();

        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA384, secret.secret_bytes());
        ring::hmac::verify(&ring_key, msg, &tag)
            .expect("ring should verify rustcrypto HMAC-SHA384 tag");
    }

    #[test]
    fn ring_tag_rustcrypto_verify_sha512() {
        let fx = fx();
        let secret = fx.hmac("cross-hmac-512-r2rc", HmacSpec::hs512());

        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, secret.secret_bytes());
        let msg = b"ring-to-rustcrypto HMAC-SHA512 test";
        let ring_tag = ring::hmac::sign(&ring_key, msg);

        let mut mac = secret.hmac_sha512();
        mac.update(msg);
        mac.verify_slice(ring_tag.as_ref())
            .expect("rustcrypto should verify ring HMAC-SHA512 tag");
    }

    #[test]
    fn rustcrypto_tag_ring_verify_sha512() {
        let fx = fx();
        let secret = fx.hmac("cross-hmac-512-rc2r", HmacSpec::hs512());

        let mut mac = secret.hmac_sha512();
        let msg = b"rustcrypto-to-ring HMAC-SHA512 test";
        mac.update(msg);
        let tag = mac.finalize().into_bytes();

        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, secret.secret_bytes());
        ring::hmac::verify(&ring_key, msg, &tag)
            .expect("ring should verify rustcrypto HMAC-SHA512 tag");
    }
}
