//! Verify that every key type generated via uselesskey works correctly when
//! converted through ALL adapter crates (ring, rustcrypto, jsonwebtoken,
//! rustls, aws-lc-rs).
//!
//! These tests don't cross-sign; they confirm that each adapter can parse and
//! use the generated key material.

use std::sync::OnceLock;

use uselesskey_core::{Factory, Seed};

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> &'static Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-all-adapters-seed-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
}

// =========================================================================
// RSA through every adapter
// =========================================================================

mod rsa_all_adapters {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rsa_ring_parse() {
        let kp = fx().rsa("all-rsa-ring", RsaSpec::rs256());
        let ring_kp = ring::rsa::KeyPair::from_pkcs8(kp.private_key_pkcs8_der())
            .expect("ring should parse RSA PKCS#8 DER");
        assert_eq!(ring_kp.public().modulus_len(), 256); // 2048-bit
    }

    #[test]
    fn rsa_rustcrypto_parse() {
        let kp = fx().rsa("all-rsa-rc", RsaSpec::rs256());
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::traits::PublicKeyParts;
        let priv_key = rsa::RsaPrivateKey::from_pkcs8_der(kp.private_key_pkcs8_der())
            .expect("rustcrypto should parse RSA PKCS#8 DER");
        assert_eq!(priv_key.size(), 256);
    }

    #[cfg(feature = "jwt-interop")]
    #[test]
    fn rsa_jsonwebtoken_round_trip() {
        use uselesskey_jsonwebtoken::JwtKeyExt;

        let kp = fx().rsa("all-rsa-jwt", RsaSpec::rs256());
        let claims = serde_json::json!({
            "sub": "all-adapter-rsa",
            "iss": "uselesskey",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let token = jsonwebtoken::encode(&header, &claims, &kp.encoding_key()).expect("JWT encode");

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&["uselesskey"]);
        let decoded =
            jsonwebtoken::decode::<serde_json::Value>(&token, &kp.decoding_key(), &validation)
                .expect("JWT decode");
        assert_eq!(decoded.claims["sub"], "all-adapter-rsa");
    }

    #[cfg(feature = "cross-tls")]
    #[test]
    fn rsa_rustls_private_key_der() {
        use uselesskey_rustls::RustlsPrivateKeyExt;

        let kp = fx().rsa("all-rsa-rustls", RsaSpec::rs256());
        let der = kp.private_key_der_rustls();
        assert!(!der.secret_der().is_empty());
    }

    #[cfg(all(feature = "aws-lc-rs-interop", any(not(windows), has_nasm)))]
    #[test]
    fn rsa_aws_lc_rs_parse() {
        let kp = fx().rsa("all-rsa-aws", RsaSpec::rs256());
        let aws_kp = aws_lc_rs::rsa::KeyPair::from_pkcs8(kp.private_key_pkcs8_der())
            .expect("aws-lc-rs should parse RSA PKCS#8 DER");
        assert_eq!(aws_kp.public_modulus_len(), 256);
    }

    #[cfg(feature = "cross-signing")]
    #[test]
    fn rsa_ring_sign_verify() {
        use ring::signature as ring_sig;
        use uselesskey_ring::RingRsaKeyPairExt;

        let kp = fx().rsa("all-rsa-ring-sv", RsaSpec::rs256());
        let ring_kp = kp.rsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"RSA ring sign-verify in all-adapters";
        let mut sig = vec![0u8; ring_kp.public().modulus_len()];
        ring_kp
            .sign(&ring_sig::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("ring sign");

        let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
        let public_key =
            ring_sig::UnparsedPublicKey::new(&ring_sig::RSA_PKCS1_2048_8192_SHA256, raw_pubkey);
        public_key.verify(msg, &sig).expect("ring self-verify");
    }

    #[cfg(feature = "cross-signing")]
    #[test]
    fn rsa_rustcrypto_sign_verify() {
        use rsa::pkcs1v15;
        use rsa::signature::{Signer, Verifier};
        use sha2::Sha256;
        use uselesskey_rustcrypto::RustCryptoRsaExt;

        let kp = fx().rsa("all-rsa-rc-sv", RsaSpec::rs256());
        let priv_key = kp.rsa_private_key();
        let pub_key = kp.rsa_public_key();
        let signing_key = pkcs1v15::SigningKey::<Sha256>::new(priv_key);
        let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(pub_key);
        let msg = b"RSA rustcrypto sign-verify in all-adapters";
        let sig = signing_key.sign(msg);
        verifying_key
            .verify(msg, &sig)
            .expect("rustcrypto self-verify");
    }

    #[cfg(all(
        feature = "cross-signing",
        feature = "aws-lc-rs-interop",
        any(not(windows), has_nasm)
    ))]
    #[test]
    fn rsa_aws_lc_rs_sign_verify() {
        use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;

        let kp = fx().rsa("all-rsa-aws-sv", RsaSpec::rs256());
        let aws_kp = kp.rsa_key_pair_aws_lc_rs();
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let msg = b"RSA aws-lc-rs sign-verify in all-adapters";
        let mut sig = vec![0u8; aws_kp.public_modulus_len()];
        aws_kp
            .sign(&aws_lc_rs::signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("aws sign");
        // Verify via raw public key
        let spki = kp.public_key_spki_der();
        let public_key = aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
            extract_public_key_from_spki(spki),
        );
        public_key.verify(msg, &sig).expect("aws-lc-rs self-verify");
    }
}

// =========================================================================
// ECDSA P-256 through every adapter
// =========================================================================

mod ecdsa_p256_all_adapters {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn p256_ring_parse() {
        let kp = fx().ecdsa("all-p256-ring", EcdsaSpec::es256());
        let _ring_kp = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            kp.private_key_pkcs8_der(),
            &ring::rand::SystemRandom::new(),
        )
        .expect("ring should parse P-256 PKCS#8");
    }

    #[test]
    fn p256_rustcrypto_parse() {
        use p256::pkcs8::DecodePrivateKey;

        let kp = fx().ecdsa("all-p256-rc", EcdsaSpec::es256());
        let _sk = p256::ecdsa::SigningKey::from_pkcs8_der(kp.private_key_pkcs8_der())
            .expect("rustcrypto should parse P-256 PKCS#8");
    }

    #[cfg(feature = "jwt-interop")]
    #[test]
    fn p256_jsonwebtoken_round_trip() {
        use uselesskey_jsonwebtoken::JwtKeyExt;

        let kp = fx().ecdsa("all-p256-jwt", EcdsaSpec::es256());
        let claims = serde_json::json!({
            "sub": "all-adapter-p256",
            "iss": "uselesskey",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        let token = jsonwebtoken::encode(&header, &claims, &kp.encoding_key()).expect("JWT encode");

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&["uselesskey"]);
        let decoded =
            jsonwebtoken::decode::<serde_json::Value>(&token, &kp.decoding_key(), &validation)
                .expect("JWT decode");
        assert_eq!(decoded.claims["sub"], "all-adapter-p256");
    }

    #[cfg(all(feature = "aws-lc-rs-interop", any(not(windows), has_nasm)))]
    #[test]
    fn p256_aws_lc_rs_parse() {
        let kp = fx().ecdsa("all-p256-aws", EcdsaSpec::es256());
        let _aws_kp = aws_lc_rs::signature::EcdsaKeyPair::from_pkcs8(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            kp.private_key_pkcs8_der(),
        )
        .expect("aws-lc-rs should parse P-256 PKCS#8");
    }
}

// =========================================================================
// ECDSA P-384 through every adapter
// =========================================================================

mod ecdsa_p384_all_adapters {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn p384_ring_parse() {
        let kp = fx().ecdsa("all-p384-ring", EcdsaSpec::es384());
        let _ring_kp = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            kp.private_key_pkcs8_der(),
            &ring::rand::SystemRandom::new(),
        )
        .expect("ring should parse P-384 PKCS#8");
    }

    #[test]
    fn p384_rustcrypto_parse() {
        use p384::pkcs8::DecodePrivateKey;

        let kp = fx().ecdsa("all-p384-rc", EcdsaSpec::es384());
        let _sk = p384::ecdsa::SigningKey::from_pkcs8_der(kp.private_key_pkcs8_der())
            .expect("rustcrypto should parse P-384 PKCS#8");
    }

    #[cfg(feature = "jwt-interop")]
    #[test]
    fn p384_jsonwebtoken_round_trip() {
        use uselesskey_jsonwebtoken::JwtKeyExt;

        let kp = fx().ecdsa("all-p384-jwt", EcdsaSpec::es384());
        let claims = serde_json::json!({
            "sub": "all-adapter-p384",
            "iss": "uselesskey",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES384);
        let token = jsonwebtoken::encode(&header, &claims, &kp.encoding_key()).expect("JWT encode");

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES384);
        validation.set_issuer(&["uselesskey"]);
        let decoded =
            jsonwebtoken::decode::<serde_json::Value>(&token, &kp.decoding_key(), &validation)
                .expect("JWT decode");
        assert_eq!(decoded.claims["sub"], "all-adapter-p384");
    }

    #[cfg(all(feature = "aws-lc-rs-interop", any(not(windows), has_nasm)))]
    #[test]
    fn p384_aws_lc_rs_parse() {
        let kp = fx().ecdsa("all-p384-aws", EcdsaSpec::es384());
        let _aws_kp = aws_lc_rs::signature::EcdsaKeyPair::from_pkcs8(
            &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            kp.private_key_pkcs8_der(),
        )
        .expect("aws-lc-rs should parse P-384 PKCS#8");
    }

    #[cfg(feature = "cross-signing")]
    #[test]
    fn p384_ring_sign_rustcrypto_verify() {
        use uselesskey_ring::RingEcdsaKeyPairExt;

        let kp = fx().ecdsa("all-p384-r2rc", EcdsaSpec::es384());
        let ring_kp = kp.ecdsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"P-384 ring sign, rustcrypto verify";
        let sig = ring_kp.sign(&rng, msg).expect("ring sign");

        use p384::ecdsa::signature::Verifier;
        use uselesskey_rustcrypto::RustCryptoEcdsaExt;
        let verifying_key = kp.p384_verifying_key();
        let der_sig = p384::ecdsa::DerSignature::try_from(sig.as_ref()).expect("valid ASN.1 sig");
        verifying_key
            .verify(msg, &der_sig)
            .expect("rustcrypto should verify ring-signed P-384 signature");
    }

    #[cfg(feature = "cross-signing")]
    #[test]
    fn p384_rustcrypto_sign_ring_verify() {
        use p384::ecdsa::signature::Signer;
        use ring::signature as ring_sig;
        use uselesskey_rustcrypto::RustCryptoEcdsaExt;

        let kp = fx().ecdsa("all-p384-rc2r", EcdsaSpec::es384());
        let signing_key = kp.p384_signing_key();
        let msg = b"P-384 rustcrypto sign, ring verify";
        let sig: p384::ecdsa::DerSignature = signing_key.sign(msg);

        let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
        let public_key =
            ring_sig::UnparsedPublicKey::new(&ring_sig::ECDSA_P384_SHA384_ASN1, raw_pubkey);
        public_key
            .verify(msg, sig.as_bytes())
            .expect("ring should verify rustcrypto-signed P-384 signature");
    }

    #[cfg(all(
        feature = "cross-signing",
        feature = "aws-lc-rs-interop",
        any(not(windows), has_nasm)
    ))]
    #[test]
    fn p384_aws_sign_ring_verify() {
        use ring::signature as ring_sig;
        use uselesskey_aws_lc_rs::AwsLcRsEcdsaKeyPairExt;

        let kp = fx().ecdsa("all-p384-a2r", EcdsaSpec::es384());
        let aws_kp = kp.ecdsa_key_pair_aws_lc_rs();
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let msg = b"P-384 aws sign, ring verify";
        let sig = aws_kp.sign(&rng, msg).expect("aws sign");

        let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
        let public_key =
            ring_sig::UnparsedPublicKey::new(&ring_sig::ECDSA_P384_SHA384_ASN1, raw_pubkey);
        public_key
            .verify(msg, sig.as_ref())
            .expect("ring should verify aws-signed P-384 signature");
    }
}

// =========================================================================
// Ed25519 through every adapter
// =========================================================================

mod ed25519_all_adapters {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn ed25519_ring_parse() {
        let kp = fx().ed25519("all-ed-ring", Ed25519Spec::new());
        let _ring_kp =
            ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(kp.private_key_pkcs8_der())
                .expect("ring should parse Ed25519 PKCS#8");
    }

    #[test]
    fn ed25519_rustcrypto_parse() {
        use ed25519_dalek::pkcs8::DecodePrivateKey;

        let kp = fx().ed25519("all-ed-rc", Ed25519Spec::new());
        let _sk = ed25519_dalek::SigningKey::from_pkcs8_der(kp.private_key_pkcs8_der())
            .expect("rustcrypto should parse Ed25519 PKCS#8");
    }

    #[cfg(feature = "jwt-interop")]
    #[test]
    fn ed25519_jsonwebtoken_round_trip() {
        use uselesskey_jsonwebtoken::JwtKeyExt;

        let kp = fx().ed25519("all-ed-jwt", Ed25519Spec::new());
        let claims = serde_json::json!({
            "sub": "all-adapter-ed25519",
            "iss": "uselesskey",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        let token = jsonwebtoken::encode(&header, &claims, &kp.encoding_key()).expect("JWT encode");

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_issuer(&["uselesskey"]);
        let decoded =
            jsonwebtoken::decode::<serde_json::Value>(&token, &kp.decoding_key(), &validation)
                .expect("JWT decode");
        assert_eq!(decoded.claims["sub"], "all-adapter-ed25519");
    }

    #[cfg(all(feature = "aws-lc-rs-interop", any(not(windows), has_nasm)))]
    #[test]
    fn ed25519_aws_lc_rs_parse() {
        let kp = fx().ed25519("all-ed-aws", Ed25519Spec::new());
        let _aws_kp = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(kp.private_key_pkcs8_der())
            .expect("aws-lc-rs should parse Ed25519 PKCS#8");
    }
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
