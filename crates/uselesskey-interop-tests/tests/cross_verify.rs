//! Cross-verification tests: sign with one adapter, verify with a *different* one.
//!
//! Covers every feasible pair among ring, rustcrypto, aws-lc-rs, and
//! jsonwebtoken for RSA, ECDSA P-256, ECDSA P-384, and Ed25519.

use std::sync::OnceLock;

use uselesskey_core::{Factory, Seed};

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> &'static Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-cross-verify-seed-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
}

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
// rustcrypto ↔ aws-lc-rs (RSA, ECDSA, Ed25519)
// =========================================================================

#[cfg(all(
    feature = "cross-signing",
    feature = "aws-lc-rs-interop",
    any(not(windows), has_nasm)
))]
mod rustcrypto_aws {
    use super::*;

    mod rsa_cross {
        use super::*;
        use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;
        use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
        use uselesskey_rustcrypto::RustCryptoRsaExt;

        #[test]
        fn rustcrypto_sign_aws_verify() {
            let kp = fx().rsa("xv-rsa-rc2a", RsaSpec::rs256());

            use rsa::pkcs1v15;
            use rsa::signature::{SignatureEncoding, Signer};
            use sha2::Sha256;
            let signing_key = pkcs1v15::SigningKey::<Sha256>::new(kp.rsa_private_key());
            let msg = b"rustcrypto-to-aws RSA cross-verify";
            let sig = signing_key.sign(msg);

            let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
            let public_key = aws_lc_rs::signature::UnparsedPublicKey::new(
                &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
                raw_pubkey,
            );
            public_key
                .verify(msg, &sig.to_bytes())
                .expect("aws-lc-rs should verify rustcrypto-signed RSA");
        }

        #[test]
        fn aws_sign_rustcrypto_verify() {
            let kp = fx().rsa("xv-rsa-a2rc", RsaSpec::rs256());

            let aws_kp = kp.rsa_key_pair_aws_lc_rs();
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let msg = b"aws-to-rustcrypto RSA cross-verify";
            let mut sig = vec![0u8; aws_kp.public_modulus_len()];
            aws_kp
                .sign(&aws_lc_rs::signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
                .expect("aws sign");

            use rsa::pkcs1v15;
            use rsa::signature::Verifier;
            use sha2::Sha256;
            let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(kp.rsa_public_key());
            let signature = pkcs1v15::Signature::try_from(sig.as_slice()).expect("valid signature");
            verifying_key
                .verify(msg, &signature)
                .expect("rustcrypto should verify aws-signed RSA");
        }
    }

    mod ecdsa_p256_cross {
        use super::*;
        use uselesskey_aws_lc_rs::AwsLcRsEcdsaKeyPairExt;
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
        use uselesskey_rustcrypto::RustCryptoEcdsaExt;

        #[test]
        fn rustcrypto_sign_aws_verify() {
            let kp = fx().ecdsa("xv-p256-rc2a", EcdsaSpec::es256());

            use p256::ecdsa::signature::Signer;
            let signing_key = kp.p256_signing_key();
            let msg = b"rustcrypto-to-aws P-256 cross-verify";
            let sig: p256::ecdsa::DerSignature = signing_key.sign(msg);

            let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
            let public_key = aws_lc_rs::signature::UnparsedPublicKey::new(
                &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
                raw_pubkey,
            );
            public_key
                .verify(msg, sig.as_bytes())
                .expect("aws-lc-rs should verify rustcrypto-signed P-256");
        }

        #[test]
        fn aws_sign_rustcrypto_verify() {
            let kp = fx().ecdsa("xv-p256-a2rc", EcdsaSpec::es256());

            let aws_kp = kp.ecdsa_key_pair_aws_lc_rs();
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let msg = b"aws-to-rustcrypto P-256 cross-verify";
            let sig = aws_kp.sign(&rng, msg).expect("aws sign");

            use p256::ecdsa::signature::Verifier;
            let verifying_key = kp.p256_verifying_key();
            let der_sig =
                p256::ecdsa::DerSignature::try_from(sig.as_ref()).expect("valid ASN.1 sig");
            verifying_key
                .verify(msg, &der_sig)
                .expect("rustcrypto should verify aws-signed P-256");
        }
    }

    mod ecdsa_p384_cross {
        use super::*;
        use uselesskey_aws_lc_rs::AwsLcRsEcdsaKeyPairExt;
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
        use uselesskey_rustcrypto::RustCryptoEcdsaExt;

        #[test]
        fn rustcrypto_sign_aws_verify() {
            let kp = fx().ecdsa("xv-p384-rc2a", EcdsaSpec::es384());

            use p384::ecdsa::signature::Signer;
            let signing_key = kp.p384_signing_key();
            let msg = b"rustcrypto-to-aws P-384 cross-verify";
            let sig: p384::ecdsa::DerSignature = signing_key.sign(msg);

            let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
            let public_key = aws_lc_rs::signature::UnparsedPublicKey::new(
                &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1,
                raw_pubkey,
            );
            public_key
                .verify(msg, sig.as_bytes())
                .expect("aws-lc-rs should verify rustcrypto-signed P-384");
        }

        #[test]
        fn aws_sign_rustcrypto_verify() {
            let kp = fx().ecdsa("xv-p384-a2rc", EcdsaSpec::es384());

            let aws_kp = kp.ecdsa_key_pair_aws_lc_rs();
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let msg = b"aws-to-rustcrypto P-384 cross-verify";
            let sig = aws_kp.sign(&rng, msg).expect("aws sign");

            use p384::ecdsa::signature::Verifier;
            let verifying_key = kp.p384_verifying_key();
            let der_sig =
                p384::ecdsa::DerSignature::try_from(sig.as_ref()).expect("valid ASN.1 sig");
            verifying_key
                .verify(msg, &der_sig)
                .expect("rustcrypto should verify aws-signed P-384");
        }
    }

    mod ed25519_cross {
        use super::*;
        use uselesskey_aws_lc_rs::AwsLcRsEd25519KeyPairExt;
        use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
        use uselesskey_rustcrypto::RustCryptoEd25519Ext;

        #[test]
        fn rustcrypto_sign_aws_verify() {
            let kp = fx().ed25519("xv-ed-rc2a", Ed25519Spec::new());

            use ed25519_dalek::Signer;
            let signing_key = kp.ed25519_signing_key();
            let msg = b"rustcrypto-to-aws Ed25519 cross-verify";
            let sig = signing_key.sign(msg);

            let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
            let public_key = aws_lc_rs::signature::UnparsedPublicKey::new(
                &aws_lc_rs::signature::ED25519,
                raw_pubkey,
            );
            public_key
                .verify(msg, sig.to_bytes().as_ref())
                .expect("aws-lc-rs should verify rustcrypto-signed Ed25519");
        }

        #[test]
        fn aws_sign_rustcrypto_verify() {
            let kp = fx().ed25519("xv-ed-a2rc", Ed25519Spec::new());

            let aws_kp = kp.ed25519_key_pair_aws_lc_rs();
            let msg = b"aws-to-rustcrypto Ed25519 cross-verify";
            let sig = aws_kp.sign(msg);

            use ed25519_dalek::Verifier;
            let verifying_key = kp.ed25519_verifying_key();
            let dalek_sig = ed25519_dalek::Signature::from_slice(sig.as_ref())
                .expect("valid 64-byte signature");
            verifying_key
                .verify(msg, &dalek_sig)
                .expect("rustcrypto should verify aws-signed Ed25519");
        }
    }
}

// =========================================================================
// JWT cross-verify: sign JWT, then verify raw signature with ring/rustcrypto
// =========================================================================

#[cfg(all(feature = "jwt-interop", feature = "cross-signing"))]
mod jwt_cross_verify {
    use super::*;
    use uselesskey_jsonwebtoken::JwtKeyExt;

    #[test]
    fn jwt_rsa_sign_ring_verify_raw() {
        use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

        let kp = fx().rsa("xv-jwt-rsa-ring", RsaSpec::rs256());
        let claims = serde_json::json!({
            "sub": "jwt-cross-rsa",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let token = jsonwebtoken::encode(&header, &claims, &kp.encoding_key()).expect("JWT encode");

        // Extract signing input and signature from the JWT
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = base64_url_decode(parts[2]);

        // Verify with ring
        let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            raw_pubkey,
        );
        public_key
            .verify(signing_input.as_bytes(), &sig_bytes)
            .expect("ring should verify JWT RS256 signature");
    }

    #[test]
    fn jwt_ecdsa_sign_ring_verify_raw() {
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

        let kp = fx().ecdsa("xv-jwt-p256-ring", EcdsaSpec::es256());
        let claims = serde_json::json!({
            "sub": "jwt-cross-p256",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        let token = jsonwebtoken::encode(&header, &claims, &kp.encoding_key()).expect("JWT encode");

        let parts: Vec<&str> = token.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = base64_url_decode(parts[2]);

        // JWT ES256 uses fixed-size (r || s) encoding; convert to ASN.1 DER for ring
        let der_sig = p256_fixed_to_der(&sig_bytes);

        let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            raw_pubkey,
        );
        public_key
            .verify(signing_input.as_bytes(), &der_sig)
            .expect("ring should verify JWT ES256 signature");
    }

    #[test]
    fn jwt_ed25519_sign_ring_verify_raw() {
        use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

        let kp = fx().ed25519("xv-jwt-ed-ring", Ed25519Spec::new());
        let claims = serde_json::json!({
            "sub": "jwt-cross-ed25519",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        let token = jsonwebtoken::encode(&header, &claims, &kp.encoding_key()).expect("JWT encode");

        let parts: Vec<&str> = token.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = base64_url_decode(parts[2]);

        let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
        let public_key =
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, raw_pubkey);
        public_key
            .verify(signing_input.as_bytes(), &sig_bytes)
            .expect("ring should verify JWT EdDSA signature");
    }

    // --- helpers ---

    fn base64_url_decode(input: &str) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(input)
            .expect("valid base64url")
    }

    /// Convert a fixed-size (r || s) P-256 signature to ASN.1 DER.
    fn p256_fixed_to_der(fixed: &[u8]) -> Vec<u8> {
        assert_eq!(fixed.len(), 64, "P-256 fixed signature must be 64 bytes");
        let r = &fixed[..32];
        let s = &fixed[32..];

        fn encode_integer(val: &[u8]) -> Vec<u8> {
            // Strip leading zeros, then add 0x00 pad if high bit set
            let stripped = match val.iter().position(|&b| b != 0) {
                Some(pos) => &val[pos..],
                None => &[0u8],
            };
            let mut out = Vec::new();
            out.push(0x02); // INTEGER tag
            if stripped[0] & 0x80 != 0 {
                out.push((stripped.len() + 1) as u8);
                out.push(0x00);
            } else {
                out.push(stripped.len() as u8);
            }
            out.extend_from_slice(stripped);
            out
        }

        let r_enc = encode_integer(r);
        let s_enc = encode_integer(s);
        let mut der = Vec::new();
        der.push(0x30); // SEQUENCE tag
        der.push((r_enc.len() + s_enc.len()) as u8);
        der.extend_from_slice(&r_enc);
        der.extend_from_slice(&s_enc);
        der
    }
}
