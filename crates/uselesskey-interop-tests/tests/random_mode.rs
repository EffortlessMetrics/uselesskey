//! Random-mode interop tests.
//!
//! These tests use `Factory::random()` (non-deterministic) and verify that
//! the generated keys still work across all adapters.

use uselesskey_core::Factory;

fn random_fx() -> Factory {
    Factory::random()
}

// =========================================================================
// RSA random mode
// =========================================================================

mod rsa_random {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn random_rsa_ring_parse() {
        let fx = random_fx();
        let kp = fx.rsa("rand-rsa-ring", RsaSpec::rs256());
        let _ring_kp = ring::rsa::KeyPair::from_pkcs8(kp.private_key_pkcs8_der())
            .expect("ring should parse random RSA key");
    }

    #[test]
    fn random_rsa_rustcrypto_parse() {
        let fx = random_fx();
        let kp = fx.rsa("rand-rsa-rc", RsaSpec::rs256());
        use rsa::pkcs8::DecodePrivateKey;
        let _pk = rsa::RsaPrivateKey::from_pkcs8_der(kp.private_key_pkcs8_der())
            .expect("rustcrypto should parse random RSA key");
    }

    #[cfg(feature = "cross-signing")]
    #[test]
    fn random_rsa_ring_sign_rustcrypto_verify() {
        use ring::signature as ring_sig;
        use uselesskey_ring::RingRsaKeyPairExt;
        use uselesskey_rustcrypto::RustCryptoRsaExt;

        let fx = random_fx();
        let kp = fx.rsa("rand-rsa-cross", RsaSpec::rs256());

        let ring_kp = kp.rsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"random RSA ring-to-rustcrypto";
        let mut sig = vec![0u8; ring_kp.public().modulus_len()];
        ring_kp
            .sign(&ring_sig::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("ring sign");

        use rsa::pkcs1v15;
        use rsa::signature::Verifier;
        use sha2::Sha256;
        let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(kp.rsa_public_key());
        let signature =
            pkcs1v15::Signature::try_from(sig.as_slice()).expect("valid signature bytes");
        verifying_key
            .verify(msg, &signature)
            .expect("rustcrypto should verify random ring-signed RSA");
    }

    #[cfg(feature = "jwt-interop")]
    #[test]
    fn random_rsa_jwt_round_trip() {
        use uselesskey_jsonwebtoken::JwtKeyExt;

        let fx = random_fx();
        let kp = fx.rsa("rand-rsa-jwt", RsaSpec::rs256());
        let claims = serde_json::json!({
            "sub": "random-rsa",
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
        assert_eq!(decoded.claims["sub"], "random-rsa");
    }
}

// =========================================================================
// ECDSA random mode
// =========================================================================

mod ecdsa_random {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

    #[test]
    fn random_p256_ring_parse() {
        let fx = random_fx();
        let kp = fx.ecdsa("rand-p256-ring", EcdsaSpec::es256());
        let _ring_kp = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            kp.private_key_pkcs8_der(),
            &ring::rand::SystemRandom::new(),
        )
        .expect("ring should parse random P-256 key");
    }

    #[test]
    fn random_p384_ring_parse() {
        let fx = random_fx();
        let kp = fx.ecdsa("rand-p384-ring", EcdsaSpec::es384());
        let _ring_kp = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            kp.private_key_pkcs8_der(),
            &ring::rand::SystemRandom::new(),
        )
        .expect("ring should parse random P-384 key");
    }

    #[test]
    fn random_p256_rustcrypto_parse() {
        let fx = random_fx();
        let kp = fx.ecdsa("rand-p256-rc", EcdsaSpec::es256());
        use p256::pkcs8::DecodePrivateKey;
        let _sk = p256::ecdsa::SigningKey::from_pkcs8_der(kp.private_key_pkcs8_der())
            .expect("rustcrypto should parse random P-256 key");
    }

    #[test]
    fn random_p384_rustcrypto_parse() {
        let fx = random_fx();
        let kp = fx.ecdsa("rand-p384-rc", EcdsaSpec::es384());
        use p384::pkcs8::DecodePrivateKey;
        let _sk = p384::ecdsa::SigningKey::from_pkcs8_der(kp.private_key_pkcs8_der())
            .expect("rustcrypto should parse random P-384 key");
    }

    #[cfg(feature = "cross-signing")]
    #[test]
    fn random_p256_ring_sign_rustcrypto_verify() {
        use p256::ecdsa::signature::Verifier;
        use uselesskey_ring::RingEcdsaKeyPairExt;
        use uselesskey_rustcrypto::RustCryptoEcdsaExt;

        let fx = random_fx();
        let kp = fx.ecdsa("rand-p256-cross", EcdsaSpec::es256());

        let ring_kp = kp.ecdsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"random P-256 ring-to-rustcrypto";
        let sig = ring_kp.sign(&rng, msg).expect("ring sign");

        let verifying_key = kp.p256_verifying_key();
        let der_sig = p256::ecdsa::DerSignature::try_from(sig.as_ref()).expect("valid ASN.1 sig");
        verifying_key
            .verify(msg, &der_sig)
            .expect("rustcrypto should verify random ring-signed P-256");
    }

    #[cfg(feature = "cross-signing")]
    #[test]
    fn random_p384_ring_sign_rustcrypto_verify() {
        use p384::ecdsa::signature::Verifier;
        use uselesskey_ring::RingEcdsaKeyPairExt;
        use uselesskey_rustcrypto::RustCryptoEcdsaExt;

        let fx = random_fx();
        let kp = fx.ecdsa("rand-p384-cross", EcdsaSpec::es384());

        let ring_kp = kp.ecdsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"random P-384 ring-to-rustcrypto";
        let sig = ring_kp.sign(&rng, msg).expect("ring sign");

        let verifying_key = kp.p384_verifying_key();
        let der_sig = p384::ecdsa::DerSignature::try_from(sig.as_ref()).expect("valid ASN.1 sig");
        verifying_key
            .verify(msg, &der_sig)
            .expect("rustcrypto should verify random ring-signed P-384");
    }

    #[cfg(feature = "jwt-interop")]
    #[test]
    fn random_p256_jwt_round_trip() {
        use uselesskey_jsonwebtoken::JwtKeyExt;

        let fx = random_fx();
        let kp = fx.ecdsa("rand-p256-jwt", EcdsaSpec::es256());
        let claims = serde_json::json!({
            "sub": "random-p256",
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
        assert_eq!(decoded.claims["sub"], "random-p256");
    }
}

// =========================================================================
// Ed25519 random mode
// =========================================================================

mod ed25519_random {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn random_ed25519_ring_parse() {
        let fx = random_fx();
        let kp = fx.ed25519("rand-ed-ring", Ed25519Spec::new());
        let _ring_kp =
            ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(kp.private_key_pkcs8_der())
                .expect("ring should parse random Ed25519 key");
    }

    #[test]
    fn random_ed25519_rustcrypto_parse() {
        let fx = random_fx();
        let kp = fx.ed25519("rand-ed-rc", Ed25519Spec::new());
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let _sk = ed25519_dalek::SigningKey::from_pkcs8_der(kp.private_key_pkcs8_der())
            .expect("rustcrypto should parse random Ed25519 key");
    }

    #[cfg(feature = "cross-signing")]
    #[test]
    fn random_ed25519_ring_sign_rustcrypto_verify() {
        use ed25519_dalek::Verifier;
        use uselesskey_ring::RingEd25519KeyPairExt;
        use uselesskey_rustcrypto::RustCryptoEd25519Ext;

        let fx = random_fx();
        let kp = fx.ed25519("rand-ed-cross", Ed25519Spec::new());

        let ring_kp = kp.ed25519_key_pair_ring();
        let msg = b"random Ed25519 ring-to-rustcrypto";
        let sig = ring_kp.sign(msg);

        let verifying_key = kp.ed25519_verifying_key();
        let dalek_sig =
            ed25519_dalek::Signature::from_slice(sig.as_ref()).expect("valid 64-byte sig");
        verifying_key
            .verify(msg, &dalek_sig)
            .expect("rustcrypto should verify random ring-signed Ed25519");
    }

    #[cfg(feature = "jwt-interop")]
    #[test]
    fn random_ed25519_jwt_round_trip() {
        use uselesskey_jsonwebtoken::JwtKeyExt;

        let fx = random_fx();
        let kp = fx.ed25519("rand-ed-jwt", Ed25519Spec::new());
        let claims = serde_json::json!({
            "sub": "random-ed25519",
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
        assert_eq!(decoded.claims["sub"], "random-ed25519");
    }
}

// =========================================================================
// X.509 random mode TLS
// =========================================================================

#[cfg(feature = "cross-tls")]
mod x509_random_tls {
    use super::*;
    use std::sync::Arc;
    use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};
    use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

    const MAX_HANDSHAKE_ITERATIONS: usize = 10;

    fn complete_handshake(
        client: &mut rustls::ClientConnection,
        server: &mut rustls::ServerConnection,
    ) {
        let mut buf = Vec::new();
        for iteration in 0..MAX_HANDSHAKE_ITERATIONS {
            let mut progress = false;

            buf.clear();
            if client.wants_write() {
                client.write_tls(&mut buf).unwrap();
                if !buf.is_empty() {
                    server.read_tls(&mut &buf[..]).unwrap();
                    server.process_new_packets().unwrap();
                    progress = true;
                }
            }

            buf.clear();
            if server.wants_write() {
                server.write_tls(&mut buf).unwrap();
                if !buf.is_empty() {
                    client.read_tls(&mut &buf[..]).unwrap();
                    client.process_new_packets().unwrap();
                    progress = true;
                }
            }

            if !progress {
                break;
            }

            assert!(
                iteration < MAX_HANDSHAKE_ITERATIONS - 1,
                "TLS handshake did not complete within {MAX_HANDSHAKE_ITERATIONS} iterations",
            );
        }

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
    }

    #[test]
    fn random_chain_tls_handshake() {
        let fx = random_fx();
        let chain = fx.x509_chain("rand-tls-chain", ChainSpec::new("random.example.com"));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

        let server_name = "random.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();

        complete_handshake(&mut client, &mut server);
    }

    #[test]
    fn random_self_signed_tls_handshake() {
        let fx = random_fx();
        let cert = fx.x509_self_signed(
            "rand-tls-ss",
            X509Spec::self_signed("random-ss.example.com")
                .with_sans(vec!["random-ss.example.com".into()]),
        );

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = Arc::new(cert.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(cert.client_config_rustls_with_provider(provider));

        let server_name = "random-ss.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();

        complete_handshake(&mut client, &mut server);
    }
}
