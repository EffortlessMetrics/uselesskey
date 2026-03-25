//! Expanded cross-adapter interoperability tests.
//!
//! Tests sign/verify across ring ↔ aws-lc-rs ↔ rustcrypto, TLS config
//! round-trips, JWK-based JWT workflows, and determinism verification.

use std::sync::OnceLock;

use uselesskey_core::{Factory, Seed};

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> &'static Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-cross-adapter-seed-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    })
}

// =========================================================================
// ASN.1 helpers (shared across modules)
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
// 1. Sign/Verify cross-adapter: ring ↔ aws-lc-rs
// =========================================================================

#[cfg(all(
    feature = "cross-signing",
    feature = "aws-lc-rs-interop",
    any(not(windows), has_nasm)
))]
mod ring_aws_lc_rs_cross {
    use super::*;
    use ring::signature as ring_sig;
    use uselesskey_aws_lc_rs::{
        AwsLcRsEcdsaKeyPairExt, AwsLcRsEd25519KeyPairExt, AwsLcRsRsaKeyPairExt,
    };
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_ring::{RingEcdsaKeyPairExt, RingEd25519KeyPairExt, RingRsaKeyPairExt};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    // ----- RSA -----

    #[test]
    fn rsa_ring_sign_aws_verify() {
        let fx = fx();
        let keypair = fx.rsa("xadapt-rsa-r2a", RsaSpec::rs256());

        // Sign with ring
        let ring_kp = keypair.rsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"ring-to-aws RSA cross-adapter test";
        let mut sig = vec![0u8; ring_kp.public().modulus_len()];
        ring_kp
            .sign(&ring_sig::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("ring sign");

        // Verify with aws-lc-rs
        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key = aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
            raw_pubkey,
        );
        public_key
            .verify(msg, &sig)
            .expect("aws-lc-rs should verify ring-signed RSA signature");
    }

    #[test]
    fn rsa_aws_sign_ring_verify() {
        let fx = fx();
        let keypair = fx.rsa("xadapt-rsa-a2r", RsaSpec::rs256());

        // Sign with aws-lc-rs
        let aws_kp = keypair.rsa_key_pair_aws_lc_rs();
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let msg = b"aws-to-ring RSA cross-adapter test";
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

    // ----- ECDSA P-256 -----

    #[test]
    fn ecdsa_ring_sign_aws_verify() {
        let fx = fx();
        let keypair = fx.ecdsa("xadapt-p256-r2a", EcdsaSpec::es256());

        let ring_kp = keypair.ecdsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"ring-to-aws ECDSA P-256 cross-adapter test";
        let sig = ring_kp.sign(&rng, msg).expect("ring sign");

        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key = aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
            raw_pubkey,
        );
        public_key
            .verify(msg, sig.as_ref())
            .expect("aws-lc-rs should verify ring-signed ECDSA P-256 signature");
    }

    #[test]
    fn ecdsa_aws_sign_ring_verify() {
        let fx = fx();
        let keypair = fx.ecdsa("xadapt-p256-a2r", EcdsaSpec::es256());

        let aws_kp = keypair.ecdsa_key_pair_aws_lc_rs();
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let msg = b"aws-to-ring ECDSA P-256 cross-adapter test";
        let sig = aws_kp.sign(&rng, msg).expect("aws sign");

        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key =
            ring_sig::UnparsedPublicKey::new(&ring_sig::ECDSA_P256_SHA256_ASN1, raw_pubkey);
        public_key
            .verify(msg, sig.as_ref())
            .expect("ring should verify aws-lc-rs-signed ECDSA P-256 signature");
    }

    // ----- Ed25519 -----

    #[test]
    fn ed25519_ring_sign_aws_verify() {
        let fx = fx();
        let keypair = fx.ed25519("xadapt-ed25519-r2a", Ed25519Spec::new());

        let ring_kp = keypair.ed25519_key_pair_ring();
        let msg = b"ring-to-aws Ed25519 cross-adapter test";
        let sig = ring_kp.sign(msg);

        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key = aws_lc_rs::signature::UnparsedPublicKey::new(
            &aws_lc_rs::signature::ED25519,
            raw_pubkey,
        );
        public_key
            .verify(msg, sig.as_ref())
            .expect("aws-lc-rs should verify ring-signed Ed25519 signature");
    }

    #[test]
    fn ed25519_aws_sign_ring_verify() {
        let fx = fx();
        let keypair = fx.ed25519("xadapt-ed25519-a2r", Ed25519Spec::new());

        let aws_kp = keypair.ed25519_key_pair_aws_lc_rs();
        let msg = b"aws-to-ring Ed25519 cross-adapter test";
        let sig = aws_kp.sign(msg);

        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key = ring_sig::UnparsedPublicKey::new(&ring_sig::ED25519, raw_pubkey);
        public_key
            .verify(msg, sig.as_ref())
            .expect("ring should verify aws-lc-rs-signed Ed25519 signature");
    }
}

// =========================================================================
// 1b. Sign/Verify cross-adapter: rustcrypto ↔ ring (beyond existing tests)
// =========================================================================

#[cfg(feature = "cross-signing")]
mod rustcrypto_ring_cross {
    use super::*;
    use ring::signature as ring_sig;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_ring::{RingEcdsaKeyPairExt, RingEd25519KeyPairExt, RingRsaKeyPairExt};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustcrypto::{RustCryptoEcdsaExt, RustCryptoEd25519Ext, RustCryptoRsaExt};

    // RSA: ring sign → rustcrypto verify
    #[test]
    fn rsa_ring_sign_rustcrypto_verify() {
        let fx = fx();
        let keypair = fx.rsa("xadapt-rsa-r2rc", RsaSpec::rs256());

        let ring_kp = keypair.rsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"ring-to-rustcrypto RSA cross-adapter expanded";
        let mut sig = vec![0u8; ring_kp.public().modulus_len()];
        ring_kp
            .sign(&ring_sig::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("ring sign");

        use rsa::pkcs1v15;
        use rsa::sha2::Sha256;
        use rsa::signature::Verifier;
        let public_key = keypair.rsa_public_key();
        let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
        let signature =
            pkcs1v15::Signature::try_from(sig.as_slice()).expect("valid signature bytes");
        verifying_key
            .verify(msg, &signature)
            .expect("rustcrypto should verify ring-signed RSA signature");
    }

    // RSA: rustcrypto sign → ring verify
    #[test]
    fn rsa_rustcrypto_sign_ring_verify() {
        let fx = fx();
        let keypair = fx.rsa("xadapt-rsa-rc2r", RsaSpec::rs256());

        use rsa::pkcs1v15;
        use rsa::sha2::Sha256;
        use rsa::signature::{SignatureEncoding, Signer};
        let private_key = keypair.rsa_private_key();
        let signing_key = pkcs1v15::SigningKey::<Sha256>::new(private_key);
        let msg = b"rustcrypto-to-ring RSA cross-adapter expanded";
        let sig = signing_key.sign(msg);

        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key =
            ring_sig::UnparsedPublicKey::new(&ring_sig::RSA_PKCS1_2048_8192_SHA256, raw_pubkey);
        public_key
            .verify(msg, &sig.to_bytes())
            .expect("ring should verify rustcrypto-signed RSA signature");
    }

    // ECDSA: ring sign → rustcrypto verify
    #[test]
    fn ecdsa_ring_sign_rustcrypto_verify() {
        let fx = fx();
        let keypair = fx.ecdsa("xadapt-p256-r2rc", EcdsaSpec::es256());

        let ring_kp = keypair.ecdsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"ring-to-rustcrypto ECDSA P-256 cross-adapter expanded";
        let sig = ring_kp.sign(&rng, msg).expect("ring sign");

        use p256::ecdsa::signature::Verifier;
        let verifying_key = keypair.p256_verifying_key();
        let der_sig =
            p256::ecdsa::DerSignature::try_from(sig.as_ref()).expect("valid ASN.1 signature");
        verifying_key
            .verify(msg, &der_sig)
            .expect("rustcrypto should verify ring-signed ECDSA P-256 signature");
    }

    // ECDSA: rustcrypto sign → ring verify
    #[test]
    fn ecdsa_rustcrypto_sign_ring_verify() {
        let fx = fx();
        let keypair = fx.ecdsa("xadapt-p256-rc2r", EcdsaSpec::es256());

        use p256::ecdsa::signature::Signer;
        let signing_key = keypair.p256_signing_key();
        let msg = b"rustcrypto-to-ring ECDSA P-256 cross-adapter expanded";
        let sig: p256::ecdsa::DerSignature = signing_key.sign(msg);

        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key =
            ring_sig::UnparsedPublicKey::new(&ring_sig::ECDSA_P256_SHA256_ASN1, raw_pubkey);
        public_key
            .verify(msg, sig.as_bytes())
            .expect("ring should verify rustcrypto-signed ECDSA P-256 signature");
    }

    // Ed25519: ring sign → rustcrypto verify
    #[test]
    fn ed25519_ring_sign_rustcrypto_verify() {
        let fx = fx();
        let keypair = fx.ed25519("xadapt-ed25519-r2rc", Ed25519Spec::new());

        let ring_kp = keypair.ed25519_key_pair_ring();
        let msg = b"ring-to-rustcrypto Ed25519 cross-adapter expanded";
        let sig = ring_kp.sign(msg);

        use ed25519_dalek::Verifier;
        let verifying_key = keypair.ed25519_verifying_key();
        let dalek_sig =
            ed25519_dalek::Signature::from_slice(sig.as_ref()).expect("valid 64-byte signature");
        verifying_key
            .verify(msg, &dalek_sig)
            .expect("rustcrypto should verify ring-signed Ed25519 signature");
    }

    // Ed25519: rustcrypto sign → ring verify
    #[test]
    fn ed25519_rustcrypto_sign_ring_verify() {
        let fx = fx();
        let keypair = fx.ed25519("xadapt-ed25519-rc2r", Ed25519Spec::new());

        use ed25519_dalek::Signer;
        let signing_key = keypair.ed25519_signing_key();
        let msg = b"rustcrypto-to-ring Ed25519 cross-adapter expanded";
        let sig = signing_key.sign(msg);

        let raw_pubkey = extract_public_key_from_spki(keypair.public_key_spki_der());
        let public_key = ring_sig::UnparsedPublicKey::new(&ring_sig::ED25519, raw_pubkey);
        public_key
            .verify(msg, sig.to_bytes().as_ref())
            .expect("ring should verify rustcrypto-signed Ed25519 signature");
    }
}

// =========================================================================
// 2. TLS cross-adapter: X.509 → rustls
// =========================================================================

#[cfg(feature = "cross-tls")]
mod tls_cross_adapter {
    use super::*;
    use std::sync::Arc;
    use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};
    use uselesskey_x509::{ChainSpec, X509FactoryExt};

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
    fn x509_chain_tls_handshake_ring_provider() {
        let fx = fx();
        let chain = fx.x509_chain("xadapt-tls-ring", ChainSpec::new("ring-cross.example.com"));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

        let server_name = "ring-cross.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();

        complete_handshake(&mut client, &mut server);
    }

    #[test]
    fn x509_chain_server_client_data_exchange() {
        use std::io::{Read, Write};

        let fx = fx();
        let chain = fx.x509_chain(
            "xadapt-tls-data",
            ChainSpec::new("data-exchange.example.com"),
        );

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

        let server_name = "data-exchange.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();

        complete_handshake(&mut client, &mut server);

        // Send data from client → server
        let payload = b"cross-adapter TLS data exchange test";
        client.writer().write_all(payload).unwrap();

        let mut buf = Vec::new();
        client.write_tls(&mut buf).unwrap();
        server.read_tls(&mut &buf[..]).unwrap();
        server.process_new_packets().unwrap();

        let mut received = vec![0u8; payload.len()];
        server.reader().read_exact(&mut received).unwrap();
        assert_eq!(&received, payload);
    }

    #[cfg(all(feature = "aws-lc-rs-interop", any(not(windows), has_nasm)))]
    #[test]
    fn x509_chain_tls_handshake_aws_provider() {
        let fx = fx();
        let chain = fx.x509_chain("xadapt-tls-aws", ChainSpec::new("aws-cross.example.com"));

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

        let server_name = "aws-cross.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();

        complete_handshake(&mut client, &mut server);
    }
}

// =========================================================================
// 3. JWK round-trip: generate key → export JWK → sign/verify JWT
// =========================================================================

#[cfg(feature = "jwt-interop")]
mod jwk_round_trip {
    use super::*;
    use uselesskey_jsonwebtoken::JwtKeyExt;

    #[test]
    fn rsa_jwt_sign_verify_round_trip() {
        use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

        let fx = fx();
        let keypair = fx.rsa("xadapt-jwt-rsa", RsaSpec::rs256());

        // Verify JWK export is valid JSON with expected fields
        let public_jwk = keypair.public_jwk_json();
        assert_eq!(public_jwk["kty"], "RSA");
        assert!(public_jwk["n"].is_string());
        assert!(public_jwk["e"].is_string());

        // Sign a JWT with encoding key from the same factory-produced keypair
        let claims = serde_json::json!({
            "sub": "interop-test",
            "iss": "uselesskey",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let token =
            jsonwebtoken::encode(&header, &claims, &keypair.encoding_key()).expect("JWT encode");

        // Verify with decoding key from the same keypair
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&["uselesskey"]);
        let decoded =
            jsonwebtoken::decode::<serde_json::Value>(&token, &keypair.decoding_key(), &validation)
                .expect("JWT decode");
        assert_eq!(decoded.claims["sub"], "interop-test");
    }

    #[test]
    fn ecdsa_jwt_sign_verify_round_trip() {
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

        let fx = fx();
        let keypair = fx.ecdsa("xadapt-jwt-ecdsa", EcdsaSpec::es256());

        let public_jwk = keypair.public_jwk_json();
        assert_eq!(public_jwk["kty"], "EC");
        assert_eq!(public_jwk["crv"], "P-256");

        let claims = serde_json::json!({
            "sub": "ecdsa-interop",
            "iss": "uselesskey",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        let token =
            jsonwebtoken::encode(&header, &claims, &keypair.encoding_key()).expect("JWT encode");

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&["uselesskey"]);
        let decoded =
            jsonwebtoken::decode::<serde_json::Value>(&token, &keypair.decoding_key(), &validation)
                .expect("JWT decode");
        assert_eq!(decoded.claims["sub"], "ecdsa-interop");
    }

    #[test]
    fn ed25519_jwt_sign_verify_round_trip() {
        use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

        let fx = fx();
        let keypair = fx.ed25519("xadapt-jwt-ed25519", Ed25519Spec::new());

        let public_jwk = keypair.public_jwk_json();
        assert_eq!(public_jwk["kty"], "OKP");
        assert_eq!(public_jwk["crv"], "Ed25519");

        let claims = serde_json::json!({
            "sub": "ed25519-interop",
            "iss": "uselesskey",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        let token =
            jsonwebtoken::encode(&header, &claims, &keypair.encoding_key()).expect("JWT encode");

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_issuer(&["uselesskey"]);
        let decoded =
            jsonwebtoken::decode::<serde_json::Value>(&token, &keypair.decoding_key(), &validation)
                .expect("JWT decode");
        assert_eq!(decoded.claims["sub"], "ed25519-interop");
    }
}

// =========================================================================
// 4. Determinism: same seed → same key material across adapters
// =========================================================================

#[cfg(feature = "cross-signing")]
mod determinism_cross_adapter {
    use uselesskey_core::{Factory, Seed};
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    fn make_factory() -> Factory {
        let seed = Seed::from_env_value("uselesskey-determinism-check-v1")
            .expect("test seed should always parse");
        Factory::deterministic(seed)
    }

    #[test]
    fn rsa_same_seed_same_pkcs8_der() {
        let fx1 = make_factory();
        let fx2 = make_factory();

        let kp1 = fx1.rsa("det-rsa", RsaSpec::rs256());
        let kp2 = fx2.rsa("det-rsa", RsaSpec::rs256());

        assert_eq!(
            kp1.private_key_pkcs8_der(),
            kp2.private_key_pkcs8_der(),
            "same seed must produce identical RSA PKCS#8 DER"
        );
        assert_eq!(
            kp1.public_key_spki_der(),
            kp2.public_key_spki_der(),
            "same seed must produce identical RSA SPKI DER"
        );
    }

    #[test]
    fn ecdsa_same_seed_same_pkcs8_der() {
        let fx1 = make_factory();
        let fx2 = make_factory();

        let kp1 = fx1.ecdsa("det-ecdsa", EcdsaSpec::es256());
        let kp2 = fx2.ecdsa("det-ecdsa", EcdsaSpec::es256());

        assert_eq!(
            kp1.private_key_pkcs8_der(),
            kp2.private_key_pkcs8_der(),
            "same seed must produce identical ECDSA PKCS#8 DER"
        );
        assert_eq!(
            kp1.public_key_spki_der(),
            kp2.public_key_spki_der(),
            "same seed must produce identical ECDSA SPKI DER"
        );
    }

    #[test]
    fn ed25519_same_seed_same_pkcs8_der() {
        let fx1 = make_factory();
        let fx2 = make_factory();

        let kp1 = fx1.ed25519("det-ed25519", Ed25519Spec::new());
        let kp2 = fx2.ed25519("det-ed25519", Ed25519Spec::new());

        assert_eq!(
            kp1.private_key_pkcs8_der(),
            kp2.private_key_pkcs8_der(),
            "same seed must produce identical Ed25519 PKCS#8 DER"
        );
        assert_eq!(
            kp1.public_key_spki_der(),
            kp2.public_key_spki_der(),
            "same seed must produce identical Ed25519 SPKI DER"
        );
    }

    #[test]
    fn different_labels_different_keys() {
        let fx = make_factory();

        let kp_a = fx.rsa("det-rsa-alpha", RsaSpec::rs256());
        let kp_b = fx.rsa("det-rsa-beta", RsaSpec::rs256());

        assert_ne!(
            kp_a.private_key_pkcs8_der(),
            kp_b.private_key_pkcs8_der(),
            "different labels must produce different RSA keys"
        );
    }

    #[cfg(all(feature = "aws-lc-rs-interop", any(not(windows), has_nasm)))]
    #[test]
    fn rsa_ring_and_aws_extract_same_modulus() {
        use uselesskey_aws_lc_rs::AwsLcRsRsaKeyPairExt;
        use uselesskey_ring::RingRsaKeyPairExt;

        let fx = make_factory();
        let keypair = fx.rsa("det-rsa-mod", RsaSpec::rs256());

        let ring_kp = keypair.rsa_key_pair_ring();
        let aws_kp = keypair.rsa_key_pair_aws_lc_rs();

        assert_eq!(
            ring_kp.public().modulus_len(),
            aws_kp.public_modulus_len(),
            "ring and aws-lc-rs must report the same RSA modulus length"
        );
    }
}
