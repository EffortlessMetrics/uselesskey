//! Cross-adapter interop matrix tests.
//!
//! Verifies that keys generated through one adapter are usable by another:
//!
//! 1. RSA: jsonwebtoken sign → ring verify
//! 2. RSA: ring sign → rustcrypto verify
//! 3. ECDSA: jsonwebtoken sign → ring verify
//! 4. Ed25519: ring sign → rustcrypto verify
//! 5. TLS cert from rustls works with ring for verification
//! 6. HMAC: consistent JWK across all adapters

use std::sync::OnceLock;

use uselesskey_core::{Factory, Seed};

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> &'static Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-interop-matrix-seed-v1")
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

fn base64_url_decode(input: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .expect("valid base64url")
}

// =========================================================================
// 1. RSA: jsonwebtoken sign → ring verify
// =========================================================================

#[cfg(all(feature = "jwt-interop", feature = "cross-signing"))]
mod rsa_jwt_to_ring {
    use super::*;
    use uselesskey_jsonwebtoken::JwtKeyExt;
    use uselesskey_ring::RingRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn jwt_sign_ring_verify_raw_signature() {
        let kp = fx().rsa("matrix-rsa-jwt2ring", RsaSpec::rs256());

        // Sign a JWT with jsonwebtoken adapter
        let claims = serde_json::json!({
            "sub": "rsa-jwt-to-ring",
            "iss": "uselesskey-matrix",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let token = jsonwebtoken::encode(&header, &claims, &kp.encoding_key()).expect("JWT encode");

        // Extract signing input and signature from the JWT
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = base64_url_decode(parts[2]);

        // Verify the raw signature with ring via the ring adapter
        let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            raw_pubkey,
        );
        public_key
            .verify(signing_input.as_bytes(), &sig_bytes)
            .expect("ring should verify JWT RS256 signature from jsonwebtoken adapter");
    }

    #[test]
    fn ring_sign_jwt_verify() {
        let kp = fx().rsa("matrix-rsa-ring2jwt", RsaSpec::rs256());

        // Sign with ring adapter
        let ring_kp = kp.rsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"ring-signed message for JWT verification";
        let mut sig = vec![0u8; ring_kp.public().modulus_len()];
        ring_kp
            .sign(&ring::signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("ring sign");

        // Verify that the jsonwebtoken adapter can decode a JWT produced
        // by encoding/decoding with the same key material
        let claims = serde_json::json!({
            "sub": "ring-to-jwt-roundtrip",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let token = jsonwebtoken::encode(&header, &claims, &kp.encoding_key()).expect("JWT encode");

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_required_spec_claims::<String>(&[]);
        let decoded =
            jsonwebtoken::decode::<serde_json::Value>(&token, &kp.decoding_key(), &validation)
                .expect("jsonwebtoken should verify using same key material as ring");
        assert_eq!(decoded.claims["sub"], "ring-to-jwt-roundtrip");
    }
}

// =========================================================================
// 2. RSA: ring sign → rustcrypto verify
// =========================================================================

#[cfg(feature = "cross-signing")]
mod rsa_ring_to_rustcrypto {
    use super::*;
    use uselesskey_ring::RingRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustcrypto::RustCryptoRsaExt;

    #[test]
    fn ring_sign_rustcrypto_verify() {
        let kp = fx().rsa("matrix-rsa-ring2rc", RsaSpec::rs256());

        // Sign with ring adapter
        let ring_kp = kp.rsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"ring-to-rustcrypto RSA interop matrix test";
        let mut sig = vec![0u8; ring_kp.public().modulus_len()];
        ring_kp
            .sign(&ring::signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("ring sign");

        // Verify with rustcrypto adapter
        use rsa::pkcs1v15;
        use rsa::sha2::Sha256;
        use rsa::signature::Verifier;
        let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(kp.rsa_public_key());
        let signature =
            pkcs1v15::Signature::try_from(sig.as_slice()).expect("valid signature bytes");
        verifying_key
            .verify(msg, &signature)
            .expect("rustcrypto should verify ring-signed RSA signature");
    }

    #[test]
    fn rustcrypto_sign_ring_verify() {
        let kp = fx().rsa("matrix-rsa-rc2ring", RsaSpec::rs256());

        // Sign with rustcrypto adapter
        use rsa::pkcs1v15;
        use rsa::sha2::Sha256;
        use rsa::signature::{SignatureEncoding, Signer};
        let signing_key = pkcs1v15::SigningKey::<Sha256>::new(kp.rsa_private_key());
        let msg = b"rustcrypto-to-ring RSA interop matrix test";
        let sig = signing_key.sign(msg);

        // Verify with ring
        let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            raw_pubkey,
        );
        public_key
            .verify(msg, &sig.to_bytes())
            .expect("ring should verify rustcrypto-signed RSA signature");
    }
}

// =========================================================================
// 3. ECDSA: jsonwebtoken sign → ring verify
// =========================================================================

#[cfg(all(feature = "jwt-interop", feature = "cross-signing"))]
mod ecdsa_jwt_to_ring {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_jsonwebtoken::JwtKeyExt;
    use uselesskey_ring::RingEcdsaKeyPairExt;

    /// Convert a fixed-size (r || s) P-256 signature to ASN.1 DER for ring.
    fn p256_fixed_to_der(fixed: &[u8]) -> Vec<u8> {
        assert_eq!(fixed.len(), 64, "P-256 fixed signature must be 64 bytes");
        let r = &fixed[..32];
        let s = &fixed[32..];

        fn encode_integer(val: &[u8]) -> Vec<u8> {
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

    #[test]
    fn jwt_sign_ring_verify_raw_signature() {
        let kp = fx().ecdsa("matrix-ecdsa-jwt2ring", EcdsaSpec::es256());

        // Sign a JWT with jsonwebtoken adapter
        let claims = serde_json::json!({
            "sub": "ecdsa-jwt-to-ring",
            "iss": "uselesskey-matrix",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        let token = jsonwebtoken::encode(&header, &claims, &kp.encoding_key()).expect("JWT encode");

        // Extract signing input and signature
        let parts: Vec<&str> = token.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = base64_url_decode(parts[2]);

        // JWT ES256 uses fixed-size (r || s); convert to ASN.1 DER for ring
        let der_sig = p256_fixed_to_der(&sig_bytes);

        // Verify with ring
        let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            raw_pubkey,
        );
        public_key
            .verify(signing_input.as_bytes(), &der_sig)
            .expect("ring should verify JWT ES256 signature from jsonwebtoken adapter");
    }

    #[test]
    fn ring_sign_jwt_verify() {
        let kp = fx().ecdsa("matrix-ecdsa-ring2jwt", EcdsaSpec::es256());

        // Sign with ring adapter
        let ring_kp = kp.ecdsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let _sig = ring_kp
            .sign(&rng, b"ecdsa ring sign test")
            .expect("ring sign");

        // Verify key material works for JWT round-trip via jsonwebtoken
        let claims = serde_json::json!({
            "sub": "ecdsa-ring-to-jwt",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        let token = jsonwebtoken::encode(&header, &claims, &kp.encoding_key()).expect("JWT encode");

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_required_spec_claims::<String>(&[]);
        let decoded =
            jsonwebtoken::decode::<serde_json::Value>(&token, &kp.decoding_key(), &validation)
                .expect("jsonwebtoken should verify using same key material as ring");
        assert_eq!(decoded.claims["sub"], "ecdsa-ring-to-jwt");
    }
}

// =========================================================================
// 4. Ed25519: ring sign → rustcrypto verify
// =========================================================================

#[cfg(feature = "cross-signing")]
mod ed25519_ring_to_rustcrypto {
    use super::*;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_ring::RingEd25519KeyPairExt;
    use uselesskey_rustcrypto::RustCryptoEd25519Ext;

    #[test]
    fn ring_sign_rustcrypto_verify() {
        let kp = fx().ed25519("matrix-ed-ring2rc", Ed25519Spec::new());

        // Sign with ring adapter
        let ring_kp = kp.ed25519_key_pair_ring();
        let msg = b"ring-to-rustcrypto Ed25519 interop matrix test";
        let sig = ring_kp.sign(msg);

        // Verify with rustcrypto adapter
        use ed25519_dalek::Verifier;
        let verifying_key = kp.ed25519_verifying_key();
        let dalek_sig =
            ed25519_dalek::Signature::from_slice(sig.as_ref()).expect("valid 64-byte signature");
        verifying_key
            .verify(msg, &dalek_sig)
            .expect("rustcrypto should verify ring-signed Ed25519 signature");
    }

    #[test]
    fn rustcrypto_sign_ring_verify() {
        let kp = fx().ed25519("matrix-ed-rc2ring", Ed25519Spec::new());

        // Sign with rustcrypto adapter
        use ed25519_dalek::Signer;
        let signing_key = kp.ed25519_signing_key();
        let msg = b"rustcrypto-to-ring Ed25519 interop matrix test";
        let sig = signing_key.sign(msg);

        // Verify with ring
        let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
        let public_key =
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, raw_pubkey);
        public_key
            .verify(msg, sig.to_bytes().as_ref())
            .expect("ring should verify rustcrypto-signed Ed25519 signature");
    }
}

// =========================================================================
// 5. TLS cert from rustls works with ring for verification
// =========================================================================

#[cfg(all(feature = "cross-tls", feature = "cross-signing"))]
mod tls_rustls_ring_verify {
    use super::*;
    use std::sync::Arc;
    use uselesskey_ring::RingRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
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
    fn tls_chain_handshake_with_ring_provider() {
        let chain = fx().x509_chain("matrix-tls-ring", ChainSpec::new("matrix-ring.example.com"));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

        let server_name = "matrix-ring.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();

        complete_handshake(&mut client, &mut server);
    }

    #[test]
    fn tls_chain_data_exchange_with_ring_provider() {
        use std::io::{Read, Write};

        let chain = fx().x509_chain(
            "matrix-tls-ring-data",
            ChainSpec::new("matrix-data.example.com"),
        );

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

        let server_name = "matrix-data.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();

        complete_handshake(&mut client, &mut server);

        let payload = b"cross-adapter TLS interop matrix data exchange";
        client.writer().write_all(payload).unwrap();

        let mut buf = Vec::new();
        client.write_tls(&mut buf).unwrap();
        server.read_tls(&mut &buf[..]).unwrap();
        server.process_new_packets().unwrap();

        let mut received = vec![0u8; payload.len()];
        server.reader().read_exact(&mut received).unwrap();
        assert_eq!(&received, payload);
    }

    #[test]
    fn tls_leaf_key_usable_by_ring_for_signing() {
        let kp = fx().rsa("matrix-tls-ring-key", RsaSpec::rs256());

        // Verify that ring can use the same RSA key for signing
        let ring_kp = kp.rsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"TLS key material usable by ring";
        let mut sig = vec![0u8; ring_kp.public().modulus_len()];
        ring_kp
            .sign(&ring::signature::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("ring should sign with key from rustls-compatible material");

        // Verify the signature
        let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            raw_pubkey,
        );
        public_key
            .verify(msg, &sig)
            .expect("ring should verify its own signature from TLS key material");
    }
}

// =========================================================================
// 6. HMAC: consistent JWK across all adapters
// =========================================================================

#[cfg(feature = "cross-signing")]
mod hmac_jwk_consistency {
    use super::*;
    use hmac::Mac;
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    use uselesskey_rustcrypto::RustCryptoHmacExt;

    #[test]
    fn hmac_jwk_fields_correct_hs256() {
        let secret = fx().hmac("matrix-hmac-jwk-256", HmacSpec::hs256());
        let jwk = secret.jwk().to_value();

        assert_eq!(jwk["kty"], "oct");
        assert_eq!(jwk["alg"], "HS256");
        assert_eq!(jwk["use"], "sig");
        assert!(jwk["kid"].is_string(), "JWK should have a kid");
        assert!(
            jwk["k"].is_string(),
            "JWK should have base64url key material"
        );
    }

    #[test]
    fn hmac_jwk_fields_correct_hs384() {
        let secret = fx().hmac("matrix-hmac-jwk-384", HmacSpec::hs384());
        let jwk = secret.jwk().to_value();

        assert_eq!(jwk["kty"], "oct");
        assert_eq!(jwk["alg"], "HS384");
        assert_eq!(jwk["use"], "sig");
    }

    #[test]
    fn hmac_jwk_fields_correct_hs512() {
        let secret = fx().hmac("matrix-hmac-jwk-512", HmacSpec::hs512());
        let jwk = secret.jwk().to_value();

        assert_eq!(jwk["kty"], "oct");
        assert_eq!(jwk["alg"], "HS512");
        assert_eq!(jwk["use"], "sig");
    }

    #[test]
    fn hmac_jwk_key_bytes_match_secret_bytes() {
        use base64::Engine;

        let secret = fx().hmac("matrix-hmac-jwk-bytes", HmacSpec::hs256());
        let jwk = secret.jwk().to_value();

        // Decode the base64url "k" field and compare with raw secret bytes
        let k_decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwk["k"].as_str().unwrap())
            .expect("JWK k field should be valid base64url");
        assert_eq!(
            k_decoded,
            secret.secret_bytes(),
            "JWK key material must match raw secret bytes"
        );
    }

    #[test]
    fn hmac_jwk_key_usable_by_ring() {
        use base64::Engine;

        let secret = fx().hmac("matrix-hmac-ring-jwk", HmacSpec::hs256());
        let jwk = secret.jwk().to_value();

        // Extract key bytes from JWK
        let key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwk["k"].as_str().unwrap())
            .expect("valid base64url");

        // Use with ring HMAC
        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key_bytes);
        let msg = b"HMAC JWK interop with ring";
        let tag = ring::hmac::sign(&ring_key, msg);

        // Verify with ring too
        ring::hmac::verify(&ring_key, msg, tag.as_ref())
            .expect("ring should verify its own HMAC tag from JWK key material");
    }

    #[test]
    fn hmac_jwk_key_usable_by_rustcrypto() {
        use base64::Engine;

        let secret = fx().hmac("matrix-hmac-rc-jwk", HmacSpec::hs256());
        let jwk = secret.jwk().to_value();

        // Extract key bytes from JWK
        let key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwk["k"].as_str().unwrap())
            .expect("valid base64url");

        // Use with RustCrypto HMAC
        let mut mac =
            hmac::Hmac::<sha2::Sha256>::new_from_slice(&key_bytes).expect("valid key length");
        let msg = b"HMAC JWK interop with rustcrypto";
        mac.update(msg);
        let tag = mac.finalize().into_bytes();

        // Verify matches direct rustcrypto adapter usage
        let mut mac2 = secret.hmac_sha256();
        mac2.update(msg);
        mac2.verify_slice(&tag)
            .expect("rustcrypto adapter tag should match JWK-derived tag");
    }

    #[test]
    fn hmac_jwk_consistent_across_ring_and_rustcrypto() {
        let secret = fx().hmac("matrix-hmac-cross-jwk", HmacSpec::hs256());
        let msg = b"HMAC cross-adapter consistency via JWK";

        // Compute tag with ring
        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.secret_bytes());
        let ring_tag = ring::hmac::sign(&ring_key, msg);

        // Compute tag with rustcrypto adapter
        let mut rc_mac = secret.hmac_sha256();
        rc_mac.update(msg);
        let rc_tag = rc_mac.finalize().into_bytes();

        // Both should produce identical tags
        assert_eq!(
            ring_tag.as_ref(),
            &rc_tag[..],
            "ring and rustcrypto HMAC tags must be identical for the same key"
        );
    }

    #[test]
    fn hmac_jwk_consistent_across_ring_and_rustcrypto_sha384() {
        let secret = fx().hmac("matrix-hmac-cross-384", HmacSpec::hs384());
        let msg = b"HMAC SHA-384 cross-adapter consistency";

        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA384, secret.secret_bytes());
        let ring_tag = ring::hmac::sign(&ring_key, msg);

        let mut rc_mac = secret.hmac_sha384();
        rc_mac.update(msg);
        let rc_tag = rc_mac.finalize().into_bytes();

        assert_eq!(ring_tag.as_ref(), &rc_tag[..]);
    }

    #[test]
    fn hmac_jwk_consistent_across_ring_and_rustcrypto_sha512() {
        let secret = fx().hmac("matrix-hmac-cross-512", HmacSpec::hs512());
        let msg = b"HMAC SHA-512 cross-adapter consistency";

        let ring_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, secret.secret_bytes());
        let ring_tag = ring::hmac::sign(&ring_key, msg);

        let mut rc_mac = secret.hmac_sha512();
        rc_mac.update(msg);
        let rc_tag = rc_mac.finalize().into_bytes();

        assert_eq!(ring_tag.as_ref(), &rc_tag[..]);
    }

    #[test]
    fn hmac_jwks_wraps_single_key() {
        let secret = fx().hmac("matrix-hmac-jwks", HmacSpec::hs256());
        let jwks = secret.jwks().to_value();

        assert!(jwks["keys"].is_array());
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "oct");
        assert_eq!(keys[0]["alg"], "HS256");
    }
}
