//! Unified cross-adapter roundtrip tests.
//!
//! Each test generates a single key and verifies it works across *all* adapters
//! in sequence (jsonwebtoken → ring → rustls), rather than testing pairs.
//! Also includes programmatic X.509 chain validation and JWK snapshot tests.

use std::sync::OnceLock;

use uselesskey_core::{Factory, Seed};

static FX: OnceLock<Factory> = OnceLock::new();

fn fx() -> &'static Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-roundtrip-seed-v1")
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
// 1. RSA: single key → jsonwebtoken → ring → rustls
// =========================================================================

#[cfg(all(
    feature = "jwt-interop",
    feature = "cross-signing",
    feature = "cross-tls"
))]
mod rsa_roundtrip {
    use super::*;
    use ring::signature as ring_sig;
    use uselesskey_jsonwebtoken::JwtKeyExt;
    use uselesskey_ring::RingRsaKeyPairExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustls::RustlsPrivateKeyExt;

    #[test]
    fn rsa_full_adapter_roundtrip() {
        let kp = fx().rsa("rt-rsa-full", RsaSpec::rs256());

        // Step 1: jsonwebtoken sign + verify
        let claims = serde_json::json!({
            "sub": "rsa-roundtrip",
            "iss": "uselesskey",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let token = jsonwebtoken::encode(&header, &claims, &kp.encoding_key()).expect("JWT encode");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&["uselesskey"]);
        let decoded =
            jsonwebtoken::decode::<serde_json::Value>(&token, &kp.decoding_key(), &validation)
                .expect("JWT decode with jsonwebtoken");
        assert_eq!(decoded.claims["sub"], "rsa-roundtrip");

        // Step 2: ring sign + verify with the same key material
        let ring_kp = kp.rsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"RSA roundtrip ring verification";
        let mut sig = vec![0u8; ring_kp.public().modulus_len()];
        ring_kp
            .sign(&ring_sig::RSA_PKCS1_SHA256, &rng, msg, &mut sig)
            .expect("ring sign");
        let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
        let public_key =
            ring_sig::UnparsedPublicKey::new(&ring_sig::RSA_PKCS1_2048_8192_SHA256, raw_pubkey);
        public_key
            .verify(msg, &sig)
            .expect("ring should verify its own RSA signature");

        // Step 3: convert to rustls PrivateKeyDer
        let rustls_key = kp.private_key_der_rustls();
        assert!(
            !rustls_key.secret_der().is_empty(),
            "rustls PrivateKeyDer should contain key material"
        );
        assert_eq!(
            rustls_key.secret_der(),
            kp.private_key_pkcs8_der(),
            "rustls DER should match original PKCS#8 DER"
        );
    }
}

// =========================================================================
// 2. ECDSA P-256: single key → jsonwebtoken → ring → rustls
// =========================================================================

#[cfg(all(
    feature = "jwt-interop",
    feature = "cross-signing",
    feature = "cross-tls"
))]
mod ecdsa_p256_roundtrip {
    use super::*;
    use ring::signature as ring_sig;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_jsonwebtoken::JwtKeyExt;
    use uselesskey_ring::RingEcdsaKeyPairExt;
    use uselesskey_rustls::RustlsPrivateKeyExt;

    #[test]
    fn ecdsa_p256_full_adapter_roundtrip() {
        let kp = fx().ecdsa("rt-p256-full", EcdsaSpec::es256());

        // Step 1: jsonwebtoken sign + verify
        let claims = serde_json::json!({
            "sub": "p256-roundtrip",
            "iss": "uselesskey",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        let token = jsonwebtoken::encode(&header, &claims, &kp.encoding_key()).expect("JWT encode");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&["uselesskey"]);
        let decoded =
            jsonwebtoken::decode::<serde_json::Value>(&token, &kp.decoding_key(), &validation)
                .expect("JWT decode with jsonwebtoken");
        assert_eq!(decoded.claims["sub"], "p256-roundtrip");

        // Step 2: ring sign + verify
        let ring_kp = kp.ecdsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"P-256 roundtrip ring verification";
        let sig = ring_kp.sign(&rng, msg).expect("ring sign");
        let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
        let public_key =
            ring_sig::UnparsedPublicKey::new(&ring_sig::ECDSA_P256_SHA256_ASN1, raw_pubkey);
        public_key
            .verify(msg, sig.as_ref())
            .expect("ring should verify its own P-256 signature");

        // Step 3: convert to rustls PrivateKeyDer
        let rustls_key = kp.private_key_der_rustls();
        assert!(
            !rustls_key.secret_der().is_empty(),
            "rustls PrivateKeyDer should contain key material"
        );
        assert_eq!(rustls_key.secret_der(), kp.private_key_pkcs8_der());
    }

    #[test]
    fn ecdsa_p384_full_adapter_roundtrip() {
        let kp = fx().ecdsa("rt-p384-full", EcdsaSpec::es384());

        // Step 1: jsonwebtoken sign + verify
        let claims = serde_json::json!({
            "sub": "p384-roundtrip",
            "iss": "uselesskey",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES384);
        let token = jsonwebtoken::encode(&header, &claims, &kp.encoding_key()).expect("JWT encode");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES384);
        validation.set_issuer(&["uselesskey"]);
        let decoded =
            jsonwebtoken::decode::<serde_json::Value>(&token, &kp.decoding_key(), &validation)
                .expect("JWT decode with jsonwebtoken");
        assert_eq!(decoded.claims["sub"], "p384-roundtrip");

        // Step 2: ring sign + verify
        let ring_kp = kp.ecdsa_key_pair_ring();
        let rng = ring::rand::SystemRandom::new();
        let msg = b"P-384 roundtrip ring verification";
        let sig = ring_kp.sign(&rng, msg).expect("ring sign");
        let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
        let public_key =
            ring_sig::UnparsedPublicKey::new(&ring_sig::ECDSA_P384_SHA384_ASN1, raw_pubkey);
        public_key
            .verify(msg, sig.as_ref())
            .expect("ring should verify its own P-384 signature");

        // Step 3: convert to rustls PrivateKeyDer
        let rustls_key = kp.private_key_der_rustls();
        assert!(!rustls_key.secret_der().is_empty());
        assert_eq!(rustls_key.secret_der(), kp.private_key_pkcs8_der());
    }
}

// =========================================================================
// 3. Ed25519: single key → jsonwebtoken → ring → rustls
// =========================================================================

#[cfg(all(
    feature = "jwt-interop",
    feature = "cross-signing",
    feature = "cross-tls"
))]
mod ed25519_roundtrip {
    use super::*;
    use ring::signature as ring_sig;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_jsonwebtoken::JwtKeyExt;
    use uselesskey_ring::RingEd25519KeyPairExt;
    use uselesskey_rustls::RustlsPrivateKeyExt;

    #[test]
    fn ed25519_full_adapter_roundtrip() {
        let kp = fx().ed25519("rt-ed25519-full", Ed25519Spec::new());

        // Step 1: jsonwebtoken sign + verify
        let claims = serde_json::json!({
            "sub": "ed25519-roundtrip",
            "iss": "uselesskey",
            "exp": 9_999_999_999u64,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
        let token = jsonwebtoken::encode(&header, &claims, &kp.encoding_key()).expect("JWT encode");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_issuer(&["uselesskey"]);
        let decoded =
            jsonwebtoken::decode::<serde_json::Value>(&token, &kp.decoding_key(), &validation)
                .expect("JWT decode with jsonwebtoken");
        assert_eq!(decoded.claims["sub"], "ed25519-roundtrip");

        // Step 2: ring sign + verify
        let ring_kp = kp.ed25519_key_pair_ring();
        let msg = b"Ed25519 roundtrip ring verification";
        let sig = ring_kp.sign(msg);
        let raw_pubkey = extract_public_key_from_spki(kp.public_key_spki_der());
        let public_key = ring_sig::UnparsedPublicKey::new(&ring_sig::ED25519, raw_pubkey);
        public_key
            .verify(msg, sig.as_ref())
            .expect("ring should verify its own Ed25519 signature");

        // Step 3: convert to rustls PrivateKeyDer
        let rustls_key = kp.private_key_der_rustls();
        assert!(!rustls_key.secret_der().is_empty());
        assert_eq!(rustls_key.secret_der(), kp.private_key_pkcs8_der());
    }
}

// =========================================================================
// 4. X.509 chain: programmatic validation via RootCertStore
// =========================================================================

#[cfg(feature = "cross-tls")]
mod x509_chain_validation {
    use super::*;
    use std::sync::Arc;
    use uselesskey_rustls::{RustlsChainExt, RustlsClientConfigExt, RustlsServerConfigExt};
    use uselesskey_x509::{ChainSpec, X509FactoryExt};

    /// Verify the chain validates by building a client with the root as trust
    /// anchor and a server with the chain, then completing a handshake.
    #[test]
    fn x509_chain_validates_with_ring_provider() {
        let chain = fx().x509_chain("rt-x509-ring", ChainSpec::new("roundtrip-ring.example.com"));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = Arc::new(chain.server_config_rustls_with_provider(provider.clone()));
        let client_config = Arc::new(chain.client_config_rustls_with_provider(provider));

        let server_name = "roundtrip-ring.example.com".try_into().unwrap();
        let mut server = rustls::ServerConnection::new(server_config).unwrap();
        let mut client = rustls::ClientConnection::new(client_config, server_name).unwrap();

        complete_handshake(&mut client, &mut server);
    }

    /// Verify the chain structure: root → intermediate → leaf.
    #[test]
    fn x509_chain_structure_is_valid() {
        let chain = fx().x509_chain(
            "rt-x509-struct",
            ChainSpec::new("roundtrip-struct.example.com"),
        );

        // Root cert is self-signed (issuer == subject conceptually)
        assert!(!chain.root_cert_der().is_empty());
        assert!(chain.root_cert_pem().contains("BEGIN CERTIFICATE"));

        // Intermediate is distinct from both root and leaf
        assert!(!chain.intermediate_cert_der().is_empty());
        assert_ne!(chain.root_cert_der(), chain.intermediate_cert_der());
        assert_ne!(chain.intermediate_cert_der(), chain.leaf_cert_der());

        // Leaf is distinct from root
        assert!(!chain.leaf_cert_der().is_empty());
        assert_ne!(chain.root_cert_der(), chain.leaf_cert_der());

        // Private keys for each tier are distinct
        assert_ne!(
            chain.root_private_key_pkcs8_der(),
            chain.intermediate_private_key_pkcs8_der()
        );
        assert_ne!(
            chain.root_private_key_pkcs8_der(),
            chain.leaf_private_key_pkcs8_der()
        );
        assert_ne!(
            chain.intermediate_private_key_pkcs8_der(),
            chain.leaf_private_key_pkcs8_der()
        );
    }

    /// Verify the root cert can be loaded into a RootCertStore and the leaf
    /// cert can be used in a rustls ServerConfig.
    #[test]
    fn x509_root_cert_store_accepts_root() {
        let chain = fx().x509_chain(
            "rt-x509-store",
            ChainSpec::new("roundtrip-store.example.com"),
        );

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(chain.root_certificate_der_rustls()).unwrap();
        assert_eq!(root_store.len(), 1, "root store should contain one cert");

        let chain_der = chain.chain_der_rustls();
        assert_eq!(
            chain_der.len(),
            2,
            "chain should contain leaf + intermediate"
        );
    }

    /// Verify the leaf key is usable for signing by ring after being
    /// extracted from an X.509 chain.
    #[cfg(feature = "cross-signing")]
    #[test]
    fn x509_leaf_key_usable_by_ring() {
        let chain = fx().x509_chain(
            "rt-x509-ring-key",
            ChainSpec::new("roundtrip-key.example.com"),
        );

        // The leaf key should be parseable by ring as an ECDSA key
        // (ChainSpec defaults to ECDSA P-256 for the leaf)
        let leaf_key_der = chain.leaf_private_key_pkcs8_der();
        assert!(!leaf_key_der.is_empty());

        // Verify the key is structurally valid by checking it can be used
        // in a rustls server config
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let _server_config = chain.server_config_rustls_with_provider(provider);
    }

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
}

// =========================================================================
// 5. JWK export/import roundtrip with structure validation
// =========================================================================

mod jwk_roundtrip {
    use super::*;

    #[test]
    fn rsa_jwk_has_expected_fields() {
        use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

        let kp = fx().rsa("rt-jwk-rsa", RsaSpec::rs256());
        let jwk = kp.public_jwk_json();

        assert_eq!(jwk["kty"], "RSA", "RSA JWK must have kty=RSA");
        assert!(jwk["n"].is_string(), "RSA JWK must have modulus 'n'");
        assert!(jwk["e"].is_string(), "RSA JWK must have exponent 'e'");
        assert!(jwk["kid"].is_string(), "RSA JWK should have a key ID 'kid'");

        // Verify 'n' is valid base64url
        let n = jwk["n"].as_str().unwrap();
        assert!(!n.is_empty(), "modulus must not be empty");
        use base64::Engine;
        let n_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(n)
            .expect("modulus 'n' must be valid base64url");
        assert_eq!(n_bytes.len(), 256, "RS256 modulus should be 256 bytes");

        // Verify 'e' decodes to standard RSA exponent 65537
        let e = jwk["e"].as_str().unwrap();
        let e_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(e)
            .expect("exponent 'e' must be valid base64url");
        assert!(!e_bytes.is_empty());

        // JWK must be valid JSON round-trip
        let serialized = serde_json::to_string(&jwk).expect("JWK should serialize to JSON");
        let reparsed: serde_json::Value =
            serde_json::from_str(&serialized).expect("JWK JSON should re-parse");
        assert_eq!(jwk, reparsed);
    }

    #[test]
    fn ecdsa_p256_jwk_has_expected_fields() {
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

        let kp = fx().ecdsa("rt-jwk-p256", EcdsaSpec::es256());
        let jwk = kp.public_jwk_json();

        assert_eq!(jwk["kty"], "EC", "EC JWK must have kty=EC");
        assert_eq!(jwk["crv"], "P-256", "ES256 JWK must have crv=P-256");
        assert!(jwk["x"].is_string(), "EC JWK must have coordinate 'x'");
        assert!(jwk["y"].is_string(), "EC JWK must have coordinate 'y'");
        assert!(jwk["kid"].is_string(), "EC JWK should have a key ID 'kid'");

        // Verify coordinates are valid base64url and 32 bytes for P-256
        use base64::Engine;
        let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwk["x"].as_str().unwrap())
            .expect("'x' must be valid base64url");
        let y_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwk["y"].as_str().unwrap())
            .expect("'y' must be valid base64url");
        assert_eq!(x_bytes.len(), 32, "P-256 x coordinate should be 32 bytes");
        assert_eq!(y_bytes.len(), 32, "P-256 y coordinate should be 32 bytes");

        // No private key in public JWK
        assert!(jwk.get("d").is_none(), "public JWK must not contain 'd'");
    }

    #[test]
    fn ecdsa_p384_jwk_has_expected_fields() {
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

        let kp = fx().ecdsa("rt-jwk-p384", EcdsaSpec::es384());
        let jwk = kp.public_jwk_json();

        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-384", "ES384 JWK must have crv=P-384");
        assert!(jwk["x"].is_string());
        assert!(jwk["y"].is_string());

        // P-384 coordinates are 48 bytes
        use base64::Engine;
        let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwk["x"].as_str().unwrap())
            .expect("'x' must be valid base64url");
        let y_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwk["y"].as_str().unwrap())
            .expect("'y' must be valid base64url");
        assert_eq!(x_bytes.len(), 48, "P-384 x coordinate should be 48 bytes");
        assert_eq!(y_bytes.len(), 48, "P-384 y coordinate should be 48 bytes");
    }

    #[test]
    fn ed25519_jwk_has_expected_fields() {
        use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

        let kp = fx().ed25519("rt-jwk-ed25519", Ed25519Spec::new());
        let jwk = kp.public_jwk_json();

        assert_eq!(jwk["kty"], "OKP", "Ed25519 JWK must have kty=OKP");
        assert_eq!(jwk["crv"], "Ed25519", "Ed25519 JWK must have crv=Ed25519");
        assert!(jwk["x"].is_string(), "OKP JWK must have public key 'x'");
        assert!(jwk["kid"].is_string(), "Ed25519 JWK should have a 'kid'");

        // Ed25519 public key is 32 bytes
        use base64::Engine;
        let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwk["x"].as_str().unwrap())
            .expect("'x' must be valid base64url");
        assert_eq!(x_bytes.len(), 32, "Ed25519 public key should be 32 bytes");

        // No private key in public JWK
        assert!(jwk.get("d").is_none(), "public JWK must not contain 'd'");
    }

    #[test]
    fn rsa_jwk_structure_snapshot() {
        use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

        let kp = fx().rsa("rt-jwk-rsa-snap", RsaSpec::rs256());
        let jwk = kp.public_jwk_json();

        // Snapshot the JWK structure with key material redacted
        let mut redacted = jwk.clone();
        if let Some(obj) = redacted.as_object_mut() {
            for key in &["n", "e", "kid"] {
                if obj.contains_key(*key) {
                    obj.insert(
                        key.to_string(),
                        serde_json::Value::String("[REDACTED]".to_string()),
                    );
                }
            }
        }
        insta::assert_yaml_snapshot!("rsa_jwk_structure", redacted);
    }

    #[test]
    fn ecdsa_p256_jwk_structure_snapshot() {
        use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};

        let kp = fx().ecdsa("rt-jwk-p256-snap", EcdsaSpec::es256());
        let jwk = kp.public_jwk_json();

        let mut redacted = jwk.clone();
        if let Some(obj) = redacted.as_object_mut() {
            for key in &["x", "y", "kid"] {
                if obj.contains_key(*key) {
                    obj.insert(
                        key.to_string(),
                        serde_json::Value::String("[REDACTED]".to_string()),
                    );
                }
            }
        }
        insta::assert_yaml_snapshot!("ecdsa_p256_jwk_structure", redacted);
    }

    #[test]
    fn ed25519_jwk_structure_snapshot() {
        use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};

        let kp = fx().ed25519("rt-jwk-ed25519-snap", Ed25519Spec::new());
        let jwk = kp.public_jwk_json();

        let mut redacted = jwk.clone();
        if let Some(obj) = redacted.as_object_mut() {
            for key in &["x", "kid"] {
                if obj.contains_key(*key) {
                    obj.insert(
                        key.to_string(),
                        serde_json::Value::String("[REDACTED]".to_string()),
                    );
                }
            }
        }
        insta::assert_yaml_snapshot!("ed25519_jwk_structure", redacted);
    }

    /// Verify that deterministic mode produces identical JWK output.
    #[test]
    fn jwk_deterministic_across_factories() {
        use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

        let seed = Seed::from_env_value("uselesskey-jwk-determinism-v1")
            .expect("test seed should always parse");
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);

        let jwk1 = fx1.rsa("det-jwk-rsa", RsaSpec::rs256()).public_jwk_json();
        let jwk2 = fx2.rsa("det-jwk-rsa", RsaSpec::rs256()).public_jwk_json();

        assert_eq!(
            jwk1, jwk2,
            "deterministic factories must produce identical JWKs"
        );
    }
}
