//! End-to-End Workflow Tests
//!
//! Tests complete workflows from key generation to usage:
//! - Test complete workflows from key generation to usage
//! - Test JWKS building and consumption
//! - Test certificate chain creation and validation
//! - Test negative fixture handling in real scenarios

mod testutil;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use testutil::fx;
use uselesskey_core::Factory;
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
use uselesskey_jsonwebtoken::JwtKeyExt;
use uselesskey_jwk::{AnyJwk, JwksBuilder};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
use uselesskey_rustls::{RustlsClientConfigExt, RustlsServerConfigExt};
use uselesskey_x509::{ChainSpec, X509FactoryExt};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct JwtClaims {
    sub: String,
    exp: usize,
    iat: usize,
    iss: String,
}

impl JwtClaims {
    fn new(sub: &str, exp: usize, iat: usize, iss: &str) -> Self {
        Self {
            sub: sub.to_string(),
            exp,
            iat,
            iss: iss.to_string(),
        }
    }
}

// =========================================================================
// Complete JWT Workflow Tests
// =========================================================================

#[cfg(feature = "e2e")]
mod jwt_workflow_tests {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn test_complete_jwt_workflow() {
        let fx = fx();

        // Step 1: Generate keypair
        let keypair = fx.rsa("jwt-workflow", RsaSpec::rs256());

        // Step 2: Extract public JWK for JWKS
        let public_jwk = keypair.public_jwk();
        assert!(!public_jwk.kid().is_empty());

        // Step 3: Build JWKS
        let jwks = JwksBuilder::new().add_public(public_jwk.into()).build();

        // Step 4: Sign JWT
        let claims = JwtClaims::new("user123", 9999999999, 1234567890, "jwt-workflow");
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(keypair.kid().to_string());

        let token =
            encode(&header, &claims, &keypair.encoding_key()).expect("Failed to encode JWT");

        // Step 5: Verify JWT using JWKS
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid() == keypair.kid())
            .expect("Key not found in JWKS");

        let jwk_value = serde_json::to_value(jwk).expect("Failed to serialize JWK");
        let jwk_json: jsonwebtoken::jwk::Jwk =
            serde_json::from_value(jwk_value).expect("Failed to deserialize JWK");
        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(&jwk_json)
            .expect("Failed to create DecodingKey from JWK");

        let validation = Validation::new(Algorithm::RS256);
        let decoded =
            decode::<JwtClaims>(&token, &decoding_key, &validation).expect("Failed to decode JWT");

        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn test_jwt_multi_issuer_workflow() {
        let fx = fx();

        // Step 1: Generate keys for multiple issuers
        let issuer1 = fx.rsa("issuer1", RsaSpec::rs256());
        let issuer2 = fx.rsa("issuer2", RsaSpec::rs256());
        let issuer3 = fx.rsa("issuer3", RsaSpec::rs256());

        // Step 2: Build JWKS with all issuers
        let jwks = JwksBuilder::new()
            .add_public(issuer1.public_jwk().into())
            .add_public(issuer2.public_jwk().into())
            .add_public(issuer3.public_jwk().into())
            .build();

        assert_eq!(jwks.keys.len(), 3);

        // Step 3: Sign JWTs from each issuer
        for (i, issuer) in [&issuer1, &issuer2, &issuer3].iter().enumerate() {
            let claims = JwtClaims::new(
                "user123",
                9999999999,
                1234567890,
                &format!("issuer{}", i + 1),
            );
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(issuer.kid().to_string());

            let token =
                encode(&header, &claims, &issuer.encoding_key()).expect("Failed to encode JWT");

            // Step 4: Verify each JWT with JWKS
            let jwk = jwks
                .keys
                .iter()
                .find(|k| k.kid() == issuer.kid())
                .expect("Key not found in JWKS");

            let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk)
                .expect("Failed to create DecodingKey from JWK");

            let validation = Validation::new(Algorithm::RS256);
            let decoded = decode::<JwtClaims>(&token, &decoding_key, &validation)
                .expect("Failed to decode JWT");

            assert_eq!(decoded.claims, claims);
        }
    }

    #[test]
    fn test_jwt_key_rotation_workflow() {
        let fx = fx();

        // Step 1: Generate old and new keys
        let old_key = fx.rsa("old-key", RsaSpec::rs256());
        let new_key = fx.rsa("new-key", RsaSpec::rs256());

        // Step 2: Build JWKS with both keys
        let jwks = JwksBuilder::new()
            .add_public(old_key.public_jwk().into())
            .add_public(new_key.public_jwk().into())
            .build();

        // Step 3: Sign JWT with new key
        let claims = JwtClaims::new("user123", 9999999999, 1234567890, "new-key");
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(new_key.kid().to_string());

        let token =
            encode(&header, &claims, &new_key.encoding_key()).expect("Failed to encode JWT");

        // Step 4: Verify with JWKS (should find new key)
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid() == new_key.kid())
            .expect("New key not found in JWKS");

        let jwk_value = serde_json::to_value(jwk).expect("Failed to serialize JWK");
        let jwk_json: jsonwebtoken::jwk::Jwk =
            serde_json::from_value(jwk_value).expect("Failed to deserialize JWK");
        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(&jwk_json)
            .expect("Failed to create DecodingKey from JWK");

        let validation = Validation::new(Algorithm::RS256);
        let decoded =
            decode::<JwtClaims>(&token, &decoding_key, &validation).expect("Failed to decode JWT");

        assert_eq!(decoded.claims, claims);

        // Step 5: Verify old key is still in JWKS for validating old tokens
        assert!(jwks.keys.iter().any(|k| k.kid() == old_key.kid()));
    }
}

// =========================================================================
// Complete TLS Workflow Tests
// =========================================================================

#[cfg(feature = "e2e")]
mod tls_workflow_tests {
    use super::*;

    #[test]
    fn test_complete_tls_workflow() {
        let fx = fx();

        // Step 1: Generate certificate chain
        let chain_spec = ChainSpec::new("test.example.com")
            .with_sans(vec!["localhost".to_string(), "127.0.0.1".to_string()]);
        let chain = fx.x509_chain("tls-workflow", chain_spec);

        // Step 2: Build server config
        let server_config = chain.server_config_rustls();
        assert_eq!(server_config.alpn_protocols.len(), 0);

        // Step 3: Build client config
        let client_config = chain.client_config_rustls();
        assert_eq!(client_config.alpn_protocols.len(), 0);

        // Step 4: Verify chain structure
        assert!(!chain.leaf_cert_pem().is_empty());
        assert!(!chain.intermediate_cert_pem().is_empty());
        assert!(!chain.root_cert_pem().is_empty());
        assert!(!chain.chain_pem().is_empty());

        // Step 5: Verify DER conversions
        let cert_chain = chain.chain_der_rustls();
        assert_eq!(cert_chain.len(), 2); // leaf + intermediate

        let root_cert = chain.root_certificate_der_rustls();
        assert!(!root_cert.as_ref().is_empty());

        let private_key = chain.private_key_der_rustls();
        assert!(!private_key.secret_bytes().is_empty());
    }

    #[test]
    fn test_mtls_workflow() {
        let fx = fx();

        // Step 1: Generate server chain
        let server_chain_spec = ChainSpec::new("server.example.com");
        let server_chain = fx.x509_chain("mtls-server", server_chain_spec);

        // Step 2: Generate client chain
        let client_chain_spec = ChainSpec::new("client.example.com");
        let client_chain = fx.x509_chain("mtls-client", client_chain_spec);

        // Step 3: Build mTLS server config
        let server_config = server_chain.server_config_mtls_rustls();
        assert_eq!(server_config.alpn_protocols.len(), 0);

        // Step 4: Build mTLS client config
        let client_config = client_chain.client_config_mtls_rustls();
        assert_eq!(client_config.alpn_protocols.len(), 0);

        // Step 5: Verify both chains have valid structure
        assert!(!server_chain.leaf_cert_pem().is_empty());
        assert!(!server_chain.root_cert_pem().is_empty());
        assert!(!client_chain.leaf_cert_pem().is_empty());
        assert!(!client_chain.root_cert_pem().is_empty());
    }

    #[test]
    fn test_tls_self_signed_workflow() {
        let fx = fx();

        // Step 1: Generate self-signed certificate
        let spec = uselesskey_x509::X509Spec::self_signed("localhost");
        let cert = fx.x509_self_signed("self-signed-workflow", spec);

        // Step 2: Build server config
        let server_config = cert.server_config_rustls();
        assert_eq!(server_config.alpn_protocols.len(), 0);

        // Step 3: Build client config
        let client_config = cert.client_config_rustls();
        assert_eq!(client_config.alpn_protocols.len(), 0);

        // Step 4: Verify certificate structure
        assert!(!cert.cert_pem().is_empty());
        assert!(!cert.private_key_pkcs8_pem().is_empty());
        assert!(!cert.identity_pem().is_empty());
    }
}

// =========================================================================
// JWKS Building and Consumption Tests
// =========================================================================

#[cfg(feature = "e2e")]
mod jwks_workflow_tests {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::Ed25519FactoryExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn test_jwks_building_workflow() {
        let fx = fx();

        // Step 1: Generate keys of different types
        let rsa_key = fx.rsa("jwks-rsa", RsaSpec::rs256());
        let ecdsa_key = fx.ecdsa("jwks-ecdsa", EcdsaSpec::Es256);
        let ed25519_key = fx.ed25519("jwks-ed25519", Ed25519Spec::new());

        // Step 2: Build JWKS with all keys
        let jwks = JwksBuilder::new()
            .add_public(rsa_key.public_jwk().into())
            .add_public(ecdsa_key.public_jwk().into())
            .add_public(ed25519_key.public_jwk().into())
            .build();

        // Step 3: Verify JWKS structure
        assert_eq!(jwks.keys.len(), 3);

        // Step 4: Verify each key is present
        let kids: Vec<&str> = jwks.keys.iter().map(|k| k.kid()).collect();
        assert!(kids.contains(&rsa_key.kid()));
        assert!(kids.contains(&ecdsa_key.kid()));
        assert!(kids.contains(&ed25519_key.kid()));

        // Step 5: Verify JWKS can be serialized
        let jwks_json = jwks.to_string();
        assert!(!jwks_json.is_empty());
        assert!(jwks_json.contains("\"keys\""));
    }

    #[test]
    fn test_jwks_key_lookup_workflow() {
        let fx = fx();

        // Step 1: Generate multiple keys
        let keys = vec![
            fx.rsa("key1", RsaSpec::rs256()),
            fx.rsa("key2", RsaSpec::rs256()),
            fx.rsa("key3", RsaSpec::rs256()),
        ];

        // Step 2: Build JWKS
        let mut builder = JwksBuilder::new();
        for key in &keys {
            builder = builder.add_public(key.public_jwk().into());
        }
        let jwks = builder.build();

        // Step 3: Lookup each key by kid
        for key in &keys {
            let jwk = jwks
                .keys
                .iter()
                .find(|k| k.kid() == key.kid())
                .expect("Key not found in JWKS");

            assert_eq!(jwk.kid(), key.kid());
        }
    }

    #[test]
    fn test_jwks_serialization_workflow() {
        let fx = fx();

        // Step 1: Generate keys
        let rsa_key = fx.rsa("serialize-rsa", RsaSpec::rs256());
        let ecdsa_key = fx.ecdsa("serialize-ecdsa", EcdsaSpec::Es256);

        // Step 2: Build JWKS
        let jwks = JwksBuilder::new()
            .add_public(rsa_key.public_jwk().into())
            .add_public(ecdsa_key.public_jwk().into())
            .build();

        // Step 3: Serialize to JSON
        let jwks_json = jwks.to_string();

        // Step 4: Verify JSON structure
        assert!(jwks_json.contains("\"keys\""));
        assert!(jwks_json.contains("\"kty\""));
        assert!(jwks_json.contains("\"kid\""));
        assert!(jwks_json.contains(rsa_key.kid()));
        assert!(jwks_json.contains(ecdsa_key.kid()));

        // Step 5: Verify can be parsed back
        let parsed: serde_json::Value =
            serde_json::from_str(&jwks_json).expect("Failed to parse JWKS JSON");
        assert!(parsed["keys"].is_array());
        assert_eq!(parsed["keys"].as_array().unwrap().len(), 2);
    }
}

// =========================================================================
// Certificate Chain Creation and Validation Tests
// =========================================================================

#[cfg(feature = "e2e")]
mod chain_workflow_tests {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn test_chain_creation_workflow() {
        let fx = fx();

        // Step 1: Generate certificate chain
        let chain_spec = ChainSpec::new("chain.example.com").with_sans(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "*.example.com".to_string(),
        ]);
        let chain = fx.x509_chain("chain-workflow", chain_spec);

        // Step 2: Verify chain structure
        assert!(!chain.leaf_cert_pem().is_empty());
        assert!(!chain.intermediate_cert_pem().is_empty());
        assert!(!chain.root_cert_pem().is_empty());
        assert!(!chain.chain_pem().is_empty());

        // Step 3: Verify DER formats
        assert!(!chain.leaf_cert_der().is_empty());
        assert!(!chain.intermediate_cert_der().is_empty());
        assert!(!chain.root_cert_der().is_empty());
        assert_eq!(chain.chain_der().len(), 2);

        // Step 4: Verify private key
        assert!(!chain.leaf_private_key_pkcs8_pem().is_empty());
        assert!(!chain.leaf_private_key_pkcs8_der().is_empty());
    }

    #[test]
    fn test_chain_with_custom_key_workflow() {
        let fx = fx();

        // Step 1: Generate custom key
        let custom_key = fx.rsa("custom-key", RsaSpec::rs256());

        // Step 2: Generate certificate chain with custom key
        let chain_spec = ChainSpec::new("custom.example.com");
        let chain = fx.x509_chain_with_key("custom-chain", chain_spec, &custom_key);

        // Step 3: Verify chain structure
        assert!(!chain.leaf_cert_pem().is_empty());
        assert!(!chain.root_cert_pem().is_empty());

        // Step 4: Verify private key matches
        assert_eq!(
            chain.leaf_private_key_pkcs8_der(),
            custom_key.private_key_pkcs8_der()
        );
    }

    #[test]
    fn test_self_signed_cert_workflow() {
        let fx = fx();

        // Step 1: Generate self-signed certificate
        let spec = uselesskey_x509::X509Spec::self_signed("self-signed.example.com");
        let cert = fx.x509_self_signed("self-signed-workflow", spec);

        // Step 2: Verify certificate structure
        assert!(!cert.cert_pem().is_empty());
        assert!(!cert.cert_der().is_empty());
        assert!(!cert.private_key_pkcs8_pem().is_empty());
        assert!(!cert.private_key_pkcs8_der().is_empty());
        assert!(!cert.identity_pem().is_empty());

        // Step 3: Verify identity PEM contains both cert and key
        let identity = cert.identity_pem();
        assert!(identity.contains("BEGIN CERTIFICATE"));
        assert!(identity.contains("BEGIN PRIVATE KEY"));
    }
}

// =========================================================================
// Negative Fixture Handling Tests
// =========================================================================

#[cfg(feature = "e2e")]
mod negative_fixture_workflow_tests {
    use super::*;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn test_expired_jwt_workflow() {
        let fx = fx();

        // Step 1: Generate key
        let keypair = fx.rsa("expired-jwt", RsaSpec::rs256());

        // Step 2: Create claims with expired timestamp
        let expired_time = 1234567890; // Past timestamp
        let claims = JwtClaims::new("user123", expired_time, 1234567890, "expired-jwt");

        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, &keypair.encoding_key())
            .expect("Failed to encode expired JWT");

        // Step 3: Verify expired token fails validation
        let validation = Validation::new(Algorithm::RS256);
        let result = decode::<JwtClaims>(&token, &keypair.decoding_key(), &validation);

        assert!(result.is_err(), "Expired JWT should fail validation");
    }

    #[test]
    fn test_expired_cert_workflow() {
        let fx = fx();

        // Step 1: Generate self-signed certificate
        let spec = uselesskey_x509::X509Spec::self_signed("expired.example.com");
        let cert = fx.x509_self_signed("expired-cert", spec);

        // Step 2: Create expired variant
        let expired_cert = cert.expired();

        // Step 3: Verify expired cert can still be used to create config
        // (config creation succeeds, handshake would fail)
        let server_config = expired_cert.server_config_rustls();
        assert_eq!(server_config.alpn_protocols.len(), 0);

        // Step 4: Verify certificate structure is preserved
        assert!(!expired_cert.cert_pem().is_empty());
        assert!(!expired_cert.cert_der().is_empty());
    }

    #[test]
    fn test_not_yet_valid_cert_workflow() {
        let fx = fx();

        // Step 1: Generate self-signed certificate
        let spec = uselesskey_x509::X509Spec::self_signed("not-yet-valid.example.com");
        let cert = fx.x509_self_signed("not-yet-valid-cert", spec);

        // Step 2: Create not-yet-valid variant
        let not_yet_valid_cert = cert.not_yet_valid();

        // Step 3: Verify not-yet-valid cert can still be used to create config
        // (config creation succeeds, handshake would fail)
        let server_config = not_yet_valid_cert.server_config_rustls();
        assert_eq!(server_config.alpn_protocols.len(), 0);

        // Step 4: Verify certificate structure is preserved
        assert!(!not_yet_valid_cert.cert_pem().is_empty());
        assert!(!not_yet_valid_cert.cert_der().is_empty());
    }

    #[test]
    fn test_mismatched_key_workflow() {
        let fx = fx();

        // Step 1: Generate two different keys
        let key1 = fx.rsa("key1", RsaSpec::rs256());
        let key2 = fx.rsa("key2", RsaSpec::rs256());

        // Step 2: Sign JWT with key1
        let claims = JwtClaims::new("user123", 9999999999, 1234567890, "key1");
        let header = Header::new(Algorithm::RS256);
        let token = encode(&header, &claims, &key1.encoding_key()).expect("Failed to encode JWT");

        // Step 3: Try to verify with key2 (should fail)
        let validation = Validation::new(Algorithm::RS256);
        let result = decode::<JwtClaims>(&token, &key2.decoding_key(), &validation);

        assert!(result.is_err(), "Mismatched key should fail verification");
    }
}

// =========================================================================
// Deterministic Workflow Tests
// =========================================================================

#[cfg(feature = "e2e")]
mod deterministic_workflow_tests {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::Ed25519FactoryExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn test_deterministic_key_workflow() {
        let fx1 = fx();
        let fx2 = fx();

        // Step 1: Generate same keys from same seed
        let rsa1 = fx1.rsa("deterministic-rsa", RsaSpec::rs256());
        let rsa2 = fx2.rsa("deterministic-rsa", RsaSpec::rs256());

        let ecdsa1 = fx1.ecdsa("deterministic-ecdsa", EcdsaSpec::Es256);
        let ecdsa2 = fx2.ecdsa("deterministic-ecdsa", EcdsaSpec::Es256);

        let ed1 = fx1.ed25519("deterministic-ed25519", Ed25519Spec::new());
        let ed2 = fx2.ed25519("deterministic-ed25519", Ed25519Spec::new());

        // Step 2: Verify keys are identical
        assert_eq!(rsa1.private_key_pkcs8_der(), rsa2.private_key_pkcs8_der());
        assert_eq!(
            ecdsa1.private_key_pkcs8_der(),
            ecdsa2.private_key_pkcs8_der()
        );
        assert_eq!(ed1.private_key_pkcs8_der(), ed2.private_key_pkcs8_der());

        // Step 3: Verify JWKs are identical
        assert_eq!(rsa1.public_jwk().kid(), rsa2.public_jwk().kid());
        assert_eq!(ecdsa1.public_jwk().kid(), ecdsa2.public_jwk().kid());
        assert_eq!(ed1.public_jwk().kid(), ed2.public_jwk().kid());
    }

    #[test]
    fn test_deterministic_jwks_workflow() {
        let fx1 = fx();
        let fx2 = fx();

        // Step 1: Generate same keys
        let rsa1 = fx1.rsa("jwks-deterministic", RsaSpec::rs256());
        let rsa2 = fx2.rsa("jwks-deterministic", RsaSpec::rs256());

        // Step 2: Build JWKS from both
        let jwks1 = JwksBuilder::new()
            .add_public(rsa1.public_jwk().into())
            .build();

        let jwks2 = JwksBuilder::new()
            .add_public(rsa2.public_jwk().into())
            .build();

        // Step 3: Verify JWKS are identical
        assert_eq!(jwks1.to_string(), jwks2.to_string());
    }
}

// =========================================================================
// Format Conversion Workflow Tests
// =========================================================================

#[cfg(feature = "e2e")]
mod format_conversion_workflow_tests {
    use super::*;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::Ed25519FactoryExt;
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

    #[test]
    fn test_pem_to_der_conversion_workflow() {
        let fx = fx();

        // Test RSA
        let rsa = fx.rsa("pem-der-rsa", RsaSpec::rs256());
        let rsa_pem = rsa.private_key_pkcs8_pem();
        let rsa_der = rsa.private_key_pkcs8_der();
        assert!(!rsa_pem.is_empty());
        assert!(!rsa_der.is_empty());

        // Test ECDSA
        let ecdsa = fx.ecdsa("pem-der-ecdsa", EcdsaSpec::Es256);
        let ecdsa_pem = ecdsa.private_key_pkcs8_pem();
        let ecdsa_der = ecdsa.private_key_pkcs8_der();
        assert!(!ecdsa_pem.is_empty());
        assert!(!ecdsa_der.is_empty());

        // Test Ed25519
        let ed = fx.ed25519("pem-der-ed25519", Ed25519Spec::new());
        let ed_pem = ed.private_key_pkcs8_pem();
        let ed_der = ed.private_key_pkcs8_der();
        assert!(!ed_pem.is_empty());
        assert!(!ed_der.is_empty());
    }

    #[test]
    fn test_jwk_conversion_workflow() {
        let fx = fx();

        // Test RSA
        let rsa = fx.rsa("jwk-conversion-rsa", RsaSpec::rs256());
        let rsa_jwk = rsa.public_jwk();
        assert!(!rsa_jwk.kid.is_empty());
        assert_eq!(rsa_jwk.kty, "RSA");

        // Test ECDSA
        let ecdsa = fx.ecdsa("jwk-conversion-ecdsa", EcdsaSpec::Es256);
        let ecdsa_jwk = ecdsa.public_jwk();
        assert!(!ecdsa_jwk.kid.is_empty());
        assert_eq!(ecdsa_jwk.kty, "EC");

        // Test Ed25519
        let ed = fx.ed25519("jwk-conversion-ed25519", Ed25519Spec::new());
        let ed_jwk = ed.public_jwk();
        assert!(!ed_jwk.kid.is_empty());
        assert_eq!(ed_jwk.kty, "OKP");
    }
}
