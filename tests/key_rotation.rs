//! Key Rotation Workflow Tests
//!
//! Tests real-world key rotation scenarios:
//! - JWT key rotation with ECDSA (old token valid only with old key)
//! - HMAC secret rotation
//! - Cross-algorithm rotation (Ed25519 → ECDSA via JWKS)
//! - JWKS incremental build and kid stability
//! - TLS certificate rotation

mod testutil;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
}

impl Claims {
    fn test() -> Self {
        Self {
            sub: "user123".to_string(),
            exp: 2_000_000_000,
            iat: 1234567890,
        }
    }
}

fn fx() -> uselesskey_core::Factory {
    #[cfg(any(feature = "tls", feature = "e2e", feature = "key-rotation"))]
    testutil::install_rustls_ring_provider();
    testutil::fx()
}

// =========================================================================
// JWT Rotation
// =========================================================================

#[cfg(feature = "key-rotation")]
mod jwt_rotation {
    use super::*;
    use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    use uselesskey_jsonwebtoken::JwtKeyExt;
    use uselesskey_jwk::JwksBuilder;

    #[test]
    fn test_old_token_valid_with_old_key_only() {
        let fx = fx();
        let kp_v1 = fx.ecdsa("rotation-v1", EcdsaSpec::es256());
        let kp_v2 = fx.ecdsa("rotation-v2", EcdsaSpec::es256());

        let claims = Claims::test();
        let header = Header::new(Algorithm::ES256);

        // Sign with v1
        let token = encode(&header, &claims, &kp_v1.encoding_key()).expect("sign with v1");

        // Verify with v1 should succeed
        let validation = Validation::new(Algorithm::ES256);
        let decoded = decode::<Claims>(&token, &kp_v1.decoding_key(), &validation);
        assert!(decoded.is_ok(), "v1 token should verify with v1 key");

        // Verify with v2 should fail
        let result = decode::<Claims>(&token, &kp_v2.decoding_key(), &validation);
        assert!(result.is_err(), "v1 token should NOT verify with v2 key");
    }

    #[test]
    fn test_new_token_valid_with_new_key_only() {
        let fx = fx();
        let kp_v1 = fx.ecdsa("new-token-v1", EcdsaSpec::es256());
        let kp_v2 = fx.ecdsa("new-token-v2", EcdsaSpec::es256());

        let claims = Claims::test();
        let header = Header::new(Algorithm::ES256);

        // Sign with v2
        let token = encode(&header, &claims, &kp_v2.encoding_key()).expect("sign with v2");

        // Verify with v2 should succeed
        let validation = Validation::new(Algorithm::ES256);
        let decoded = decode::<Claims>(&token, &kp_v2.decoding_key(), &validation);
        assert!(decoded.is_ok(), "v2 token should verify with v2 key");

        // Verify with v1 should fail
        let result = decode::<Claims>(&token, &kp_v1.decoding_key(), &validation);
        assert!(result.is_err(), "v2 token should NOT verify with v1 key");
    }

    #[test]
    fn test_grace_period_jwks_with_both_keys() {
        let fx = fx();
        let kp_v1 = fx.ecdsa("grace-v1", EcdsaSpec::es256());
        let kp_v2 = fx.ecdsa("grace-v2", EcdsaSpec::es256());

        // Build JWKS with both keys (grace period)
        let jwks = JwksBuilder::new()
            .add_public(kp_v1.public_jwk())
            .add_public(kp_v2.public_jwk())
            .build();

        // Both kids should be findable
        let found_v1 = jwks.keys.iter().find(|k| k.kid() == kp_v1.kid());
        let found_v2 = jwks.keys.iter().find(|k| k.kid() == kp_v2.kid());

        assert!(found_v1.is_some(), "v1 key should be in JWKS");
        assert!(found_v2.is_some(), "v2 key should be in JWKS");
        assert_ne!(
            kp_v1.kid(),
            kp_v2.kid(),
            "v1 and v2 should have different kids"
        );
    }

    #[test]
    fn test_hmac_secret_rotation() {
        let fx = fx();
        let s1 = fx.hmac("hmac-rotation-v1", HmacSpec::hs256());
        let s2 = fx.hmac("hmac-rotation-v2", HmacSpec::hs256());

        let claims = Claims::test();
        let header = Header::new(Algorithm::HS256);

        // Sign with s1
        let token = encode(&header, &claims, &s1.encoding_key()).expect("sign with s1");

        // Verify with s1 - ok
        let validation = Validation::new(Algorithm::HS256);
        assert!(
            decode::<Claims>(&token, &s1.decoding_key(), &validation).is_ok(),
            "s1 token should verify with s1"
        );

        // Verify with s2 - fail
        assert!(
            decode::<Claims>(&token, &s2.decoding_key(), &validation).is_err(),
            "s1 token should NOT verify with s2"
        );
    }

    #[test]
    fn test_cross_algorithm_rotation() {
        let fx = fx();

        // Old key: Ed25519
        let ed_kp = fx.ed25519("cross-alg-old", Ed25519Spec::new());
        // New key: ECDSA P-256
        let ec_kp = fx.ecdsa("cross-alg-new", EcdsaSpec::es256());

        // Build JWKS with both (different algorithms)
        let jwks = JwksBuilder::new()
            .add_public(ed_kp.public_jwk())
            .add_public(ec_kp.public_jwk())
            .build();

        assert_eq!(jwks.keys.len(), 2);

        // Both should be findable by kid
        let ed_jwk = jwks.keys.iter().find(|k| k.kid() == ed_kp.kid());
        let ec_jwk = jwks.keys.iter().find(|k| k.kid() == ec_kp.kid());

        assert!(ed_jwk.is_some(), "Ed25519 key should be in JWKS");
        assert!(ec_jwk.is_some(), "ECDSA key should be in JWKS");

        // Verify Ed25519 token
        let claims = Claims::test();
        let ed_token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            &ed_kp.encoding_key(),
        )
        .expect("sign with Ed25519");

        let ed_validation = Validation::new(Algorithm::EdDSA);
        assert!(decode::<Claims>(&ed_token, &ed_kp.decoding_key(), &ed_validation).is_ok());

        // Verify ECDSA token
        let ec_token = encode(
            &Header::new(Algorithm::ES256),
            &claims,
            &ec_kp.encoding_key(),
        )
        .expect("sign with ECDSA");

        let ec_validation = Validation::new(Algorithm::ES256);
        assert!(decode::<Claims>(&ec_token, &ec_kp.decoding_key(), &ec_validation).is_ok());
    }
}

// =========================================================================
// JWKS Rotation
// =========================================================================

#[cfg(feature = "key-rotation")]
mod jwks_rotation {
    use super::*;
    use std::collections::HashSet;
    use uselesskey_core::{Factory, Seed};
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_jwk::JwksBuilder;

    #[test]
    fn test_incremental_jwks_build() {
        let fx = fx();

        let v1 = fx.ecdsa("epoch-v1", EcdsaSpec::es256());
        let v2 = fx.ecdsa("epoch-v2", EcdsaSpec::es256());
        let v3 = fx.ecdsa("epoch-v3", EcdsaSpec::es256());

        // Epoch 1: only v1
        let jwks1 = JwksBuilder::new().add_public(v1.public_jwk()).build();
        assert_eq!(jwks1.keys.len(), 1);

        // Epoch 2: v1 + v2 (grace period)
        let jwks2 = JwksBuilder::new()
            .add_public(v1.public_jwk())
            .add_public(v2.public_jwk())
            .build();
        assert_eq!(jwks2.keys.len(), 2);

        // Epoch 3: v2 + v3 (v1 removed)
        let jwks3 = JwksBuilder::new()
            .add_public(v2.public_jwk())
            .add_public(v3.public_jwk())
            .build();
        assert_eq!(jwks3.keys.len(), 2);
        assert!(jwks3.keys.iter().all(|k| k.kid() != v1.kid()));

        // Epoch 4: v3 only (v2 removed)
        let jwks4 = JwksBuilder::new().add_public(v3.public_jwk()).build();
        assert_eq!(jwks4.keys.len(), 1);
        assert_eq!(jwks4.keys[0].kid(), v3.kid());
    }

    #[test]
    fn test_kid_uniqueness_across_rotations() {
        let fx = fx();

        let kids: HashSet<String> = (0..5)
            .map(|i| {
                let kp = fx.ecdsa(format!("unique-kid-{}", i), EcdsaSpec::es256());
                kp.kid().to_string()
            })
            .collect();

        assert_eq!(kids.len(), 5, "All 5 kids should be unique");
    }

    #[test]
    fn test_deterministic_kid_stability() {
        let seed = Seed::from_env_value("kid-stability-seed").unwrap();

        let fx1 = Factory::deterministic(seed);
        let kp1 = fx1.ecdsa("stable-kid", EcdsaSpec::es256());
        let kid1 = kp1.kid().to_string();

        let fx2 = Factory::deterministic(seed);
        let kp2 = fx2.ecdsa("stable-kid", EcdsaSpec::es256());
        let kid2 = kp2.kid().to_string();

        assert_eq!(kid1, kid2, "Same seed + label should produce same kid");
    }
}

// =========================================================================
// TLS Rotation
// =========================================================================

#[cfg(feature = "key-rotation")]
mod tls_rotation {
    use super::*;
    use uselesskey_rustls::RustlsServerConfigExt;
    use uselesskey_x509::{ChainSpec, X509FactoryExt, X509Spec};

    #[test]
    fn test_tls_cert_rotation_chain() {
        let fx = fx();

        let chain_v1 = fx.x509_chain("tls-rot-v1", ChainSpec::new("tls.example.com"));
        let chain_v2 = fx.x509_chain("tls-rot-v2", ChainSpec::new("tls.example.com"));

        // Different labels should produce different leaf certificates
        assert_ne!(
            chain_v1.leaf_cert_der(),
            chain_v2.leaf_cert_der(),
            "Different chain labels should produce different leaf DER"
        );

        // Both should build valid server configs
        let _config_v1 = chain_v1.server_config_rustls();
        let _config_v2 = chain_v2.server_config_rustls();
    }

    #[test]
    fn test_tls_self_signed_rotation() {
        let fx = fx();

        let cert_v1 = fx.x509_self_signed("tls-ss-v1", X509Spec::self_signed("tls.example.com"));
        let cert_v2 = fx.x509_self_signed("tls-ss-v2", X509Spec::self_signed("tls.example.com"));

        // Different labels should produce different certificates
        assert_ne!(
            cert_v1.cert_der(),
            cert_v2.cert_der(),
            "Different self-signed labels should produce different DER"
        );

        // Both should build valid server configs
        let _config_v1 = cert_v1.server_config_rustls();
        let _config_v2 = cert_v2.server_config_rustls();
    }
}
