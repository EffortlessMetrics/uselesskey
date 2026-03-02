//! Feature flag combination tests for the `uselesskey` facade crate.
//!
//! Verifies that the API works correctly under different feature combinations:
//! each algorithm independently, pairs of features together, core-only (no
//! algorithm features), re-exports, deterministic mode, key generation, JWK
//! output, and negative fixtures.

mod testutil;

use uselesskey::{Factory, Mode, Seed};

// ===========================================================================
// 1. Core-only: Factory works with no algorithm features
// ===========================================================================

#[test]
fn factory_random_mode_core_only() {
    let fx = Factory::random();
    assert!(matches!(fx.mode(), Mode::Random));
}

#[test]
fn factory_deterministic_mode_core_only() {
    let seed = Seed::from_env_value("feature-combo-seed").unwrap();
    let fx = Factory::deterministic(seed);
    assert!(matches!(fx.mode(), Mode::Deterministic { .. }));
}

#[test]
fn factory_clone_preserves_mode() {
    let fx = Factory::random();
    let fx2 = fx.clone();
    assert!(matches!(fx2.mode(), Mode::Random));
}

#[test]
fn negative_module_available_without_algorithm_features() {
    use uselesskey::negative::CorruptPem;

    let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
    let corrupted = uselesskey::negative::corrupt_pem(pem, CorruptPem::BadHeader);
    assert!(corrupted.contains("CORRUPTED"));
}

// ===========================================================================
// 2. Individual feature: RSA
// ===========================================================================

#[cfg(feature = "rsa")]
mod rsa_independent {
    use super::*;
    use uselesskey::{RsaFactoryExt, RsaKeyPair, RsaSpec};

    #[test]
    fn reexport_types_available() {
        let fx = testutil::fx();
        let _kp: RsaKeyPair = fx.rsa("rsa-reexport", RsaSpec::rs256());
    }

    #[test]
    fn keygen_rs256() {
        let fx = testutil::fx();
        let kp = fx.rsa("rsa-gen-256", RsaSpec::rs256());
        assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(!kp.private_key_pkcs8_der().is_empty());
        assert!(kp.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
        assert!(!kp.public_key_spki_der().is_empty());
    }

    #[test]
    fn deterministic_rsa_is_stable() {
        let seed = Seed::from_env_value("rsa-det-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);
        let k1 = fx1.rsa("det-rsa", RsaSpec::rs256());
        let k2 = fx2.rsa("det-rsa", RsaSpec::rs256());
        assert_eq!(k1.private_key_pkcs8_pem(), k2.private_key_pkcs8_pem());
    }

    #[test]
    fn negative_corrupt_pem() {
        use uselesskey::negative::CorruptPem;
        let fx = testutil::fx();
        let kp = fx.rsa("rsa-neg", RsaSpec::rs256());
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));
    }

    #[test]
    fn negative_truncated_der() {
        let fx = testutil::fx();
        let kp = fx.rsa("rsa-trunc", RsaSpec::rs256());
        let trunc = kp.private_key_pkcs8_der_truncated(16);
        assert_eq!(trunc.len(), 16);
    }

    #[test]
    fn negative_mismatched_public_key() {
        let fx = testutil::fx();
        let kp = fx.rsa("rsa-mm", RsaSpec::rs256());
        let mm = kp.mismatched_public_key_spki_der();
        assert_ne!(mm.as_slice(), kp.public_key_spki_der());
    }
}

// ===========================================================================
// 3. Individual feature: ECDSA
// ===========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_independent {
    use super::*;
    use uselesskey::{EcdsaFactoryExt, EcdsaKeyPair, EcdsaSpec};

    #[test]
    fn reexport_types_available() {
        let fx = testutil::fx();
        let _kp: EcdsaKeyPair = fx.ecdsa("ecdsa-reexport", EcdsaSpec::es256());
    }

    #[test]
    fn keygen_es256() {
        let fx = testutil::fx();
        let kp = fx.ecdsa("ecdsa-gen-256", EcdsaSpec::es256());
        assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(!kp.private_key_pkcs8_der().is_empty());
    }

    #[test]
    fn keygen_es384() {
        let fx = testutil::fx();
        let kp = fx.ecdsa("ecdsa-gen-384", EcdsaSpec::es384());
        assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(!kp.public_key_spki_der().is_empty());
    }

    #[test]
    fn deterministic_ecdsa_is_stable() {
        let seed = Seed::from_env_value("ecdsa-det-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);
        let k1 = fx1.ecdsa("det-ecdsa", EcdsaSpec::es256());
        let k2 = fx2.ecdsa("det-ecdsa", EcdsaSpec::es256());
        assert_eq!(k1.private_key_pkcs8_pem(), k2.private_key_pkcs8_pem());
    }

    #[test]
    fn negative_corrupt_pem() {
        use uselesskey::negative::CorruptPem;
        let fx = testutil::fx();
        let kp = fx.ecdsa("ecdsa-neg", EcdsaSpec::es256());
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));
    }

    #[test]
    fn negative_mismatched_public_key() {
        let fx = testutil::fx();
        let kp = fx.ecdsa("ecdsa-mm", EcdsaSpec::es256());
        let mm = kp.mismatched_public_key_spki_der();
        assert_ne!(mm.as_slice(), kp.public_key_spki_der());
    }
}

// ===========================================================================
// 4. Individual feature: Ed25519
// ===========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_independent {
    use super::*;
    use uselesskey::{Ed25519FactoryExt, Ed25519KeyPair, Ed25519Spec};

    #[test]
    fn reexport_types_available() {
        let fx = testutil::fx();
        let _kp: Ed25519KeyPair = fx.ed25519("ed-reexport", Ed25519Spec::new());
    }

    #[test]
    fn keygen() {
        let fx = testutil::fx();
        let kp = fx.ed25519("ed-gen", Ed25519Spec::new());
        assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(!kp.private_key_pkcs8_der().is_empty());
        assert!(kp.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
        assert!(!kp.public_key_spki_der().is_empty());
    }

    #[test]
    fn deterministic_ed25519_is_stable() {
        let seed = Seed::from_env_value("ed25519-det-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);
        let k1 = fx1.ed25519("det-ed", Ed25519Spec::new());
        let k2 = fx2.ed25519("det-ed", Ed25519Spec::new());
        assert_eq!(k1.private_key_pkcs8_pem(), k2.private_key_pkcs8_pem());
    }

    #[test]
    fn negative_corrupt_pem() {
        use uselesskey::negative::CorruptPem;
        let fx = testutil::fx();
        let kp = fx.ed25519("ed-neg", Ed25519Spec::new());
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));
    }

    #[test]
    fn negative_mismatched_public_key() {
        let fx = testutil::fx();
        let kp = fx.ed25519("ed-mm", Ed25519Spec::new());
        let mm = kp.mismatched_public_key_spki_der();
        assert_ne!(mm.as_slice(), kp.public_key_spki_der());
    }
}

// ===========================================================================
// 5. Individual feature: HMAC
// ===========================================================================

#[cfg(feature = "hmac")]
mod hmac_independent {
    use super::*;
    use uselesskey::{HmacFactoryExt, HmacSecret, HmacSpec};

    #[test]
    fn reexport_types_available() {
        let fx = testutil::fx();
        let _s: HmacSecret = fx.hmac("hmac-reexport", HmacSpec::hs256());
    }

    #[test]
    fn keygen_hs256() {
        let fx = testutil::fx();
        let s = fx.hmac("hmac-256", HmacSpec::hs256());
        assert_eq!(s.secret_bytes().len(), HmacSpec::hs256().byte_len());
    }

    #[test]
    fn keygen_hs384() {
        let fx = testutil::fx();
        let s = fx.hmac("hmac-384", HmacSpec::hs384());
        assert_eq!(s.secret_bytes().len(), HmacSpec::hs384().byte_len());
    }

    #[test]
    fn keygen_hs512() {
        let fx = testutil::fx();
        let s = fx.hmac("hmac-512", HmacSpec::hs512());
        assert_eq!(s.secret_bytes().len(), HmacSpec::hs512().byte_len());
    }

    #[test]
    fn deterministic_hmac_is_stable() {
        let seed = Seed::from_env_value("hmac-det-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);
        let s1 = fx1.hmac("det-hmac", HmacSpec::hs256());
        let s2 = fx2.hmac("det-hmac", HmacSpec::hs256());
        assert_eq!(s1.secret_bytes(), s2.secret_bytes());
    }
}

// ===========================================================================
// 6. Individual feature: Token
// ===========================================================================

#[cfg(feature = "token")]
mod token_independent {
    use super::*;
    use uselesskey::{TokenFactoryExt, TokenFixture, TokenSpec};

    #[test]
    fn reexport_types_available() {
        let fx = testutil::fx();
        let _t: TokenFixture = fx.token("tok-reexport", TokenSpec::api_key());
    }

    #[test]
    fn api_key_has_prefix() {
        let fx = testutil::fx();
        let t = fx.token("tok-api", TokenSpec::api_key());
        assert!(t.value().starts_with("uk_test_"));
    }

    #[test]
    fn bearer_authorization_header() {
        let fx = testutil::fx();
        let t = fx.token("tok-bearer", TokenSpec::bearer());
        assert!(t.authorization_header().starts_with("Bearer "));
    }

    #[test]
    fn oauth_has_jwt_shape() {
        let fx = testutil::fx();
        let t = fx.token("tok-oauth", TokenSpec::oauth_access_token());
        let segments: Vec<&str> = t.value().split('.').collect();
        assert_eq!(
            segments.len(),
            3,
            "OAuth token should have 3 dot-separated segments"
        );
    }

    #[test]
    fn deterministic_token_is_stable() {
        let seed = Seed::from_env_value("token-det-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);
        let t1 = fx1.token("det-tok", TokenSpec::api_key());
        let t2 = fx2.token("det-tok", TokenSpec::api_key());
        assert_eq!(t1.value(), t2.value());
    }
}

// ===========================================================================
// 7. Individual feature: X.509
// ===========================================================================

#[cfg(feature = "x509")]
mod x509_independent {
    use super::*;
    use uselesskey::{X509FactoryExt, X509Spec};

    #[test]
    fn self_signed_cert_generation() {
        let fx = testutil::fx();
        let cert = fx.x509_self_signed("x509-gen", X509Spec::self_signed("test.example.com"));
        assert!(cert.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(!cert.cert_der().is_empty());
    }

    #[test]
    fn deterministic_x509_is_stable() {
        let seed = Seed::from_env_value("x509-det-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);
        let c1 = fx1.x509_self_signed("det-x509", X509Spec::self_signed("det.example.com"));
        let c2 = fx2.x509_self_signed("det-x509", X509Spec::self_signed("det.example.com"));
        assert_eq!(c1.cert_der(), c2.cert_der());
    }

    #[test]
    fn negative_expired_cert() {
        use uselesskey::negative::CorruptPem;
        let fx = testutil::fx();
        let cert = fx.x509_self_signed("x509-neg", X509Spec::self_signed("neg.example.com"));
        let expired = cert.expired();
        assert_ne!(cert.cert_der(), expired.cert_der());

        let bad_pem = cert.corrupt_cert_pem(CorruptPem::BadHeader);
        assert!(bad_pem.contains("CORRUPTED"));
    }
}

// ===========================================================================
// 8. JWK output per algorithm (requires jwk + algorithm feature)
// ===========================================================================

#[cfg(all(feature = "jwk", feature = "rsa"))]
mod jwk_rsa {
    use super::*;
    use uselesskey::RsaFactoryExt;
    use uselesskey::RsaSpec;

    #[test]
    fn rsa_public_jwk_format() {
        let fx = testutil::fx();
        let kp = fx.rsa("jwk-rsa", RsaSpec::rs256());
        let jwk = kp.public_jwk();
        let val = jwk.to_value();
        assert_eq!(val["kty"], "RSA");
        assert_eq!(val["alg"], "RS256");
        assert_eq!(val["use"], "sig");
        assert!(val["n"].is_string());
        assert!(val["e"].is_string());
        assert!(val["kid"].is_string());
    }

    #[test]
    fn rsa_kid_is_non_empty() {
        let fx = testutil::fx();
        let kp = fx.rsa("jwk-rsa-kid", RsaSpec::rs256());
        assert!(!kp.kid().is_empty());
    }

    #[test]
    fn rsa_jwks_has_one_key() {
        let fx = testutil::fx();
        let kp = fx.rsa("jwk-rsa-jwks", RsaSpec::rs256());
        let jwks = kp.public_jwks();
        let val = jwks.to_value();
        assert_eq!(val["keys"].as_array().unwrap().len(), 1);
    }
}

#[cfg(all(feature = "jwk", feature = "ecdsa"))]
mod jwk_ecdsa {
    use super::*;
    use uselesskey::EcdsaFactoryExt;
    use uselesskey::EcdsaSpec;

    #[test]
    fn ecdsa_es256_public_jwk_format() {
        let fx = testutil::fx();
        let kp = fx.ecdsa("jwk-ec256", EcdsaSpec::es256());
        let jwk = kp.public_jwk();
        let val = jwk.to_value();
        assert_eq!(val["kty"], "EC");
        assert_eq!(val["alg"], "ES256");
        assert_eq!(val["crv"], "P-256");
        assert_eq!(val["use"], "sig");
        assert!(val["x"].is_string());
        assert!(val["y"].is_string());
        assert!(val["kid"].is_string());
    }

    #[test]
    fn ecdsa_es384_public_jwk_format() {
        let fx = testutil::fx();
        let kp = fx.ecdsa("jwk-ec384", EcdsaSpec::es384());
        let val = kp.public_jwk().to_value();
        assert_eq!(val["kty"], "EC");
        assert_eq!(val["alg"], "ES384");
        assert_eq!(val["crv"], "P-384");
    }

    #[test]
    fn ecdsa_kid_is_non_empty() {
        let fx = testutil::fx();
        let kp = fx.ecdsa("jwk-ec-kid", EcdsaSpec::es256());
        assert!(!kp.kid().is_empty());
    }
}

#[cfg(all(feature = "jwk", feature = "ed25519"))]
mod jwk_ed25519 {
    use super::*;
    use uselesskey::Ed25519FactoryExt;
    use uselesskey::Ed25519Spec;

    #[test]
    fn ed25519_public_jwk_format() {
        let fx = testutil::fx();
        let kp = fx.ed25519("jwk-ed", Ed25519Spec::new());
        let jwk = kp.public_jwk();
        let val = jwk.to_value();
        assert_eq!(val["kty"], "OKP");
        assert_eq!(val["alg"], "EdDSA");
        assert_eq!(val["crv"], "Ed25519");
        assert_eq!(val["use"], "sig");
        assert!(val["x"].is_string());
        assert!(val["kid"].is_string());
    }

    #[test]
    fn ed25519_jwks_has_one_key() {
        let fx = testutil::fx();
        let kp = fx.ed25519("jwk-ed-jwks", Ed25519Spec::new());
        let jwks = kp.public_jwks();
        let val = jwks.to_value();
        assert_eq!(val["keys"].as_array().unwrap().len(), 1);
    }
}

#[cfg(all(feature = "jwk", feature = "hmac"))]
mod jwk_hmac {
    use super::*;
    use uselesskey::HmacFactoryExt;
    use uselesskey::HmacSpec;

    #[test]
    fn hmac_jwk_format() {
        let fx = testutil::fx();
        let s = fx.hmac("jwk-hmac", HmacSpec::hs256());
        let jwk = s.jwk();
        let val = jwk.to_value();
        assert_eq!(val["kty"], "oct");
        assert_eq!(val["alg"], "HS256");
        assert_eq!(val["use"], "sig");
        assert!(val["k"].is_string());
        assert!(val["kid"].is_string());
    }

    #[test]
    fn hmac_hs384_jwk_alg() {
        let fx = testutil::fx();
        let s = fx.hmac("jwk-hmac-384", HmacSpec::hs384());
        let val = s.jwk().to_value();
        assert_eq!(val["alg"], "HS384");
    }

    #[test]
    fn hmac_hs512_jwk_alg() {
        let fx = testutil::fx();
        let s = fx.hmac("jwk-hmac-512", HmacSpec::hs512());
        let val = s.jwk().to_value();
        assert_eq!(val["alg"], "HS512");
    }

    #[test]
    fn hmac_jwks_has_one_key() {
        let fx = testutil::fx();
        let s = fx.hmac("jwk-hmac-jwks", HmacSpec::hs256());
        let jwks = s.jwks();
        let val = jwks.to_value();
        assert_eq!(val["keys"].as_array().unwrap().len(), 1);
    }
}

// ===========================================================================
// 9. Feature pairs: RSA + ECDSA
// ===========================================================================

#[cfg(all(feature = "rsa", feature = "ecdsa"))]
mod pair_rsa_ecdsa {
    use super::*;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec, RsaFactoryExt, RsaSpec};

    #[test]
    fn both_key_types_from_same_factory() {
        let fx = testutil::fx();
        let rsa = fx.rsa("pair-rsa", RsaSpec::rs256());
        let ec = fx.ecdsa("pair-ecdsa", EcdsaSpec::es256());
        assert!(rsa.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(ec.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        // Different algorithms produce different keys
        assert_ne!(rsa.private_key_pkcs8_der(), ec.private_key_pkcs8_der());
    }

    #[test]
    fn deterministic_cross_algorithm_independence() {
        let seed = Seed::from_env_value("pair-re-seed").unwrap();
        let fx = Factory::deterministic(seed);
        // Generating one type should not affect the other
        let rsa1 = fx.rsa("pair-rsa-det", RsaSpec::rs256());
        let ec1 = fx.ecdsa("pair-ec-det", EcdsaSpec::es256());

        let seed2 = Seed::from_env_value("pair-re-seed").unwrap();
        let fx2 = Factory::deterministic(seed2);
        // Reverse order: ECDSA first, then RSA
        let ec2 = fx2.ecdsa("pair-ec-det", EcdsaSpec::es256());
        let rsa2 = fx2.rsa("pair-rsa-det", RsaSpec::rs256());

        assert_eq!(rsa1.private_key_pkcs8_pem(), rsa2.private_key_pkcs8_pem());
        assert_eq!(ec1.private_key_pkcs8_pem(), ec2.private_key_pkcs8_pem());
    }
}

// ===========================================================================
// 10. Feature pairs: RSA + Ed25519
// ===========================================================================

#[cfg(all(feature = "rsa", feature = "ed25519"))]
mod pair_rsa_ed25519 {
    use super::*;
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec, RsaFactoryExt, RsaSpec};

    #[test]
    fn both_key_types_from_same_factory() {
        let fx = testutil::fx();
        let rsa = fx.rsa("pair-rsa-ed-r", RsaSpec::rs256());
        let ed = fx.ed25519("pair-rsa-ed-e", Ed25519Spec::new());
        assert!(!rsa.private_key_pkcs8_der().is_empty());
        assert!(!ed.private_key_pkcs8_der().is_empty());
        assert_ne!(rsa.private_key_pkcs8_der(), ed.private_key_pkcs8_der());
    }
}

// ===========================================================================
// 11. Feature pairs: RSA + HMAC
// ===========================================================================

#[cfg(all(feature = "rsa", feature = "hmac"))]
mod pair_rsa_hmac {
    use super::*;
    use uselesskey::{HmacFactoryExt, HmacSpec, RsaFactoryExt, RsaSpec};

    #[test]
    fn asymmetric_and_symmetric_from_same_factory() {
        let fx = testutil::fx();
        let rsa = fx.rsa("pair-rh-r", RsaSpec::rs256());
        let hmac = fx.hmac("pair-rh-h", HmacSpec::hs256());
        assert!(rsa.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert_eq!(hmac.secret_bytes().len(), HmacSpec::hs256().byte_len());
    }
}

// ===========================================================================
// 12. Feature pairs: ECDSA + Ed25519
// ===========================================================================

#[cfg(all(feature = "ecdsa", feature = "ed25519"))]
mod pair_ecdsa_ed25519 {
    use super::*;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec};

    #[test]
    fn both_elliptic_curve_types_coexist() {
        let fx = testutil::fx();
        let ec = fx.ecdsa("pair-ee-ec", EcdsaSpec::es256());
        let ed = fx.ed25519("pair-ee-ed", Ed25519Spec::new());
        assert!(!ec.public_key_spki_der().is_empty());
        assert!(!ed.public_key_spki_der().is_empty());
        assert_ne!(ec.public_key_spki_der(), ed.public_key_spki_der());
    }
}

// ===========================================================================
// 13. Feature pairs: ECDSA + HMAC
// ===========================================================================

#[cfg(all(feature = "ecdsa", feature = "hmac"))]
mod pair_ecdsa_hmac {
    use super::*;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec, HmacFactoryExt, HmacSpec};

    #[test]
    fn ecdsa_and_hmac_from_same_factory() {
        let fx = testutil::fx();
        let ec = fx.ecdsa("pair-eh-ec", EcdsaSpec::es256());
        let hmac = fx.hmac("pair-eh-h", HmacSpec::hs256());
        assert!(ec.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert_eq!(hmac.secret_bytes().len(), HmacSpec::hs256().byte_len());
    }
}

// ===========================================================================
// 14. Feature pairs: Ed25519 + HMAC
// ===========================================================================

#[cfg(all(feature = "ed25519", feature = "hmac"))]
mod pair_ed25519_hmac {
    use super::*;
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec, HmacFactoryExt, HmacSpec};

    #[test]
    fn ed25519_and_hmac_from_same_factory() {
        let fx = testutil::fx();
        let ed = fx.ed25519("pair-edh-ed", Ed25519Spec::new());
        let hmac = fx.hmac("pair-edh-h", HmacSpec::hs512());
        assert!(!ed.private_key_pkcs8_der().is_empty());
        assert_eq!(hmac.secret_bytes().len(), HmacSpec::hs512().byte_len());
    }
}

// ===========================================================================
// 15. Feature pairs: RSA + Token
// ===========================================================================

#[cfg(all(feature = "rsa", feature = "token"))]
mod pair_rsa_token {
    use super::*;
    use uselesskey::{RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec};

    #[test]
    fn rsa_and_token_from_same_factory() {
        let fx = testutil::fx();
        let rsa = fx.rsa("pair-rt-r", RsaSpec::rs256());
        let tok = fx.token("pair-rt-t", TokenSpec::bearer());
        assert!(rsa.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(!tok.value().is_empty());
    }
}

// ===========================================================================
// 16. Feature pairs: RSA + X.509 (x509 implies rsa)
// ===========================================================================

#[cfg(feature = "x509")]
mod pair_rsa_x509 {
    use super::*;
    use uselesskey::{RsaFactoryExt, RsaSpec, X509FactoryExt, X509Spec};

    #[test]
    fn rsa_and_x509_from_same_factory() {
        let fx = testutil::fx();
        let rsa = fx.rsa("pair-rx-r", RsaSpec::rs256());
        let cert = fx.x509_self_signed("pair-rx-x", X509Spec::self_signed("pair.example.com"));
        assert!(rsa.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(cert.cert_pem().contains("BEGIN CERTIFICATE"));
    }
}

// ===========================================================================
// 17. Feature pairs with JWK: RSA + ECDSA + JWK
// ===========================================================================

#[cfg(all(feature = "jwk", feature = "rsa", feature = "ecdsa"))]
mod pair_jwk_rsa_ecdsa {
    use super::*;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec, RsaFactoryExt, RsaSpec};

    #[test]
    fn different_kty_in_jwk_output() {
        let fx = testutil::fx();
        let rsa_jwk = fx
            .rsa("jwk-pair-r", RsaSpec::rs256())
            .public_jwk()
            .to_value();
        let ec_jwk = fx
            .ecdsa("jwk-pair-ec", EcdsaSpec::es256())
            .public_jwk()
            .to_value();
        assert_eq!(rsa_jwk["kty"], "RSA");
        assert_eq!(ec_jwk["kty"], "EC");
    }

    #[test]
    fn kids_differ_across_algorithms() {
        let fx = testutil::fx();
        let rsa_kid = fx.rsa("jwk-kid-r", RsaSpec::rs256()).kid();
        let ec_kid = fx.ecdsa("jwk-kid-ec", EcdsaSpec::es256()).kid();
        assert_ne!(rsa_kid, ec_kid);
    }
}

// ===========================================================================
// 18. Feature pairs with JWK: Ed25519 + HMAC + JWK
// ===========================================================================

#[cfg(all(feature = "jwk", feature = "ed25519", feature = "hmac"))]
mod pair_jwk_ed25519_hmac {
    use super::*;
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec, HmacFactoryExt, HmacSpec};

    #[test]
    fn different_kty_in_jwk_output() {
        let fx = testutil::fx();
        let ed_jwk = fx
            .ed25519("jwk-pair-ed", Ed25519Spec::new())
            .public_jwk()
            .to_value();
        let hmac_jwk = fx.hmac("jwk-pair-h", HmacSpec::hs256()).jwk().to_value();
        assert_eq!(ed_jwk["kty"], "OKP");
        assert_eq!(hmac_jwk["kty"], "oct");
    }
}

// ===========================================================================
// 19. Prelude re-exports based on enabled features
// ===========================================================================

#[test]
fn prelude_always_exports_core() {
    use uselesskey::prelude::*;
    let fx = Factory::random();
    assert!(matches!(fx.mode(), Mode::Random));
}

#[cfg(feature = "rsa")]
#[test]
fn prelude_exports_rsa_when_enabled() {
    use uselesskey::prelude::*;
    let fx = testutil::fx();
    let _kp: RsaKeyPair = fx.rsa("prelude-rsa", RsaSpec::rs256());
}

#[cfg(feature = "ecdsa")]
#[test]
fn prelude_exports_ecdsa_when_enabled() {
    use uselesskey::prelude::*;
    let fx = testutil::fx();
    let _kp: EcdsaKeyPair = fx.ecdsa("prelude-ecdsa", EcdsaSpec::es256());
}

#[cfg(feature = "ed25519")]
#[test]
fn prelude_exports_ed25519_when_enabled() {
    use uselesskey::prelude::*;
    let fx = testutil::fx();
    let _kp: Ed25519KeyPair = fx.ed25519("prelude-ed25519", Ed25519Spec::new());
}

#[cfg(feature = "hmac")]
#[test]
fn prelude_exports_hmac_when_enabled() {
    use uselesskey::prelude::*;
    let fx = testutil::fx();
    let _s: HmacSecret = fx.hmac("prelude-hmac", HmacSpec::hs256());
}

#[cfg(feature = "token")]
#[test]
fn prelude_exports_token_when_enabled() {
    use uselesskey::prelude::*;
    let fx = testutil::fx();
    let _t: TokenFixture = fx.token("prelude-token", TokenSpec::api_key());
}

#[cfg(feature = "x509")]
#[test]
fn prelude_exports_x509_when_enabled() {
    use uselesskey::prelude::*;
    let fx = testutil::fx();
    let _c: X509Cert = fx.x509_self_signed("prelude-x509", X509Spec::self_signed("p.example.com"));
}

// ===========================================================================
// 20. All-keys bundle: all algorithm features together
// ===========================================================================

#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "hmac"
))]
mod all_algorithms {
    use super::*;
    use uselesskey::{
        EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, HmacFactoryExt, HmacSpec,
        RsaFactoryExt, RsaSpec,
    };

    #[test]
    fn all_algorithms_from_single_factory() {
        let fx = testutil::fx();
        let rsa = fx.rsa("all-rsa", RsaSpec::rs256());
        let ec = fx.ecdsa("all-ecdsa", EcdsaSpec::es256());
        let ed = fx.ed25519("all-ed25519", Ed25519Spec::new());
        let hmac = fx.hmac("all-hmac", HmacSpec::hs256());

        assert!(rsa.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(ec.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(ed.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert_eq!(hmac.secret_bytes().len(), HmacSpec::hs256().byte_len());
    }

    #[test]
    fn deterministic_all_algorithms_order_independent() {
        let seed = Seed::from_env_value("all-alg-seed").unwrap();

        // Forward order
        let fx1 = Factory::deterministic(seed);
        let rsa1 = fx1.rsa("oi-rsa", RsaSpec::rs256());
        let ec1 = fx1.ecdsa("oi-ecdsa", EcdsaSpec::es256());
        let ed1 = fx1.ed25519("oi-ed25519", Ed25519Spec::new());
        let hmac1 = fx1.hmac("oi-hmac", HmacSpec::hs256());

        // Reverse order
        let fx2 = Factory::deterministic(seed);
        let hmac2 = fx2.hmac("oi-hmac", HmacSpec::hs256());
        let ed2 = fx2.ed25519("oi-ed25519", Ed25519Spec::new());
        let ec2 = fx2.ecdsa("oi-ecdsa", EcdsaSpec::es256());
        let rsa2 = fx2.rsa("oi-rsa", RsaSpec::rs256());

        assert_eq!(rsa1.private_key_pkcs8_pem(), rsa2.private_key_pkcs8_pem());
        assert_eq!(ec1.private_key_pkcs8_pem(), ec2.private_key_pkcs8_pem());
        assert_eq!(ed1.private_key_pkcs8_pem(), ed2.private_key_pkcs8_pem());
        assert_eq!(hmac1.secret_bytes(), hmac2.secret_bytes());
    }
}

// ===========================================================================
// 21. Full feature set: all keys + token + x509 + jwk
// ===========================================================================

#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "hmac",
    feature = "token",
    feature = "x509",
    feature = "jwk"
))]
mod full_feature_set {
    use super::*;
    use uselesskey::{
        EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, HmacFactoryExt, HmacSpec,
        RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec, X509FactoryExt, X509Spec,
    };

    #[test]
    fn all_features_generate_from_single_factory() {
        let fx = testutil::fx();
        let rsa = fx.rsa("full-rsa", RsaSpec::rs256());
        let ec = fx.ecdsa("full-ecdsa", EcdsaSpec::es256());
        let ed = fx.ed25519("full-ed25519", Ed25519Spec::new());
        let hmac = fx.hmac("full-hmac", HmacSpec::hs256());
        let tok = fx.token("full-tok", TokenSpec::api_key());
        let cert = fx.x509_self_signed("full-x509", X509Spec::self_signed("full.example.com"));

        // JWK output for asymmetric types
        let rsa_jwk = rsa.public_jwk().to_value();
        let ec_jwk = ec.public_jwk().to_value();
        let ed_jwk = ed.public_jwk().to_value();
        let hmac_jwk = hmac.jwk().to_value();

        assert_eq!(rsa_jwk["kty"], "RSA");
        assert_eq!(ec_jwk["kty"], "EC");
        assert_eq!(ed_jwk["kty"], "OKP");
        assert_eq!(hmac_jwk["kty"], "oct");
        assert!(tok.value().starts_with("uk_test_"));
        assert!(cert.cert_pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn all_negative_fixtures_work_together() {
        use uselesskey::negative::CorruptPem;

        let fx = testutil::fx();
        let rsa = fx.rsa("full-neg-rsa", RsaSpec::rs256());
        let ec = fx.ecdsa("full-neg-ecdsa", EcdsaSpec::es256());
        let ed = fx.ed25519("full-neg-ed25519", Ed25519Spec::new());
        let cert = fx.x509_self_signed(
            "full-neg-x509",
            X509Spec::self_signed("neg-full.example.com"),
        );

        // Corrupt PEM for each type
        assert!(
            rsa.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader)
                .contains("CORRUPTED")
        );
        assert!(
            ec.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader)
                .contains("CORRUPTED")
        );
        assert!(
            ed.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader)
                .contains("CORRUPTED")
        );
        assert!(
            cert.corrupt_cert_pem(CorruptPem::BadHeader)
                .contains("CORRUPTED")
        );

        // Mismatch for asymmetric types
        assert_ne!(
            rsa.mismatched_public_key_spki_der().as_slice(),
            rsa.public_key_spki_der()
        );
        assert_ne!(
            ec.mismatched_public_key_spki_der().as_slice(),
            ec.public_key_spki_der()
        );
        assert_ne!(
            ed.mismatched_public_key_spki_der().as_slice(),
            ed.public_key_spki_der()
        );
    }
}
