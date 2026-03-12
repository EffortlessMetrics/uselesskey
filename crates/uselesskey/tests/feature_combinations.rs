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

// ===========================================================================
// 22. Feature gating: core works when individual features are absent
// ===========================================================================

/// When `rsa` is NOT enabled, core types (Factory, Seed, Mode, negative)
/// must still compile and work. RSA-specific types would be absent.
#[cfg(not(feature = "rsa"))]
mod rsa_gated_out {
    #[test]
    fn core_factory_works_without_rsa() {
        let fx = uselesskey::Factory::random();
        assert!(matches!(fx.mode(), uselesskey::Mode::Random));
    }

    #[test]
    fn seed_works_without_rsa() {
        let seed = uselesskey::Seed::from_env_value("no-rsa-seed").unwrap();
        let fx = uselesskey::Factory::deterministic(seed);
        assert!(matches!(fx.mode(), uselesskey::Mode::Deterministic { .. }));
    }

    #[test]
    fn negative_helpers_work_without_rsa() {
        use uselesskey::negative::CorruptPem;
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let corrupted = uselesskey::negative::corrupt_pem(pem, CorruptPem::BadHeader);
        assert!(corrupted.contains("CORRUPTED"));
    }
}

/// When `ecdsa` is NOT enabled, core types must still work.
#[cfg(not(feature = "ecdsa"))]
mod ecdsa_gated_out {
    #[test]
    fn core_factory_works_without_ecdsa() {
        let fx = uselesskey::Factory::random();
        assert!(matches!(fx.mode(), uselesskey::Mode::Random));
    }

    #[test]
    fn negative_helpers_work_without_ecdsa() {
        use uselesskey::negative::CorruptPem;
        let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
        let corrupted = uselesskey::negative::corrupt_pem(pem, CorruptPem::BadFooter);
        assert!(corrupted.contains("CORRUPTED"));
    }
}

/// When `ed25519` is NOT enabled, core types must still work.
#[cfg(not(feature = "ed25519"))]
mod ed25519_gated_out {
    #[test]
    fn core_factory_works_without_ed25519() {
        let fx = uselesskey::Factory::random();
        assert!(matches!(fx.mode(), uselesskey::Mode::Random));
    }
}

/// When `hmac` is NOT enabled, core types must still work.
#[cfg(not(feature = "hmac"))]
mod hmac_gated_out {
    #[test]
    fn core_factory_works_without_hmac() {
        let fx = uselesskey::Factory::random();
        assert!(matches!(fx.mode(), uselesskey::Mode::Random));
    }
}

/// When `token` is NOT enabled, core types must still work.
#[cfg(not(feature = "token"))]
mod token_gated_out {
    #[test]
    fn core_factory_works_without_token() {
        let fx = uselesskey::Factory::random();
        assert!(matches!(fx.mode(), uselesskey::Mode::Random));
    }
}

/// When `jwk` is NOT enabled, core types must still work.
#[cfg(not(feature = "jwk"))]
mod jwk_gated_out {
    #[test]
    fn core_factory_works_without_jwk() {
        let fx = uselesskey::Factory::random();
        assert!(matches!(fx.mode(), uselesskey::Mode::Random));
    }
}

// ===========================================================================
// 23. Feature interdependencies
// ===========================================================================

/// The `x509` feature implies `rsa`, so when `x509` is enabled, RSA types
/// and the extension trait must be available.
#[cfg(feature = "x509")]
mod x509_implies_rsa {
    use super::*;
    use uselesskey::{RsaFactoryExt, RsaKeyPair, RsaSpec, X509FactoryExt, X509Spec};

    #[test]
    fn rsa_available_when_x509_enabled() {
        let fx = testutil::fx();
        let _kp: RsaKeyPair = fx.rsa("x509-implies-rsa", RsaSpec::rs256());
    }

    #[test]
    fn x509_and_rsa_share_factory() {
        let fx = testutil::fx();
        let rsa = fx.rsa("x509-rsa-share-r", RsaSpec::rs256());
        let cert = fx.x509_self_signed(
            "x509-rsa-share-x",
            X509Spec::self_signed("share.example.com"),
        );
        assert!(!rsa.private_key_pkcs8_der().is_empty());
        assert!(!cert.cert_der().is_empty());
    }

    #[test]
    fn x509_implies_rsa_deterministic_independence() {
        let seed = Seed::from_env_value("x509-rsa-dep-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let rsa1 = fx1.rsa("x509dep-rsa", RsaSpec::rs256());
        let cert1 = fx1.x509_self_signed("x509dep-cert", X509Spec::self_signed("dep.example.com"));

        let fx2 = Factory::deterministic(seed);
        // Reverse order
        let cert2 = fx2.x509_self_signed("x509dep-cert", X509Spec::self_signed("dep.example.com"));
        let rsa2 = fx2.rsa("x509dep-rsa", RsaSpec::rs256());

        assert_eq!(rsa1.private_key_pkcs8_pem(), rsa2.private_key_pkcs8_pem());
        assert_eq!(cert1.cert_der(), cert2.cert_der());
    }
}

/// The `x509` feature also implies `jwk` (via `uselesskey-x509/jwk`),
/// so JWK module should be available when x509 is enabled.
#[cfg(feature = "x509")]
mod x509_implies_jwk {
    use super::*;
    use uselesskey::{RsaFactoryExt, RsaSpec};

    #[test]
    fn jwk_output_available_via_x509_feature() {
        let fx = testutil::fx();
        let kp = fx.rsa("x509-jwk-test", RsaSpec::rs256());
        // x509 enables jwk passthrough for rsa, so kid() should work
        let kid = kp.kid();
        assert!(!kid.is_empty());
    }
}

/// The `full` feature implies `all-keys` + `token` + `x509` + `jwk`.
/// `all-keys` is `rsa` + `ecdsa` + `ed25519` + `hmac` + `pgp`.
/// Verify all sub-features are transitively enabled.
#[cfg(feature = "full")]
mod full_implies_all {
    use super::*;

    #[test]
    fn full_enables_rsa() {
        use uselesskey::{RsaFactoryExt, RsaSpec};
        let fx = testutil::fx();
        let kp = fx.rsa("full-rsa-check", RsaSpec::rs256());
        assert!(!kp.private_key_pkcs8_der().is_empty());
    }

    #[test]
    fn full_enables_ecdsa() {
        use uselesskey::{EcdsaFactoryExt, EcdsaSpec};
        let fx = testutil::fx();
        let kp = fx.ecdsa("full-ecdsa-check", EcdsaSpec::es256());
        assert!(!kp.private_key_pkcs8_der().is_empty());
    }

    #[test]
    fn full_enables_ed25519() {
        use uselesskey::{Ed25519FactoryExt, Ed25519Spec};
        let fx = testutil::fx();
        let kp = fx.ed25519("full-ed25519-check", Ed25519Spec::new());
        assert!(!kp.private_key_pkcs8_der().is_empty());
    }

    #[test]
    fn full_enables_hmac() {
        use uselesskey::{HmacFactoryExt, HmacSpec};
        let fx = testutil::fx();
        let s = fx.hmac("full-hmac-check", HmacSpec::hs256());
        assert!(!s.secret_bytes().is_empty());
    }

    #[test]
    fn full_enables_pgp() {
        use uselesskey::{PgpFactoryExt, PgpSpec};
        let fx = testutil::fx();
        let kp = fx.pgp("full-pgp-check", PgpSpec::ed25519());
        assert!(
            kp.public_key_armored()
                .contains("BEGIN PGP PUBLIC KEY BLOCK")
        );
    }

    #[test]
    fn full_enables_token() {
        use uselesskey::{TokenFactoryExt, TokenSpec};
        let fx = testutil::fx();
        let t = fx.token("full-token-check", TokenSpec::api_key());
        assert!(!t.value().is_empty());
    }

    #[test]
    fn full_enables_x509() {
        use uselesskey::{X509FactoryExt, X509Spec};
        let fx = testutil::fx();
        let cert =
            fx.x509_self_signed("full-x509-check", X509Spec::self_signed("full.example.com"));
        assert!(!cert.cert_der().is_empty());
    }

    #[test]
    fn full_enables_jwk_on_all_key_types() {
        use uselesskey::{
            EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, HmacFactoryExt, HmacSpec,
            RsaFactoryExt, RsaSpec,
        };
        let fx = testutil::fx();
        let rsa_kid = fx.rsa("full-jwk-r", RsaSpec::rs256()).kid();
        let ec_kid = fx.ecdsa("full-jwk-ec", EcdsaSpec::es256()).kid();
        let ed_kid = fx.ed25519("full-jwk-ed", Ed25519Spec::new()).kid();
        let hmac_kid = fx.hmac("full-jwk-h", HmacSpec::hs256()).kid();
        assert!(!rsa_kid.is_empty());
        assert!(!ec_kid.is_empty());
        assert!(!ed_kid.is_empty());
        assert!(!hmac_kid.is_empty());
    }
}

// ===========================================================================
// 24. Individual feature: PGP
// ===========================================================================

#[cfg(feature = "pgp")]
mod pgp_independent {
    use super::*;
    use uselesskey::{PgpFactoryExt, PgpKeyPair, PgpSpec};

    #[test]
    fn reexport_types_available() {
        let fx = testutil::fx();
        let _kp: PgpKeyPair = fx.pgp("pgp-reexport", PgpSpec::ed25519());
    }

    #[test]
    fn keygen_ed25519() {
        let fx = testutil::fx();
        let kp = fx.pgp("pgp-gen-ed", PgpSpec::ed25519());
        assert!(
            kp.public_key_armored()
                .contains("BEGIN PGP PUBLIC KEY BLOCK")
        );
        assert!(
            kp.private_key_armored()
                .contains("BEGIN PGP PRIVATE KEY BLOCK")
        );
        assert!(!kp.public_key_binary().is_empty());
        assert!(!kp.private_key_binary().is_empty());
    }

    #[test]
    fn keygen_rsa2048() {
        let fx = testutil::fx();
        let kp = fx.pgp("pgp-gen-rsa2048", PgpSpec::rsa_2048());
        assert!(
            kp.public_key_armored()
                .contains("BEGIN PGP PUBLIC KEY BLOCK")
        );
        assert!(!kp.fingerprint().is_empty());
    }

    #[test]
    fn keygen_rsa3072() {
        let fx = testutil::fx();
        let kp = fx.pgp("pgp-gen-rsa3072", PgpSpec::rsa_3072());
        assert!(
            kp.private_key_armored()
                .contains("BEGIN PGP PRIVATE KEY BLOCK")
        );
        assert!(!kp.fingerprint().is_empty());
    }

    #[test]
    fn deterministic_pgp_is_stable() {
        let seed = Seed::from_env_value("pgp-det-seed").unwrap();
        let fx1 = Factory::deterministic(seed);
        let fx2 = Factory::deterministic(seed);
        let k1 = fx1.pgp("det-pgp", PgpSpec::ed25519());
        let k2 = fx2.pgp("det-pgp", PgpSpec::ed25519());
        assert_eq!(k1.public_key_binary(), k2.public_key_binary());
        assert_eq!(k1.fingerprint(), k2.fingerprint());
    }

    #[test]
    fn negative_corrupt_armored() {
        use uselesskey::negative::CorruptPem;
        let fx = testutil::fx();
        let kp = fx.pgp("pgp-neg", PgpSpec::ed25519());
        let bad = kp.private_key_armored_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));
    }

    #[test]
    fn negative_truncated_binary() {
        let fx = testutil::fx();
        let kp = fx.pgp("pgp-trunc", PgpSpec::ed25519());
        let trunc = kp.private_key_binary_truncated(16);
        assert_eq!(trunc.len(), 16);
    }

    #[test]
    fn negative_mismatched_public_key() {
        let fx = testutil::fx();
        let kp = fx.pgp("pgp-mm", PgpSpec::ed25519());
        let mm = kp.mismatched_public_key_binary();
        assert_ne!(mm, kp.public_key_binary());
    }

    #[test]
    fn user_id_set() {
        let fx = testutil::fx();
        let kp = fx.pgp("pgp-uid", PgpSpec::ed25519());
        assert!(!kp.user_id().is_empty());
    }
}

// ===========================================================================
// 25. Feature pairs: PGP + other key types
// ===========================================================================

#[cfg(all(feature = "pgp", feature = "rsa"))]
mod pair_pgp_rsa {
    use super::*;
    use uselesskey::{PgpFactoryExt, PgpSpec, RsaFactoryExt, RsaSpec};

    #[test]
    fn pgp_and_rsa_from_same_factory() {
        let fx = testutil::fx();
        let pgp = fx.pgp("pair-pgp-rsa-p", PgpSpec::ed25519());
        let rsa = fx.rsa("pair-pgp-rsa-r", RsaSpec::rs256());
        assert!(!pgp.public_key_binary().is_empty());
        assert!(!rsa.public_key_spki_der().is_empty());
    }
}

#[cfg(all(feature = "pgp", feature = "ecdsa"))]
mod pair_pgp_ecdsa {
    use super::*;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec, PgpFactoryExt, PgpSpec};

    #[test]
    fn pgp_and_ecdsa_from_same_factory() {
        let fx = testutil::fx();
        let pgp = fx.pgp("pair-pgp-ec-p", PgpSpec::rsa_2048());
        let ec = fx.ecdsa("pair-pgp-ec-e", EcdsaSpec::es256());
        assert!(!pgp.fingerprint().is_empty());
        assert!(!ec.private_key_pkcs8_der().is_empty());
    }
}

// ===========================================================================
// 26. Explicit `rsa` feature
// ===========================================================================

/// Verify RSA remains available when consumers opt into the `rsa` feature.
#[cfg(feature = "rsa")]
mod explicit_rsa_feature {
    use super::*;
    use uselesskey::{RsaFactoryExt, RsaSpec};

    #[test]
    fn rsa_feature_provides_rsa() {
        let fx = testutil::fx();
        let kp = fx.rsa("default-rsa", RsaSpec::rs256());
        assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    }
}

// ===========================================================================
// 27. Adapter crate integration (dev-dependencies)
// ===========================================================================

/// Test that the `uselesskey-jsonwebtoken` adapter works with facade types.
/// The adapter is a dev-dependency, not a feature of the facade crate.
#[cfg(feature = "rsa")]
mod adapter_jsonwebtoken {
    use super::*;
    use uselesskey::{RsaFactoryExt, RsaSpec};
    use uselesskey_jsonwebtoken::JwtKeyExt;

    #[test]
    fn rsa_encoding_key() {
        let fx = testutil::fx();
        let kp = fx.rsa("jwt-rsa-enc", RsaSpec::rs256());
        let _enc = kp.encoding_key();
    }

    #[test]
    fn rsa_decoding_key() {
        let fx = testutil::fx();
        let kp = fx.rsa("jwt-rsa-dec", RsaSpec::rs256());
        let _dec = kp.decoding_key();
    }

    #[test]
    fn rsa_roundtrip_sign_verify() {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Serialize, Deserialize)]
        struct Claims {
            sub: String,
            exp: u64,
        }

        let fx = testutil::fx();
        let kp = fx.rsa("jwt-rsa-rt", RsaSpec::rs256());
        let enc = kp.encoding_key();
        let dec = kp.decoding_key();

        let claims = Claims {
            sub: "test".to_string(),
            exp: 9_999_999_999,
        };
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let token = jsonwebtoken::encode(&header, &claims, &enc).unwrap();

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        let decoded = jsonwebtoken::decode::<Claims>(&token, &dec, &validation)
            .expect("JWT should verify with matching keys");
        assert_eq!(decoded.claims.sub, "test");
    }
}

/// Test that the `uselesskey-jsonwebtoken` adapter works with ECDSA.
#[cfg(feature = "ecdsa")]
mod adapter_jsonwebtoken_ecdsa {
    use super::*;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_jsonwebtoken::JwtKeyExt;

    #[test]
    fn ecdsa_encoding_key() {
        let fx = testutil::fx();
        let kp = fx.ecdsa("jwt-ec-enc", EcdsaSpec::es256());
        let _enc = kp.encoding_key();
    }

    #[test]
    fn ecdsa_decoding_key() {
        let fx = testutil::fx();
        let kp = fx.ecdsa("jwt-ec-dec", EcdsaSpec::es256());
        let _dec = kp.decoding_key();
    }
}

/// Test that the `uselesskey-jsonwebtoken` adapter works with Ed25519.
#[cfg(feature = "ed25519")]
mod adapter_jsonwebtoken_ed25519 {
    use super::*;
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_jsonwebtoken::JwtKeyExt;

    #[test]
    fn ed25519_encoding_key() {
        let fx = testutil::fx();
        let kp = fx.ed25519("jwt-ed-enc", Ed25519Spec::new());
        let _enc = kp.encoding_key();
    }

    #[test]
    fn ed25519_decoding_key() {
        let fx = testutil::fx();
        let kp = fx.ed25519("jwt-ed-dec", Ed25519Spec::new());
        let _dec = kp.decoding_key();
    }
}

/// Test that the `uselesskey-jsonwebtoken` adapter works with HMAC.
#[cfg(feature = "hmac")]
mod adapter_jsonwebtoken_hmac {
    use super::*;
    use uselesskey::{HmacFactoryExt, HmacSpec};
    use uselesskey_jsonwebtoken::JwtKeyExt;

    #[test]
    fn hmac_encoding_key() {
        let fx = testutil::fx();
        let s = fx.hmac("jwt-hmac-enc", HmacSpec::hs256());
        let _enc = s.encoding_key();
    }

    #[test]
    fn hmac_decoding_key() {
        let fx = testutil::fx();
        let s = fx.hmac("jwt-hmac-dec", HmacSpec::hs256());
        let _dec = s.decoding_key();
    }
}

/// Test that the `uselesskey-rustls` adapter works with facade types.
#[cfg(feature = "rsa")]
mod adapter_rustls_rsa {
    use super::*;
    use uselesskey::{RsaFactoryExt, RsaSpec};
    use uselesskey_rustls::RustlsPrivateKeyExt;

    #[test]
    fn rsa_to_rustls_private_key() {
        let fx = testutil::fx();
        let kp = fx.rsa("rustls-rsa-pk", RsaSpec::rs256());
        let _pk: rustls_pki_types::PrivateKeyDer<'_> = kp.private_key_der_rustls();
    }
}

#[cfg(feature = "ecdsa")]
mod adapter_rustls_ecdsa {
    use super::*;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_rustls::RustlsPrivateKeyExt;

    #[test]
    fn ecdsa_to_rustls_private_key() {
        let fx = testutil::fx();
        let kp = fx.ecdsa("rustls-ec-pk", EcdsaSpec::es256());
        let _pk: rustls_pki_types::PrivateKeyDer<'_> = kp.private_key_der_rustls();
    }
}

#[cfg(feature = "ed25519")]
mod adapter_rustls_ed25519 {
    use super::*;
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_rustls::RustlsPrivateKeyExt;

    #[test]
    fn ed25519_to_rustls_private_key() {
        let fx = testutil::fx();
        let kp = fx.ed25519("rustls-ed-pk", Ed25519Spec::new());
        let _pk: rustls_pki_types::PrivateKeyDer<'_> = kp.private_key_der_rustls();
    }
}

/// Test that the rustls adapter works with X.509 certs.
#[cfg(feature = "x509")]
mod adapter_rustls_x509 {
    use super::*;
    use uselesskey::{X509FactoryExt, X509Spec};
    use uselesskey_rustls::{RustlsCertExt, RustlsPrivateKeyExt};

    #[test]
    fn x509_to_rustls_cert_and_key() {
        let fx = testutil::fx();
        let cert = fx.x509_self_signed("rustls-x509", X509Spec::self_signed("rustls.example.com"));
        let _cert_der: rustls_pki_types::CertificateDer<'_> = cert.certificate_der_rustls();
        let _pk: rustls_pki_types::PrivateKeyDer<'_> = cert.private_key_der_rustls();
    }
}

// ===========================================================================
// 28. JWK module gating
// ===========================================================================

/// The `jwk` feature gates the `uselesskey::jwk` module.
#[cfg(feature = "jwk")]
mod jwk_module_gating {
    #[test]
    fn jwk_module_accessible() {
        // The jwk module itself is available
        use uselesskey::jwk::JwksBuilder;
        let builder = JwksBuilder::new();
        let jwks = builder.build();
        let val = jwks.to_value();
        assert!(val["keys"].is_array());
        assert_eq!(val["keys"].as_array().unwrap().len(), 0);
    }
}

/// When jwk is enabled with multiple key types, JwksBuilder can combine them.
#[cfg(all(feature = "jwk", feature = "rsa", feature = "ecdsa"))]
mod jwk_multi_key_builder {
    use super::*;
    use uselesskey::jwk::JwksBuilder;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec, RsaFactoryExt, RsaSpec};

    #[test]
    fn jwks_builder_combines_algorithms() {
        let fx = testutil::fx();
        let rsa = fx.rsa("jwks-build-r", RsaSpec::rs256());
        let ec = fx.ecdsa("jwks-build-ec", EcdsaSpec::es256());

        let jwks = JwksBuilder::new()
            .add_public(rsa.public_jwk())
            .add_public(ec.public_jwk())
            .build();
        let val = jwks.to_value();
        let keys = val["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);

        let ktys: Vec<&str> = keys.iter().map(|k| k["kty"].as_str().unwrap()).collect();
        assert!(ktys.contains(&"RSA"));
        assert!(ktys.contains(&"EC"));
    }
}
