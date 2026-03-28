//! Feature-flag isolation tests for the `uselesskey` facade crate.
//!
//! These tests verify that each feature gate correctly controls type visibility,
//! trait availability, and domain constant re-exports. Each module compiles only
//! when its corresponding feature is active, proving the `#[cfg]` gates in
//! `lib.rs` work as intended.

mod testutil;

// ===========================================================================
// 1. Core types are always available (no feature flags required)
// ===========================================================================

mod core_always_available {
    use uselesskey::negative::CorruptPem;
    use uselesskey::{ArtifactDomain, DerivationVersion, Error, Factory, Mode, Seed, TempArtifact};

    fn generated_private_key_pem() -> String {
        #[cfg(feature = "rsa")]
        {
            use uselesskey::{RsaFactoryExt, RsaSpec};
            Factory::deterministic_from_str("feature-isolation-negative")
                .rsa("core-negative", RsaSpec::rs256())
                .private_key_pkcs8_pem()
                .to_owned()
        }

        #[cfg(not(feature = "rsa"))]
        {
            "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----\n".to_owned()
        }
    }

    #[test]
    fn factory_constructors() {
        let _random = Factory::random();

        let seed = Seed::from_env_value("isolation-core-seed").unwrap();
        let det = Factory::deterministic(seed);
        assert!(matches!(det.mode(), Mode::Deterministic { .. }));
    }

    #[test]
    fn seed_parsing() {
        let seed = Seed::from_env_value("any-string-is-valid").unwrap();
        let _fx = Factory::deterministic(seed);
    }

    #[test]
    fn negative_module_always_available() {
        let pem = generated_private_key_pem();
        let bad = uselesskey::negative::corrupt_pem(&pem, CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));
    }

    #[test]
    fn core_error_type_accessible() {
        let _: fn() -> Result<(), Error> = || Ok(());
    }

    #[test]
    fn artifact_id_types_accessible() {
        let _domain: ArtifactDomain = "test-domain";
        let _version: DerivationVersion = DerivationVersion::V1;
    }

    #[test]
    fn temp_artifact_type_accessible() {
        let _: fn() -> Option<TempArtifact> = || None;
    }
}

// ===========================================================================
// 2. RSA feature isolation
// ===========================================================================

#[cfg(feature = "rsa")]
mod rsa_isolation {
    use super::testutil;
    use uselesskey::{DOMAIN_RSA_KEYPAIR, RsaFactoryExt, RsaKeyPair, RsaSpec};

    #[test]
    fn domain_constant_re_exported() {
        assert!(!DOMAIN_RSA_KEYPAIR.is_empty());
    }

    #[test]
    fn extension_trait_adds_rsa_method() {
        let fx = testutil::fx();
        let kp: RsaKeyPair = fx.rsa("rsa-iso-trait", RsaSpec::rs256());
        assert!(!kp.private_key_pkcs8_der().is_empty());
    }

    #[test]
    fn rsa_spec_variants() {
        let fx = testutil::fx();
        let rs256 = fx.rsa("rsa-iso-2048", RsaSpec::rs256());
        let rs4096 = fx.rsa("rsa-iso-4096", RsaSpec::new(4096));

        // Different bit sizes produce distinct keys
        assert_ne!(
            rs256.private_key_pkcs8_der(),
            rs4096.private_key_pkcs8_der()
        );
    }

    #[test]
    fn rsa_output_formats() {
        let fx = testutil::fx();
        let kp = fx.rsa("rsa-iso-fmt", RsaSpec::rs256());

        assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(!kp.private_key_pkcs8_der().is_empty());
        assert!(kp.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
        assert!(!kp.public_key_spki_der().is_empty());
    }

    #[test]
    fn rsa_prelude_types() {
        use uselesskey::prelude::*;
        let fx = uselesskey::Factory::random();
        let _kp: RsaKeyPair = fx.rsa("rsa-iso-prelude", RsaSpec::rs256());
    }
}

// ===========================================================================
// 3. ECDSA feature isolation
// ===========================================================================

#[cfg(feature = "ecdsa")]
mod ecdsa_isolation {
    use super::testutil;
    use uselesskey::{DOMAIN_ECDSA_KEYPAIR, EcdsaFactoryExt, EcdsaKeyPair, EcdsaSpec};

    #[test]
    fn domain_constant_re_exported() {
        assert!(!DOMAIN_ECDSA_KEYPAIR.is_empty());
    }

    #[test]
    fn extension_trait_adds_ecdsa_method() {
        let fx = testutil::fx();
        let kp: EcdsaKeyPair = fx.ecdsa("ecdsa-iso-trait", EcdsaSpec::es256());
        assert!(!kp.private_key_pkcs8_der().is_empty());
    }

    #[test]
    fn ecdsa_curve_variants() {
        let fx = testutil::fx();
        let p256 = fx.ecdsa("ecdsa-iso-p256", EcdsaSpec::es256());
        let p384 = fx.ecdsa("ecdsa-iso-p384", EcdsaSpec::es384());

        assert_ne!(p256.private_key_pkcs8_der(), p384.private_key_pkcs8_der());
    }

    #[test]
    fn ecdsa_output_formats() {
        let fx = testutil::fx();
        let kp = fx.ecdsa("ecdsa-iso-fmt", EcdsaSpec::es256());

        assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(!kp.private_key_pkcs8_der().is_empty());
        assert!(kp.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
        assert!(!kp.public_key_spki_der().is_empty());
    }

    #[test]
    fn ecdsa_prelude_types() {
        use uselesskey::prelude::*;
        let fx = Factory::random();
        let _kp: EcdsaKeyPair = fx.ecdsa("ecdsa-iso-prelude", EcdsaSpec::es256());
    }
}

// ===========================================================================
// 4. Ed25519 feature isolation
// ===========================================================================

#[cfg(feature = "ed25519")]
mod ed25519_isolation {
    use super::testutil;
    use uselesskey::{DOMAIN_ED25519_KEYPAIR, Ed25519FactoryExt, Ed25519KeyPair, Ed25519Spec};

    #[test]
    fn domain_constant_re_exported() {
        assert!(!DOMAIN_ED25519_KEYPAIR.is_empty());
    }

    #[test]
    fn extension_trait_adds_ed25519_method() {
        let fx = testutil::fx();
        let kp: Ed25519KeyPair = fx.ed25519("ed25519-iso-trait", Ed25519Spec::new());
        assert!(!kp.private_key_pkcs8_der().is_empty());
    }

    #[test]
    fn ed25519_output_formats() {
        let fx = testutil::fx();
        let kp = fx.ed25519("ed25519-iso-fmt", Ed25519Spec::new());

        assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(!kp.private_key_pkcs8_der().is_empty());
        assert!(kp.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
        assert!(!kp.public_key_spki_der().is_empty());
    }

    #[test]
    fn ed25519_prelude_types() {
        use uselesskey::prelude::*;
        let fx = Factory::random();
        let _kp: Ed25519KeyPair = fx.ed25519("ed25519-iso-prelude", Ed25519Spec::new());
    }
}

// ===========================================================================
// 5. HMAC feature isolation
// ===========================================================================

#[cfg(feature = "hmac")]
mod hmac_isolation {
    use super::testutil;
    use uselesskey::{DOMAIN_HMAC_SECRET, HmacFactoryExt, HmacSecret, HmacSpec};

    #[test]
    fn domain_constant_re_exported() {
        assert!(!DOMAIN_HMAC_SECRET.is_empty());
    }

    #[test]
    fn extension_trait_adds_hmac_method() {
        let fx = testutil::fx();
        let s: HmacSecret = fx.hmac("hmac-iso-trait", HmacSpec::hs256());
        assert!(!s.secret_bytes().is_empty());
    }

    #[test]
    fn hmac_spec_variants() {
        let fx = testutil::fx();
        let hs256 = fx.hmac("hmac-iso-256", HmacSpec::hs256());
        let hs384 = fx.hmac("hmac-iso-384", HmacSpec::hs384());
        let hs512 = fx.hmac("hmac-iso-512", HmacSpec::hs512());

        assert_eq!(hs256.secret_bytes().len(), HmacSpec::hs256().byte_len());
        assert_eq!(hs384.secret_bytes().len(), HmacSpec::hs384().byte_len());
        assert_eq!(hs512.secret_bytes().len(), HmacSpec::hs512().byte_len());
    }

    #[test]
    fn hmac_prelude_types() {
        use uselesskey::prelude::*;
        let fx = Factory::random();
        let _s: HmacSecret = fx.hmac("hmac-iso-prelude", HmacSpec::hs256());
    }
}

// ===========================================================================
// 6. Token feature isolation
// ===========================================================================

#[cfg(feature = "token")]
mod token_isolation {
    use super::testutil;
    use uselesskey::{DOMAIN_TOKEN_FIXTURE, TokenFactoryExt, TokenFixture, TokenSpec};

    #[test]
    fn domain_constant_re_exported() {
        assert!(!DOMAIN_TOKEN_FIXTURE.is_empty());
    }

    #[test]
    fn extension_trait_adds_token_method() {
        let fx = testutil::fx();
        let t: TokenFixture = fx.token("token-iso-trait", TokenSpec::api_key());
        assert!(!t.value().is_empty());
    }

    #[test]
    fn token_spec_variants() {
        let fx = testutil::fx();
        let api = fx.token("token-iso-api", TokenSpec::api_key());
        let bearer = fx.token("token-iso-bearer", TokenSpec::bearer());
        let oauth = fx.token("token-iso-oauth", TokenSpec::oauth_access_token());

        assert!(api.value().starts_with("uk_test_"));
        assert!(bearer.authorization_header().starts_with("Bearer "));
        // OAuth tokens have 3 dot-separated segments (JWT-shaped)
        assert_eq!(oauth.value().split('.').count(), 3);
    }

    #[test]
    fn token_prelude_types() {
        use uselesskey::prelude::*;
        let fx = Factory::random();
        let _t: TokenFixture = fx.token("token-iso-prelude", TokenSpec::api_key());
    }
}

// ===========================================================================
// 7. X.509 feature isolation (implies rsa)
// ===========================================================================

#[cfg(feature = "x509")]
mod x509_isolation {
    use super::testutil;
    use uselesskey::{
        ChainNegative, ChainSpec, DOMAIN_X509_CERT, DOMAIN_X509_CHAIN, KeyUsage, X509Cert,
        X509FactoryExt, X509Negative, X509Spec,
    };

    #[test]
    fn domain_constants_re_exported() {
        assert!(!DOMAIN_X509_CERT.is_empty());
        assert!(!DOMAIN_X509_CHAIN.is_empty());
    }

    #[test]
    fn extension_trait_adds_x509_method() {
        let fx = testutil::fx();
        let cert: X509Cert =
            fx.x509_self_signed("x509-iso-trait", X509Spec::self_signed("iso.example.com"));
        assert!(!cert.cert_der().is_empty());
    }

    #[test]
    fn x509_enables_rsa_transitively() {
        // x509 implies rsa, so RSA types must be available
        use uselesskey::{RsaFactoryExt, RsaKeyPair, RsaSpec};
        let fx = testutil::fx();
        let _kp: RsaKeyPair = fx.rsa("x509-iso-rsa-transitive", RsaSpec::rs256());
    }

    #[test]
    fn x509_output_formats() {
        let fx = testutil::fx();
        let cert = fx.x509_self_signed("x509-iso-fmt", X509Spec::self_signed("fmt.example.com"));

        assert!(cert.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(!cert.cert_der().is_empty());
        assert!(!cert.private_key_pkcs8_der().is_empty());
    }

    #[test]
    fn x509_negative_types_accessible() {
        // Verify negative fixture types compile
        let _: fn() -> Option<X509Negative> = || None;
        let _: fn() -> Option<ChainNegative> = || None;
    }

    #[test]
    fn x509_spec_types_accessible() {
        let _: fn() -> Option<ChainSpec> = || None;
        let _: fn() -> Option<KeyUsage> = || None;
    }

    #[test]
    fn x509_prelude_types() {
        use uselesskey::prelude::*;
        let fx = Factory::random();
        let _c: X509Cert = fx.x509_self_signed(
            "x509-iso-prelude",
            X509Spec::self_signed("prelude.example.com"),
        );
    }
}

// ===========================================================================
// 8. PGP feature isolation
// ===========================================================================

#[cfg(feature = "pgp")]
mod pgp_isolation {
    use super::testutil;
    use uselesskey::{DOMAIN_PGP_KEYPAIR, PgpFactoryExt, PgpKeyPair, PgpSpec};

    #[test]
    fn domain_constant_re_exported() {
        assert!(!DOMAIN_PGP_KEYPAIR.is_empty());
    }

    #[test]
    fn extension_trait_adds_pgp_method() {
        let fx = testutil::fx();
        let kp: PgpKeyPair = fx.pgp("pgp-iso-trait", PgpSpec::ed25519());
        assert!(!kp.public_key_binary().is_empty());
    }

    #[test]
    fn pgp_output_formats() {
        let fx = testutil::fx();
        let kp = fx.pgp("pgp-iso-fmt", PgpSpec::ed25519());

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
        assert!(!kp.fingerprint().is_empty());
    }

    #[test]
    fn pgp_prelude_types() {
        use uselesskey::prelude::*;
        let fx = Factory::random();
        let _kp: PgpKeyPair = fx.pgp("pgp-iso-prelude", PgpSpec::ed25519());
    }
}

// ===========================================================================
// 9. JWK feature isolation
// ===========================================================================

#[cfg(feature = "jwk")]
mod jwk_isolation {
    #[test]
    fn jwk_module_accessible() {
        use uselesskey::jwk::JwksBuilder;
        let jwks = JwksBuilder::new().build();
        let val = jwks.to_value();
        assert!(val["keys"].as_array().unwrap().is_empty());
    }
}

// ===========================================================================
// 10. Feature combinations: RSA + ECDSA
// ===========================================================================

#[cfg(all(feature = "rsa", feature = "ecdsa"))]
mod combo_rsa_ecdsa {
    use super::testutil;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec, RsaFactoryExt, RsaSpec};

    #[test]
    fn both_traits_on_same_factory() {
        let fx = testutil::fx();
        let rsa = fx.rsa("combo-re-rsa", RsaSpec::rs256());
        let ec = fx.ecdsa("combo-re-ec", EcdsaSpec::es256());

        assert!(rsa.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(ec.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert_ne!(rsa.private_key_pkcs8_der(), ec.private_key_pkcs8_der());
    }
}

// ===========================================================================
// 11. Feature combinations: RSA + Ed25519 + HMAC
// ===========================================================================

#[cfg(all(feature = "rsa", feature = "ed25519", feature = "hmac"))]
mod combo_rsa_ed25519_hmac {
    use super::testutil;
    use uselesskey::{
        Ed25519FactoryExt, Ed25519Spec, Factory, HmacFactoryExt, HmacSpec, RsaFactoryExt, RsaSpec,
        Seed,
    };

    #[test]
    fn three_types_from_single_factory() {
        let fx = testutil::fx();
        let rsa = fx.rsa("combo-reh-rsa", RsaSpec::rs256());
        let ed = fx.ed25519("combo-reh-ed", Ed25519Spec::new());
        let hmac = fx.hmac("combo-reh-hmac", HmacSpec::hs256());

        assert!(!rsa.private_key_pkcs8_der().is_empty());
        assert!(!ed.private_key_pkcs8_der().is_empty());
        assert!(!hmac.secret_bytes().is_empty());
    }

    #[test]
    fn deterministic_order_independence_across_three() {
        let seed = Seed::from_env_value("combo-reh-seed").unwrap();

        let fx1 = Factory::deterministic(seed);
        let rsa1 = fx1.rsa("combo-oi-rsa", RsaSpec::rs256());
        let ed1 = fx1.ed25519("combo-oi-ed", Ed25519Spec::new());
        let hmac1 = fx1.hmac("combo-oi-hmac", HmacSpec::hs256());

        let fx2 = Factory::deterministic(seed);
        // Reverse order
        let hmac2 = fx2.hmac("combo-oi-hmac", HmacSpec::hs256());
        let ed2 = fx2.ed25519("combo-oi-ed", Ed25519Spec::new());
        let rsa2 = fx2.rsa("combo-oi-rsa", RsaSpec::rs256());

        assert_eq!(rsa1.private_key_pkcs8_pem(), rsa2.private_key_pkcs8_pem());
        assert_eq!(ed1.private_key_pkcs8_pem(), ed2.private_key_pkcs8_pem());
        assert_eq!(hmac1.secret_bytes(), hmac2.secret_bytes());
    }
}

// ===========================================================================
// 12. Feature combinations: ECDSA + Token
// ===========================================================================

#[cfg(all(feature = "ecdsa", feature = "token"))]
mod combo_ecdsa_token {
    use super::testutil;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec, TokenFactoryExt, TokenSpec};

    #[test]
    fn asymmetric_and_token_coexist() {
        let fx = testutil::fx();
        let ec = fx.ecdsa("combo-et-ec", EcdsaSpec::es256());
        let tok = fx.token("combo-et-tok", TokenSpec::bearer());

        assert!(!ec.private_key_pkcs8_der().is_empty());
        assert!(!tok.value().is_empty());
    }
}

// ===========================================================================
// 13. All features enabled
// ===========================================================================

#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "hmac",
    feature = "token",
    feature = "pgp",
    feature = "x509",
    feature = "jwk",
))]
mod all_features {
    use super::testutil;
    use uselesskey::{
        EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, HmacFactoryExt, HmacSpec,
        PgpFactoryExt, PgpSpec, RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec, X509FactoryExt,
        X509Spec,
    };

    #[test]
    fn every_extension_trait_on_single_factory() {
        let fx = testutil::fx();

        let rsa = fx.rsa("all-iso-rsa", RsaSpec::rs256());
        let ec = fx.ecdsa("all-iso-ec", EcdsaSpec::es256());
        let ed = fx.ed25519("all-iso-ed", Ed25519Spec::new());
        let hmac = fx.hmac("all-iso-hmac", HmacSpec::hs256());
        let tok = fx.token("all-iso-tok", TokenSpec::api_key());
        let pgp = fx.pgp("all-iso-pgp", PgpSpec::ed25519());
        let cert = fx.x509_self_signed("all-iso-x509", X509Spec::self_signed("all.example.com"));

        assert!(!rsa.private_key_pkcs8_der().is_empty());
        assert!(!ec.private_key_pkcs8_der().is_empty());
        assert!(!ed.private_key_pkcs8_der().is_empty());
        assert!(!hmac.secret_bytes().is_empty());
        assert!(!tok.value().is_empty());
        assert!(!pgp.public_key_binary().is_empty());
        assert!(!cert.cert_der().is_empty());
    }

    #[test]
    fn jwk_output_for_all_asymmetric_types() {
        let fx = testutil::fx();

        let rsa_jwk = fx
            .rsa("all-iso-jwk-rsa", RsaSpec::rs256())
            .public_jwk()
            .to_value();
        let ec_jwk = fx
            .ecdsa("all-iso-jwk-ec", EcdsaSpec::es256())
            .public_jwk()
            .to_value();
        let ed_jwk = fx
            .ed25519("all-iso-jwk-ed", Ed25519Spec::new())
            .public_jwk()
            .to_value();
        let hmac_jwk = fx
            .hmac("all-iso-jwk-hmac", HmacSpec::hs256())
            .jwk()
            .to_value();

        assert_eq!(rsa_jwk["kty"], "RSA");
        assert_eq!(ec_jwk["kty"], "EC");
        assert_eq!(ed_jwk["kty"], "OKP");
        assert_eq!(hmac_jwk["kty"], "oct");
    }

    #[test]
    fn negative_fixtures_across_all_asymmetric() {
        use uselesskey::negative::CorruptPem;
        let fx = testutil::fx();

        let rsa = fx.rsa("all-iso-neg-rsa", RsaSpec::rs256());
        let ec = fx.ecdsa("all-iso-neg-ec", EcdsaSpec::es256());
        let ed = fx.ed25519("all-iso-neg-ed", Ed25519Spec::new());

        // Corrupt PEM works for each type
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

        // Mismatched public keys
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
// 14. Explicit `rsa` feature — core + rsa should compile
// ===========================================================================

#[cfg(feature = "rsa")]
mod explicit_rsa_feature {
    use super::testutil;
    use uselesskey::{Factory, Mode, RsaFactoryExt, RsaSpec, Seed};

    #[test]
    fn rsa_feature_provides_factory_and_rsa() {
        let fx = testutil::fx();
        let kp = fx.rsa("default-iso-rsa", RsaSpec::rs256());
        assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn rsa_feature_deterministic_works() {
        let seed = Seed::from_env_value("default-iso-seed").unwrap();
        let fx = Factory::deterministic(seed);
        assert!(matches!(fx.mode(), Mode::Deterministic { .. }));
        let kp = fx.rsa("default-iso-det", RsaSpec::rs256());
        assert!(!kp.private_key_pkcs8_der().is_empty());
    }
}
