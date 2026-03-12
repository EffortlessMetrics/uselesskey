//! API surface stability and smoke tests.
//!
//! These tests verify that key public traits, types, methods, and negative
//! fixture helpers remain importable and functional. They act as a compile-time
//! and runtime guard against accidental API breakage.

// ---------------------------------------------------------------------------
// 1. Traits are importable and can be used via Factory
// ---------------------------------------------------------------------------

#[test]
fn factory_random_creates_factory() {
    let fx = uselesskey_core::Factory::random();
    assert!(matches!(fx.mode(), uselesskey_core::Mode::Random));
}

#[test]
fn factory_deterministic_creates_factory() {
    let seed = uselesskey_core::Seed::new([0xAA; 32]);
    let fx = uselesskey_core::Factory::deterministic(seed);
    assert!(matches!(
        fx.mode(),
        uselesskey_core::Mode::Deterministic { .. }
    ));
}

#[test]
fn factory_deterministic_from_env_value() {
    let seed = uselesskey_core::Seed::from_env_value("api-surface-test").unwrap();
    let fx = uselesskey_core::Factory::deterministic(seed);
    assert!(matches!(
        fx.mode(),
        uselesskey_core::Mode::Deterministic { .. }
    ));
}

#[test]
fn factory_deterministic_from_str_value() {
    let fx = uselesskey_core::Factory::deterministic_from_str("api-surface-test");
    assert!(matches!(
        fx.mode(),
        uselesskey_core::Mode::Deterministic { .. }
    ));
}

// ---------------------------------------------------------------------------
// 2. RSA surface
// ---------------------------------------------------------------------------

#[cfg(feature = "api-surface")]
mod rsa_surface {
    use uselesskey_core::Factory;
    use uselesskey_rsa::{RsaFactoryExt, RsaKeyPair, RsaSpec};

    fn fx() -> Factory {
        Factory::deterministic(uselesskey_core::Seed::new([0x01; 32]))
    }

    #[test]
    fn rsa_spec_constructors() {
        let s = RsaSpec::rs256();
        assert_eq!(s.bits, 2048);
        assert_eq!(s.exponent, 65537);

        let s4k = RsaSpec::new(4096);
        assert_eq!(s4k.bits, 4096);
    }

    #[test]
    fn rsa_keypair_output_methods() {
        let kp: RsaKeyPair = fx().rsa("surface", RsaSpec::rs256());

        assert!(
            kp.private_key_pkcs8_pem()
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
        assert!(!kp.private_key_pkcs8_der().is_empty());
        assert!(
            kp.public_key_spki_pem()
                .starts_with("-----BEGIN PUBLIC KEY-----")
        );
        assert!(!kp.public_key_spki_der().is_empty());
    }

    #[test]
    fn rsa_keypair_tempfile_methods() {
        let kp = fx().rsa("surface-tmp", RsaSpec::rs256());

        let tmp_priv = kp.write_private_key_pkcs8_pem().unwrap();
        assert!(tmp_priv.path().exists());
        let tmp_pub = kp.write_public_key_spki_pem().unwrap();
        assert!(tmp_pub.path().exists());
    }

    #[test]
    fn rsa_negative_corrupt_pem() {
        use uselesskey_core::negative::CorruptPem;

        let kp = fx().rsa("surface-neg", RsaSpec::rs256());
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));
    }

    #[test]
    fn rsa_negative_truncated_der() {
        let kp = fx().rsa("surface-trunc", RsaSpec::rs256());
        let trunc = kp.private_key_pkcs8_der_truncated(10);
        assert_eq!(trunc.len(), 10);
    }

    #[test]
    fn rsa_negative_mismatch() {
        let kp = fx().rsa("surface-mm", RsaSpec::rs256());
        let mm = kp.mismatched_public_key_spki_der();
        assert_ne!(mm, kp.public_key_spki_der());
    }

    #[test]
    fn rsa_jwk_surface() {
        let kp = fx().rsa("surface-jwk", RsaSpec::rs256());

        let kid = kp.kid();
        assert!(!kid.is_empty());

        let pub_jwk = kp.public_jwk();
        let val = pub_jwk.to_value();
        assert_eq!(val["kty"], "RSA");
        assert_eq!(val["alg"], "RS256");

        let priv_jwk = kp.private_key_jwk();
        let pval = priv_jwk.to_value();
        assert_eq!(pval["kty"], "RSA");
        assert!(pval["d"].is_string());

        let jwks = kp.public_jwks();
        assert!(jwks.to_value()["keys"].is_array());
    }

    #[test]
    fn rsa_debug_does_not_leak_key_material() {
        let kp = fx().rsa("surface-dbg", RsaSpec::rs256());
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("RsaKeyPair"));
        assert!(!dbg.contains("BEGIN PRIVATE KEY"));
    }
}

// ---------------------------------------------------------------------------
// 3. ECDSA surface
// ---------------------------------------------------------------------------

#[cfg(feature = "api-surface")]
mod ecdsa_surface {
    use uselesskey_core::Factory;
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaKeyPair, EcdsaSpec};

    fn fx() -> Factory {
        Factory::deterministic(uselesskey_core::Seed::new([0x02; 32]))
    }

    #[test]
    fn ecdsa_spec_constructors() {
        let es256 = EcdsaSpec::es256();
        assert_eq!(es256.alg_name(), "ES256");
        assert_eq!(es256.curve_name(), "P-256");

        let es384 = EcdsaSpec::es384();
        assert_eq!(es384.alg_name(), "ES384");
        assert_eq!(es384.curve_name(), "P-384");
    }

    #[test]
    fn ecdsa_keypair_output_methods() {
        let kp: EcdsaKeyPair = fx().ecdsa("surface", EcdsaSpec::es256());

        assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(!kp.private_key_pkcs8_der().is_empty());
        assert!(kp.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
        assert!(!kp.public_key_spki_der().is_empty());
    }

    #[test]
    fn ecdsa_negative_methods() {
        use uselesskey_core::negative::CorruptPem;

        let kp = fx().ecdsa("surface-neg", EcdsaSpec::es256());
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));

        let trunc = kp.private_key_pkcs8_der_truncated(5);
        assert_eq!(trunc.len(), 5);

        let mm = kp.mismatched_public_key_spki_der();
        assert_ne!(mm, kp.public_key_spki_der());
    }

    #[test]
    fn ecdsa_debug_does_not_leak() {
        let kp = fx().ecdsa("surface-dbg", EcdsaSpec::es256());
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("EcdsaKeyPair"));
        assert!(!dbg.contains("BEGIN PRIVATE KEY"));
    }
}

// ---------------------------------------------------------------------------
// 4. Ed25519 surface
// ---------------------------------------------------------------------------

#[cfg(feature = "api-surface")]
mod ed25519_surface {
    use uselesskey_core::Factory;
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519KeyPair, Ed25519Spec};

    fn fx() -> Factory {
        Factory::deterministic(uselesskey_core::Seed::new([0x03; 32]))
    }

    #[test]
    fn ed25519_spec_constructors() {
        let spec = Ed25519Spec::new();
        assert_eq!(spec, Ed25519Spec::default());
    }

    #[test]
    fn ed25519_keypair_output_methods() {
        let kp: Ed25519KeyPair = fx().ed25519("surface", Ed25519Spec::new());

        assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(!kp.private_key_pkcs8_der().is_empty());
        assert!(kp.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
        assert!(!kp.public_key_spki_der().is_empty());
    }

    #[test]
    fn ed25519_negative_methods() {
        use uselesskey_core::negative::CorruptPem;

        let kp = fx().ed25519("surface-neg", Ed25519Spec::new());
        let bad = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));

        let trunc = kp.private_key_pkcs8_der_truncated(5);
        assert_eq!(trunc.len(), 5);

        let mm = kp.mismatched_public_key_spki_der();
        assert_ne!(mm, kp.public_key_spki_der());
    }

    #[test]
    fn ed25519_debug_does_not_leak() {
        let kp = fx().ed25519("surface-dbg", Ed25519Spec::new());
        let dbg = format!("{kp:?}");
        assert!(dbg.contains("Ed25519KeyPair"));
        assert!(!dbg.contains("BEGIN PRIVATE KEY"));
    }
}

// ---------------------------------------------------------------------------
// 5. HMAC surface
// ---------------------------------------------------------------------------

#[cfg(feature = "api-surface")]
mod hmac_surface {
    use uselesskey_core::Factory;
    use uselesskey_hmac::{HmacFactoryExt, HmacSecret, HmacSpec};

    fn fx() -> Factory {
        Factory::deterministic(uselesskey_core::Seed::new([0x04; 32]))
    }

    #[test]
    fn hmac_spec_constructors() {
        let _hs256 = HmacSpec::hs256();
        let _hs384 = HmacSpec::hs384();
        let _hs512 = HmacSpec::hs512();
    }

    #[test]
    fn hmac_secret_output_methods() {
        let s: HmacSecret = fx().hmac("surface", HmacSpec::hs256());
        assert_eq!(s.secret_bytes().len(), 32);

        let s512 = fx().hmac("surface-512", HmacSpec::hs512());
        assert_eq!(s512.secret_bytes().len(), 64);
    }

    #[test]
    fn hmac_jwk_surface() {
        let s = fx().hmac("surface-jwk", HmacSpec::hs256());
        let kid = s.kid();
        assert!(!kid.is_empty());

        let jwk = s.jwk();
        let val = jwk.to_value();
        assert_eq!(val["kty"], "oct");
        assert_eq!(val["alg"], "HS256");

        let jwks = s.jwks();
        assert!(jwks.to_value()["keys"].is_array());
    }

    #[test]
    fn hmac_debug_does_not_leak() {
        let s = fx().hmac("surface-dbg", HmacSpec::hs256());
        let dbg = format!("{s:?}");
        assert!(dbg.contains("HmacSecret"));
        assert!(!dbg.contains("secret_bytes"));
    }
}

// ---------------------------------------------------------------------------
// 6. Token surface
// ---------------------------------------------------------------------------

#[cfg(feature = "api-surface")]
mod token_surface {
    use uselesskey_core::Factory;
    use uselesskey_token::{TokenFactoryExt, TokenFixture, TokenSpec};

    fn fx() -> Factory {
        Factory::deterministic(uselesskey_core::Seed::new([0x05; 32]))
    }

    #[test]
    fn token_spec_constructors() {
        let _api = TokenSpec::api_key();
        let _bearer = TokenSpec::bearer();
        let _oauth = TokenSpec::oauth_access_token();
    }

    #[test]
    fn token_fixture_output_methods() {
        let t: TokenFixture = fx().token("surface", TokenSpec::api_key());
        assert!(t.value().starts_with("uk_test_"));

        let bearer = fx().token("surface-bearer", TokenSpec::bearer());
        assert!(!bearer.value().is_empty());
        assert!(bearer.authorization_header().starts_with("Bearer "));
    }

    #[test]
    fn token_with_variant() {
        let good = fx().token("svc", TokenSpec::api_key());
        let alt = fx().token_with_variant("svc", TokenSpec::api_key(), "alt");
        assert_ne!(good.value(), alt.value());
    }

    #[test]
    fn token_debug_does_not_leak() {
        let t = fx().token("surface-dbg", TokenSpec::api_key());
        let dbg = format!("{t:?}");
        assert!(dbg.contains("TokenFixture"));
        assert!(!dbg.contains(t.value()));
    }
}

// ---------------------------------------------------------------------------
// 7. X.509 surface
// ---------------------------------------------------------------------------

#[cfg(feature = "api-surface")]
mod x509_surface {
    use uselesskey_core::Factory;
    use uselesskey_x509::{ChainSpec, X509Cert, X509FactoryExt, X509Spec};

    fn fx() -> Factory {
        Factory::deterministic(uselesskey_core::Seed::new([0x06; 32]))
    }

    #[test]
    fn x509_spec_constructors() {
        let _spec = X509Spec::self_signed("test.example.com");
    }

    #[test]
    fn x509_cert_output_methods() {
        let cert: X509Cert = fx().x509_self_signed("surface", X509Spec::self_signed("test.local"));

        assert!(cert.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(!cert.cert_der().is_empty());
        assert!(cert.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
        assert!(!cert.private_key_pkcs8_der().is_empty());
        assert!(!cert.identity_pem().is_empty());
    }

    #[test]
    fn x509_cert_tempfile_methods() {
        let cert = fx().x509_self_signed("surface-tmp", X509Spec::self_signed("test.local"));

        assert!(cert.write_cert_pem().unwrap().path().exists());
        assert!(cert.write_cert_der().unwrap().path().exists());
        assert!(cert.write_private_key_pem().unwrap().path().exists());
        assert!(cert.write_identity_pem().unwrap().path().exists());
    }

    #[test]
    fn x509_negative_expired() {
        let cert = fx().x509_self_signed("surface-exp", X509Spec::self_signed("test.local"));
        let expired = cert.expired();
        assert!(expired.cert_pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn x509_negative_not_yet_valid() {
        let cert = fx().x509_self_signed("surface-nyv", X509Spec::self_signed("test.local"));
        let nyv = cert.not_yet_valid();
        assert!(nyv.cert_pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn x509_negative_corrupt_pem() {
        use uselesskey_core::negative::CorruptPem;

        let cert = fx().x509_self_signed("surface-corrupt", X509Spec::self_signed("test.local"));
        let bad = cert.corrupt_cert_pem(CorruptPem::BadHeader);
        assert!(bad.contains("CORRUPTED"));
    }

    #[test]
    fn x509_chain_surface() {
        let chain = fx().x509_chain("surface-chain", ChainSpec::new("test.local"));
        assert!(chain.leaf_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(chain.root_cert_pem().contains("BEGIN CERTIFICATE"));
        // chain_pem has leaf + intermediate = 2 certs
        let chain_pem = chain.chain_pem();
        assert!(chain_pem.matches("BEGIN CERTIFICATE").count() >= 2);
    }

    #[test]
    fn x509_debug_does_not_leak() {
        let cert = fx().x509_self_signed("surface-dbg", X509Spec::self_signed("test.local"));
        let dbg = format!("{cert:?}");
        assert!(dbg.contains("X509Cert"));
        assert!(!dbg.contains("BEGIN PRIVATE KEY"));
    }
}

// ---------------------------------------------------------------------------
// 8. Snapshot tests for API "shape" (insta)
// ---------------------------------------------------------------------------

#[cfg(feature = "api-surface")]
mod api_shape_snapshots {
    use insta::assert_snapshot;

    /// Capture the public API shape of key types and their method signatures.
    /// If any of these change, the snapshot must be intentionally updated.
    #[test]
    fn core_types_shape() {
        let shape = [
            "Factory::random() -> Factory",
            "Factory::deterministic(Seed) -> Factory",
            "Factory::deterministic_from_str(&str) -> Factory",
            "Factory::deterministic_from_env(&str) -> Result<Factory, Error>",
            "Factory::mode() -> &Mode",
            "Factory::clear_cache()",
            "Mode::Random",
            "Mode::Deterministic { master: Seed }",
            "Seed::new([u8; 32]) -> Seed",
            "Seed::from_text(&str) -> Seed",
            "Seed::from_env_value(&str) -> Result<Seed, String>",
        ]
        .join("\n");
        assert_snapshot!("core_types_shape", shape);
    }

    #[test]
    fn rsa_api_shape() {
        let shape = [
            "RsaFactoryExt::rsa(&self, label, RsaSpec) -> RsaKeyPair",
            "RsaSpec::rs256() -> RsaSpec",
            "RsaSpec::new(bits) -> RsaSpec",
            "RsaSpec { bits: usize, exponent: u32 }",
            "RsaKeyPair::private_key_pkcs8_pem() -> &str",
            "RsaKeyPair::private_key_pkcs8_der() -> &[u8]",
            "RsaKeyPair::public_key_spki_pem() -> &str",
            "RsaKeyPair::public_key_spki_der() -> &[u8]",
            "RsaKeyPair::write_private_key_pkcs8_pem() -> Result<TempArtifact, Error>",
            "RsaKeyPair::write_public_key_spki_pem() -> Result<TempArtifact, Error>",
            "RsaKeyPair::private_key_pkcs8_pem_corrupt(CorruptPem) -> String",
            "RsaKeyPair::private_key_pkcs8_der_truncated(usize) -> Vec<u8>",
            "RsaKeyPair::mismatched_public_key_spki_der() -> Vec<u8>",
            "RsaKeyPair::kid() -> String [jwk]",
            "RsaKeyPair::public_jwk() -> PublicJwk [jwk]",
            "RsaKeyPair::private_key_jwk() -> PrivateJwk [jwk]",
            "RsaKeyPair::public_jwks() -> Jwks [jwk]",
        ]
        .join("\n");
        assert_snapshot!("rsa_api_shape", shape);
    }

    #[test]
    fn ecdsa_api_shape() {
        let shape = [
            "EcdsaFactoryExt::ecdsa(&self, label, EcdsaSpec) -> EcdsaKeyPair",
            "EcdsaSpec::es256() -> EcdsaSpec",
            "EcdsaSpec::es384() -> EcdsaSpec",
            "EcdsaSpec::alg_name() -> &str",
            "EcdsaSpec::curve_name() -> &str",
            "EcdsaKeyPair::private_key_pkcs8_pem() -> &str",
            "EcdsaKeyPair::private_key_pkcs8_der() -> &[u8]",
            "EcdsaKeyPair::public_key_spki_pem() -> &str",
            "EcdsaKeyPair::public_key_spki_der() -> &[u8]",
            "EcdsaKeyPair::private_key_pkcs8_pem_corrupt(CorruptPem) -> String",
            "EcdsaKeyPair::private_key_pkcs8_der_truncated(usize) -> Vec<u8>",
            "EcdsaKeyPair::mismatched_public_key_spki_der() -> Vec<u8>",
        ]
        .join("\n");
        assert_snapshot!("ecdsa_api_shape", shape);
    }

    #[test]
    fn ed25519_api_shape() {
        let shape = [
            "Ed25519FactoryExt::ed25519(&self, label, Ed25519Spec) -> Ed25519KeyPair",
            "Ed25519Spec::new() -> Ed25519Spec",
            "Ed25519Spec::default() -> Ed25519Spec",
            "Ed25519KeyPair::private_key_pkcs8_pem() -> &str",
            "Ed25519KeyPair::private_key_pkcs8_der() -> &[u8]",
            "Ed25519KeyPair::public_key_spki_pem() -> &str",
            "Ed25519KeyPair::public_key_spki_der() -> &[u8]",
            "Ed25519KeyPair::private_key_pkcs8_pem_corrupt(CorruptPem) -> String",
            "Ed25519KeyPair::private_key_pkcs8_der_truncated(usize) -> Vec<u8>",
            "Ed25519KeyPair::mismatched_public_key_spki_der() -> Vec<u8>",
        ]
        .join("\n");
        assert_snapshot!("ed25519_api_shape", shape);
    }

    #[test]
    fn hmac_api_shape() {
        let shape = [
            "HmacFactoryExt::hmac(&self, label, HmacSpec) -> HmacSecret",
            "HmacSpec::hs256() -> HmacSpec",
            "HmacSpec::hs384() -> HmacSpec",
            "HmacSpec::hs512() -> HmacSpec",
            "HmacSecret::secret_bytes() -> &[u8]",
            "HmacSecret::kid() -> String [jwk]",
            "HmacSecret::jwk() -> PrivateJwk [jwk]",
            "HmacSecret::jwks() -> Jwks [jwk]",
        ]
        .join("\n");
        assert_snapshot!("hmac_api_shape", shape);
    }

    #[test]
    fn token_api_shape() {
        let shape = [
            "TokenFactoryExt::token(&self, label, TokenSpec) -> TokenFixture",
            "TokenFactoryExt::token_with_variant(&self, label, TokenSpec, variant) -> TokenFixture",
            "TokenSpec::api_key() -> TokenSpec",
            "TokenSpec::bearer() -> TokenSpec",
            "TokenSpec::oauth_access_token() -> TokenSpec",
            "TokenFixture::value() -> &str",
            "TokenFixture::authorization_header() -> String",
        ]
        .join("\n");
        assert_snapshot!("token_api_shape", shape);
    }

    #[test]
    fn x509_api_shape() {
        let shape = [
            "X509FactoryExt::x509_self_signed(&self, label, X509Spec) -> X509Cert",
            "X509FactoryExt::x509_chain(&self, label, ChainSpec) -> X509Chain",
            "X509Spec::self_signed(cn) -> X509Spec",
            "ChainSpec::new(cn) -> ChainSpec",
            "X509Cert::cert_pem() -> &str",
            "X509Cert::cert_der() -> &[u8]",
            "X509Cert::private_key_pkcs8_pem() -> &str",
            "X509Cert::private_key_pkcs8_der() -> &[u8]",
            "X509Cert::identity_pem() -> String",
            "X509Cert::write_cert_pem() -> Result<TempArtifact, Error>",
            "X509Cert::write_cert_der() -> Result<TempArtifact, Error>",
            "X509Cert::write_private_key_pem() -> Result<TempArtifact, Error>",
            "X509Cert::write_identity_pem() -> Result<TempArtifact, Error>",
            "X509Cert::corrupt_cert_pem(CorruptPem) -> String",
            "X509Cert::expired() -> X509Cert",
            "X509Cert::not_yet_valid() -> X509Cert",
            "X509Chain::leaf_cert_pem() -> &str",
            "X509Chain::root_cert_pem() -> &str",
            "X509Chain::chain_pem() -> String",
        ]
        .join("\n");
        assert_snapshot!("x509_api_shape", shape);
    }

    #[test]
    fn negative_fixtures_shape() {
        let shape = [
            "CorruptPem::BadHeader",
            "CorruptPem::BadFooter",
            "CorruptPem::BadBase64",
            "CorruptPem::Truncate { bytes: usize }",
            "CorruptPem::ExtraBlankLine",
        ]
        .join("\n");
        assert_snapshot!("negative_fixtures_shape", shape);
    }
}

// ---------------------------------------------------------------------------
// 9. Cross-type smoke test: all key types from a single deterministic factory
// ---------------------------------------------------------------------------

#[cfg(feature = "api-surface")]
#[test]
fn all_key_types_from_single_factory() {
    use uselesskey_core::{Factory, Seed};
    use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
    use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
    use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
    use uselesskey_rsa::{RsaFactoryExt, RsaSpec};
    use uselesskey_token::{TokenFactoryExt, TokenSpec};
    use uselesskey_x509::{X509FactoryExt, X509Spec};

    let fx = Factory::deterministic(Seed::new([0xFF; 32]));

    let rsa = fx.rsa("all-types", RsaSpec::rs256());
    let ecdsa = fx.ecdsa("all-types", EcdsaSpec::es256());
    let ed = fx.ed25519("all-types", Ed25519Spec::new());
    let hmac = fx.hmac("all-types", HmacSpec::hs256());
    let tok = fx.token("all-types", TokenSpec::api_key());
    let cert = fx.x509_self_signed("all-types", X509Spec::self_signed("test.local"));

    // Each type produces non-empty output
    assert!(!rsa.private_key_pkcs8_pem().is_empty());
    assert!(!ecdsa.private_key_pkcs8_pem().is_empty());
    assert!(!ed.private_key_pkcs8_pem().is_empty());
    assert!(!hmac.secret_bytes().is_empty());
    assert!(!tok.value().is_empty());
    assert!(!cert.cert_pem().is_empty());
}
