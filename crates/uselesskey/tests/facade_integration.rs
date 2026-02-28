mod testutil;

// ---------------------------------------------------------------------------
// 1. Factory creation (random + deterministic)
// ---------------------------------------------------------------------------

#[test]
fn factory_random_mode() {
    use uselesskey::{Factory, Mode};
    let fx = Factory::random();
    assert!(matches!(fx.mode(), Mode::Random));
}

#[test]
fn factory_deterministic_mode() {
    use uselesskey::{Factory, Mode, Seed};
    let seed = Seed::from_env_value("facade-integration-seed").unwrap();
    let fx = Factory::deterministic(seed);
    assert!(matches!(fx.mode(), Mode::Deterministic { .. }));
}

#[test]
fn factory_deterministic_from_env() {
    use uselesskey::Factory;
    // Variable not set → error
    let result = Factory::deterministic_from_env("USELESSKEY_FACADE_TEST_NONEXISTENT_39284");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// 2. RSA key generation
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "rsa")]
fn rsa_pem_and_der_outputs() {
    use uselesskey::{RsaFactoryExt, RsaSpec};
    let fx = testutil::fx();
    let kp = fx.rsa("rsa-integ", RsaSpec::rs256());

    let priv_pem = kp.private_key_pkcs8_pem();
    assert!(priv_pem.starts_with("-----BEGIN PRIVATE KEY-----"));

    let priv_der = kp.private_key_pkcs8_der();
    assert!(!priv_der.is_empty());

    let pub_pem = kp.public_key_spki_pem();
    assert!(pub_pem.starts_with("-----BEGIN PUBLIC KEY-----"));

    let pub_der = kp.public_key_spki_der();
    assert!(!pub_der.is_empty());
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_tempfile_outputs() {
    use uselesskey::{RsaFactoryExt, RsaSpec};
    let fx = testutil::fx();
    let kp = fx.rsa("rsa-tmp", RsaSpec::rs256());

    let priv_tmp = kp.write_private_key_pkcs8_pem().unwrap();
    assert!(priv_tmp.path().exists());

    let pub_tmp = kp.write_public_key_spki_pem().unwrap();
    assert!(pub_tmp.path().exists());
}

#[test]
#[cfg(all(feature = "rsa", feature = "jwk"))]
fn rsa_jwk_outputs() {
    use uselesskey::{RsaFactoryExt, RsaSpec};
    let fx = testutil::fx();
    let kp = fx.rsa("rsa-jwk", RsaSpec::rs256());

    let kid = kp.kid();
    assert!(!kid.is_empty());

    let pub_jwk = kp.public_jwk();
    let v = pub_jwk.to_value();
    assert_eq!(v["kty"], "RSA");
    assert_eq!(v["alg"], "RS256");

    let priv_jwk = kp.private_key_jwk();
    let pv = priv_jwk.to_value();
    assert_eq!(pv["kty"], "RSA");

    let jwks = kp.public_jwks();
    let jv = jwks.to_value();
    assert!(jv["keys"].is_array());
    assert_eq!(jv["keys"].as_array().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// 3. ECDSA key generation
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_p256_outputs() {
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};
    let fx = testutil::fx();
    let kp = fx.ecdsa("ec-p256", EcdsaSpec::es256());

    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(!kp.private_key_pkcs8_der().is_empty());
    assert!(kp.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
    assert!(!kp.public_key_spki_der().is_empty());
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_p384_outputs() {
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};
    let fx = testutil::fx();
    let kp = fx.ecdsa("ec-p384", EcdsaSpec::es384());

    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(!kp.public_key_spki_der().is_empty());
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_tempfile_outputs() {
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};
    let fx = testutil::fx();
    let kp = fx.ecdsa("ec-tmp", EcdsaSpec::es256());

    assert!(kp.write_private_key_pkcs8_pem().unwrap().path().exists());
    assert!(kp.write_public_key_spki_pem().unwrap().path().exists());
}

#[test]
#[cfg(all(feature = "ecdsa", feature = "jwk"))]
fn ecdsa_jwk_outputs() {
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};
    let fx = testutil::fx();
    let kp = fx.ecdsa("ec-jwk", EcdsaSpec::es256());

    assert!(!kp.kid().is_empty());

    let v = kp.public_jwk().to_value();
    assert_eq!(v["kty"], "EC");

    let pv = kp.private_key_jwk().to_value();
    assert_eq!(pv["kty"], "EC");

    let jv = kp.public_jwks().to_value();
    assert!(jv["keys"].is_array());
}

// ---------------------------------------------------------------------------
// 4. Ed25519 key generation
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_outputs() {
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec};
    let fx = testutil::fx();
    let kp = fx.ed25519("ed-integ", Ed25519Spec::new());

    assert!(kp.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(!kp.private_key_pkcs8_der().is_empty());
    assert!(kp.public_key_spki_pem().contains("BEGIN PUBLIC KEY"));
    assert!(!kp.public_key_spki_der().is_empty());
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_tempfile_outputs() {
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec};
    let fx = testutil::fx();
    let kp = fx.ed25519("ed-tmp", Ed25519Spec::new());

    assert!(kp.write_private_key_pkcs8_pem().unwrap().path().exists());
    assert!(kp.write_public_key_spki_pem().unwrap().path().exists());
}

#[test]
#[cfg(all(feature = "ed25519", feature = "jwk"))]
fn ed25519_jwk_outputs() {
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec};
    let fx = testutil::fx();
    let kp = fx.ed25519("ed-jwk", Ed25519Spec::new());

    assert!(!kp.kid().is_empty());

    let v = kp.public_jwk().to_value();
    assert_eq!(v["kty"], "OKP");

    let pv = kp.private_key_jwk().to_value();
    assert_eq!(pv["kty"], "OKP");

    let jv = kp.public_jwks().to_value();
    assert!(jv["keys"].is_array());
}

// ---------------------------------------------------------------------------
// 5. HMAC key generation
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "hmac")]
fn hmac_all_specs() {
    use uselesskey::{HmacFactoryExt, HmacSpec};
    let fx = testutil::fx();

    let hs256 = fx.hmac("hmac-256", HmacSpec::hs256());
    assert_eq!(hs256.secret_bytes().len(), 32);

    let hs384 = fx.hmac("hmac-384", HmacSpec::hs384());
    assert_eq!(hs384.secret_bytes().len(), 48);

    let hs512 = fx.hmac("hmac-512", HmacSpec::hs512());
    assert_eq!(hs512.secret_bytes().len(), 64);
}

#[test]
#[cfg(all(feature = "hmac", feature = "jwk"))]
fn hmac_jwk_outputs() {
    use uselesskey::{HmacFactoryExt, HmacSpec};
    let fx = testutil::fx();
    let secret = fx.hmac("hmac-jwk", HmacSpec::hs256());

    assert!(!secret.kid().is_empty());

    let jwk = secret.jwk();
    let v = jwk.to_value();
    assert_eq!(v["kty"], "oct");

    let jwks = secret.jwks();
    assert_eq!(jwks.to_value()["keys"].as_array().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// 6. Token generation
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "token")]
fn token_api_key() {
    use uselesskey::{TokenFactoryExt, TokenSpec};
    let fx = testutil::fx();
    let token = fx.token("tok-api", TokenSpec::api_key());

    assert!(token.value().starts_with("uk_test_"));
    let auth = token.authorization_header();
    assert!(auth.starts_with("ApiKey "));
}

#[test]
#[cfg(feature = "token")]
fn token_bearer() {
    use uselesskey::{TokenFactoryExt, TokenSpec};
    let fx = testutil::fx();
    let token = fx.token("tok-bearer", TokenSpec::bearer());

    assert!(!token.value().is_empty());
}

#[test]
#[cfg(feature = "token")]
fn token_oauth_access_token() {
    use uselesskey::{TokenFactoryExt, TokenSpec};
    let fx = testutil::fx();
    let token = fx.token("tok-oauth", TokenSpec::oauth_access_token());

    assert!(!token.value().is_empty());
}

// ---------------------------------------------------------------------------
// 7. X.509 certificate generation
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "x509")]
fn x509_self_signed_outputs() {
    use uselesskey::{X509FactoryExt, X509Spec};
    let fx = testutil::fx();
    let cert = fx.x509_self_signed("x509-ss", X509Spec::self_signed("test.example.com"));

    assert!(cert.cert_pem().contains("BEGIN CERTIFICATE"));
    assert!(!cert.cert_der().is_empty());
    assert!(cert.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
    assert!(!cert.private_key_pkcs8_der().is_empty());

    let id_pem = cert.identity_pem();
    assert!(id_pem.contains("BEGIN CERTIFICATE"));
    assert!(id_pem.contains("BEGIN PRIVATE KEY"));
}

#[test]
#[cfg(feature = "x509")]
fn x509_self_signed_tempfiles() {
    use uselesskey::{X509FactoryExt, X509Spec};
    let fx = testutil::fx();
    let cert = fx.x509_self_signed("x509-tmp", X509Spec::self_signed("test.example.com"));

    assert!(cert.write_cert_pem().unwrap().path().exists());
    assert!(cert.write_cert_der().unwrap().path().exists());
    assert!(cert.write_private_key_pem().unwrap().path().exists());
    assert!(cert.write_identity_pem().unwrap().path().exists());
}

#[test]
#[cfg(feature = "x509")]
fn x509_self_signed_negative_variants() {
    use uselesskey::{X509FactoryExt, X509Spec};
    let fx = testutil::fx();
    let cert = fx.x509_self_signed("x509-neg", X509Spec::self_signed("neg.example.com"));

    let expired = cert.expired();
    assert!(!expired.cert_der().is_empty());

    let not_yet = cert.not_yet_valid();
    assert!(!not_yet.cert_der().is_empty());

    let wrong_ku = cert.wrong_key_usage();
    assert!(!wrong_ku.cert_der().is_empty());
}

#[test]
#[cfg(feature = "x509")]
fn x509_chain_outputs() {
    use uselesskey::{ChainSpec, X509FactoryExt};
    let fx = testutil::fx();
    let chain = fx.x509_chain("x509-chain", ChainSpec::new("leaf.example.com"));

    assert!(chain.root_cert_pem().contains("BEGIN CERTIFICATE"));
    assert!(!chain.root_cert_der().is_empty());
    assert!(
        chain
            .root_private_key_pkcs8_pem()
            .contains("BEGIN PRIVATE KEY")
    );
    assert!(!chain.root_private_key_pkcs8_der().is_empty());

    assert!(chain.intermediate_cert_pem().contains("BEGIN CERTIFICATE"));
    assert!(!chain.intermediate_cert_der().is_empty());
    assert!(
        chain
            .intermediate_private_key_pkcs8_pem()
            .contains("BEGIN PRIVATE KEY")
    );

    assert!(chain.leaf_cert_pem().contains("BEGIN CERTIFICATE"));
    assert!(!chain.leaf_cert_der().is_empty());
    assert!(
        chain
            .leaf_private_key_pkcs8_pem()
            .contains("BEGIN PRIVATE KEY")
    );

    let chain_pem = chain.chain_pem();
    assert!(chain_pem.contains("BEGIN CERTIFICATE"));

    let full_chain_pem = chain.full_chain_pem();
    assert!(full_chain_pem.contains("BEGIN CERTIFICATE"));
    // Full chain should be longer (includes root)
    assert!(full_chain_pem.len() > chain_pem.len());
}

#[test]
#[cfg(feature = "x509")]
fn x509_chain_tempfiles() {
    use uselesskey::{ChainSpec, X509FactoryExt};
    let fx = testutil::fx();
    let chain = fx.x509_chain("x509-chain-tmp", ChainSpec::new("tmp.example.com"));

    assert!(chain.write_leaf_cert_pem().unwrap().path().exists());
    assert!(chain.write_leaf_cert_der().unwrap().path().exists());
    assert!(chain.write_leaf_private_key_pem().unwrap().path().exists());
    assert!(chain.write_chain_pem().unwrap().path().exists());
    assert!(chain.write_full_chain_pem().unwrap().path().exists());
    assert!(chain.write_root_cert_pem().unwrap().path().exists());
}

// ---------------------------------------------------------------------------
// 8. JWK/JWKS building
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "jwk")]
fn jwks_builder_multi_key() {
    use uselesskey::jwk::JwksBuilder;

    #[cfg(feature = "rsa")]
    {
        use uselesskey::{RsaFactoryExt, RsaSpec};
        let fx = testutil::fx();
        let rsa = fx.rsa("jwks-rsa", RsaSpec::rs256());
        let mut builder = JwksBuilder::new();
        builder.push_public(rsa.public_jwk());

        #[cfg(feature = "ecdsa")]
        {
            use uselesskey::{EcdsaFactoryExt, EcdsaSpec};
            let ec = fx.ecdsa("jwks-ec", EcdsaSpec::es256());
            builder.push_public(ec.public_jwk());
        }

        let jwks = builder.build();
        let v = jwks.to_value();
        assert!(!v["keys"].as_array().unwrap().is_empty());
    }
}

#[test]
#[cfg(feature = "jwk")]
fn jwks_builder_empty_is_valid() {
    use uselesskey::jwk::JwksBuilder;
    let jwks = JwksBuilder::new().build();
    let v = jwks.to_value();
    assert!(v["keys"].as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// 9. PGP key generation
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "pgp")]
fn pgp_ed25519_outputs() {
    use uselesskey::{PgpFactoryExt, PgpSpec};
    let fx = testutil::fx();
    let kp = fx.pgp("pgp-ed", PgpSpec::ed25519());

    assert!(
        kp.private_key_armored()
            .contains("BEGIN PGP PRIVATE KEY BLOCK")
    );
    assert!(
        kp.public_key_armored()
            .contains("BEGIN PGP PUBLIC KEY BLOCK")
    );
    assert!(!kp.private_key_binary().is_empty());
    assert!(!kp.public_key_binary().is_empty());
    assert!(!kp.user_id().is_empty());
    assert!(!kp.fingerprint().is_empty());
}

#[test]
#[cfg(feature = "pgp")]
fn pgp_rsa_outputs() {
    use uselesskey::{PgpFactoryExt, PgpSpec};
    let fx = testutil::fx();
    let kp = fx.pgp("pgp-rsa", PgpSpec::rsa_2048());

    assert!(
        kp.private_key_armored()
            .contains("BEGIN PGP PRIVATE KEY BLOCK")
    );
    assert!(
        kp.public_key_armored()
            .contains("BEGIN PGP PUBLIC KEY BLOCK")
    );
}

#[test]
#[cfg(feature = "pgp")]
fn pgp_tempfile_outputs() {
    use uselesskey::{PgpFactoryExt, PgpSpec};
    let fx = testutil::fx();
    let kp = fx.pgp("pgp-tmp", PgpSpec::ed25519());

    assert!(kp.write_private_key_armored().unwrap().path().exists());
    assert!(kp.write_public_key_armored().unwrap().path().exists());
}

#[test]
#[cfg(feature = "pgp")]
fn pgp_negative_fixtures() {
    use uselesskey::negative::CorruptPem;
    use uselesskey::{PgpFactoryExt, PgpSpec};
    let fx = testutil::fx();
    let kp = fx.pgp("pgp-neg", PgpSpec::ed25519());

    let corrupted = kp.private_key_armored_corrupt(CorruptPem::BadHeader);
    assert!(corrupted.contains("CORRUPTED"));

    let truncated = kp.private_key_binary_truncated(10);
    assert_eq!(truncated.len(), 10);

    let mismatched = kp.mismatched_public_key_binary();
    assert!(!mismatched.is_empty());
    assert_ne!(mismatched, kp.public_key_binary());
}

// ---------------------------------------------------------------------------
// 10. Negative fixtures
// ---------------------------------------------------------------------------

#[test]
fn negative_corrupt_pem_variants() {
    use uselesskey::negative::{CorruptPem, corrupt_pem};
    let pem = "-----BEGIN TEST-----\nYWJj\n-----END TEST-----\n";

    let bad_hdr = corrupt_pem(pem, CorruptPem::BadHeader);
    assert!(bad_hdr.contains("CORRUPTED"));

    let bad_ftr = corrupt_pem(pem, CorruptPem::BadFooter);
    assert!(bad_ftr.contains("CORRUPTED"));

    let bad_b64 = corrupt_pem(pem, CorruptPem::BadBase64);
    assert!(bad_b64.contains("NOT_BASE64"));

    let extra = corrupt_pem(pem, CorruptPem::ExtraBlankLine);
    assert!(extra.contains("\n\n"));

    let trunc = corrupt_pem(pem, CorruptPem::Truncate { bytes: 10 });
    assert_eq!(trunc.len(), 10);
}

#[test]
fn negative_truncate_der() {
    use uselesskey::negative::truncate_der;
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x30, 0x0d];
    let t = truncate_der(&der, 3);
    assert_eq!(t, &[0x30, 0x82, 0x01]);
}

#[test]
fn negative_corrupt_pem_deterministic() {
    use uselesskey::negative::corrupt_pem_deterministic;
    let pem = "-----BEGIN TEST-----\nYWJj\n-----END TEST-----\n";

    let c1 = corrupt_pem_deterministic(pem, "variant-a");
    let c2 = corrupt_pem_deterministic(pem, "variant-a");
    assert_eq!(c1, c2, "same variant must produce identical corruption");

    let c3 = corrupt_pem_deterministic(pem, "variant-b");
    assert_ne!(
        c1, c3,
        "different variants should produce different corruption"
    );
}

#[test]
fn negative_corrupt_der_deterministic() {
    use uselesskey::negative::corrupt_der_deterministic;
    let der = vec![0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09];

    let c1 = corrupt_der_deterministic(&der, "variant-a");
    let c2 = corrupt_der_deterministic(&der, "variant-a");
    assert_eq!(c1, c2);
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_negative_fixtures() {
    use uselesskey::negative::CorruptPem;
    use uselesskey::{RsaFactoryExt, RsaSpec};
    let fx = testutil::fx();
    let kp = fx.rsa("rsa-neg", RsaSpec::rs256());

    let bad_pem = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadHeader);
    assert!(bad_pem.contains("CORRUPTED"));

    let det_pem = kp.private_key_pkcs8_pem_corrupt_deterministic("test-variant");
    assert!(!det_pem.is_empty());

    let truncated = kp.private_key_pkcs8_der_truncated(16);
    assert_eq!(truncated.len(), 16);

    let det_der = kp.private_key_pkcs8_der_corrupt_deterministic("test-variant");
    assert!(!det_der.is_empty());

    let mismatch = kp.mismatched_public_key_spki_der();
    assert!(!mismatch.is_empty());
    assert_ne!(mismatch, kp.public_key_spki_der());
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_negative_fixtures() {
    use uselesskey::negative::CorruptPem;
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec};
    let fx = testutil::fx();
    let kp = fx.ecdsa("ec-neg", EcdsaSpec::es256());

    let bad_pem = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadFooter);
    assert!(bad_pem.contains("CORRUPTED"));

    let truncated = kp.private_key_pkcs8_der_truncated(8);
    assert_eq!(truncated.len(), 8);

    let mismatch = kp.mismatched_public_key_spki_der();
    assert!(!mismatch.is_empty());
    assert_ne!(mismatch, kp.public_key_spki_der());
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_negative_fixtures() {
    use uselesskey::negative::CorruptPem;
    use uselesskey::{Ed25519FactoryExt, Ed25519Spec};
    let fx = testutil::fx();
    let kp = fx.ed25519("ed-neg", Ed25519Spec::new());

    let bad_pem = kp.private_key_pkcs8_pem_corrupt(CorruptPem::BadBase64);
    assert!(bad_pem.contains("NOT_BASE64"));

    let truncated = kp.private_key_pkcs8_der_truncated(4);
    assert_eq!(truncated.len(), 4);

    let mismatch = kp.mismatched_public_key_spki_der();
    assert!(!mismatch.is_empty());
    assert_ne!(mismatch, kp.public_key_spki_der());
}

#[test]
#[cfg(feature = "x509")]
fn x509_corrupt_cert_pem() {
    use uselesskey::negative::CorruptPem;
    use uselesskey::{X509FactoryExt, X509Spec};
    let fx = testutil::fx();
    let cert = fx.x509_self_signed("x509-corrupt", X509Spec::self_signed("corrupt.example.com"));

    let bad = cert.corrupt_cert_pem(CorruptPem::BadHeader);
    assert!(bad.contains("CORRUPTED"));

    let det = cert.corrupt_cert_pem_deterministic("v1");
    assert!(!det.is_empty());

    let trunc = cert.truncate_cert_der(10);
    assert_eq!(trunc.len(), 10);

    let det_der = cert.corrupt_cert_der_deterministic("v1");
    assert!(!det_der.is_empty());
}

// ---------------------------------------------------------------------------
// 11. Cache behavior (clear, determinism)
// ---------------------------------------------------------------------------

#[test]
#[cfg(feature = "rsa")]
fn deterministic_same_seed_same_output() {
    use uselesskey::{Factory, RsaFactoryExt, RsaSpec, Seed};

    let seed = Seed::from_env_value("cache-test-seed").unwrap();
    let fx1 = Factory::deterministic(seed);
    let fx2 = Factory::deterministic(seed);

    let k1 = fx1.rsa("det-test", RsaSpec::rs256());
    let k2 = fx2.rsa("det-test", RsaSpec::rs256());

    assert_eq!(k1.private_key_pkcs8_pem(), k2.private_key_pkcs8_pem());
    assert_eq!(k1.public_key_spki_pem(), k2.public_key_spki_pem());
}

#[test]
#[cfg(feature = "rsa")]
fn deterministic_different_labels_different_keys() {
    use uselesskey::{RsaFactoryExt, RsaSpec};
    let fx = testutil::fx();

    let k1 = fx.rsa("label-a", RsaSpec::rs256());
    let k2 = fx.rsa("label-b", RsaSpec::rs256());

    assert_ne!(k1.private_key_pkcs8_pem(), k2.private_key_pkcs8_pem());
}

#[test]
#[cfg(feature = "rsa")]
fn cache_returns_same_arc() {
    use uselesskey::{RsaFactoryExt, RsaSpec};
    let fx = testutil::fx();

    let k1 = fx.rsa("cache-arc", RsaSpec::rs256());
    let k2 = fx.rsa("cache-arc", RsaSpec::rs256());

    // Same label+spec should return cached result with identical bytes
    assert_eq!(k1.private_key_pkcs8_pem(), k2.private_key_pkcs8_pem());
}

#[test]
fn clear_cache_does_not_panic() {
    use uselesskey::Factory;
    let fx = Factory::random();
    fx.clear_cache();
}

// ---------------------------------------------------------------------------
// 12. All output formats (PEM, DER, JWK, tempfile) — cross-key-type summary
// ---------------------------------------------------------------------------

#[test]
#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "jwk"
))]
fn all_key_types_produce_distinct_kids() {
    use uselesskey::{EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec};
    use uselesskey::{RsaFactoryExt, RsaSpec};
    let fx = testutil::fx();

    let rsa_kid = fx.rsa("kid-test", RsaSpec::rs256()).kid();
    let ec_kid = fx.ecdsa("kid-test", EcdsaSpec::es256()).kid();
    let ed_kid = fx.ed25519("kid-test", Ed25519Spec::new()).kid();

    // Different key types should produce different kids even with same label
    assert_ne!(rsa_kid, ec_kid);
    assert_ne!(rsa_kid, ed_kid);
    assert_ne!(ec_kid, ed_kid);
}

#[test]
#[cfg(all(
    feature = "rsa",
    feature = "ecdsa",
    feature = "ed25519",
    feature = "hmac",
    feature = "jwk"
))]
fn jwks_builder_all_key_types() {
    use uselesskey::jwk::JwksBuilder;
    use uselesskey::{
        EcdsaFactoryExt, EcdsaSpec, Ed25519FactoryExt, Ed25519Spec, HmacFactoryExt, HmacSpec,
        RsaFactoryExt, RsaSpec,
    };
    let fx = testutil::fx();

    let jwks = JwksBuilder::new()
        .add_public(fx.rsa("jwks-all-rsa", RsaSpec::rs256()).public_jwk())
        .add_public(fx.ecdsa("jwks-all-ec", EcdsaSpec::es256()).public_jwk())
        .add_public(fx.ed25519("jwks-all-ed", Ed25519Spec::new()).public_jwk())
        .add_private(fx.hmac("jwks-all-hmac", HmacSpec::hs256()).jwk())
        .build();

    let v = jwks.to_value();
    assert_eq!(v["keys"].as_array().unwrap().len(), 4);
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_json_roundtrip_values() {
    #[cfg(feature = "jwk")]
    {
        use uselesskey::{RsaFactoryExt, RsaSpec};
        let fx = testutil::fx();
        let kp = fx.rsa("rsa-json", RsaSpec::rs256());

        let pub_json = kp.public_jwk_json();
        assert!(pub_json.is_object());
        assert_eq!(pub_json["kty"], "RSA");

        let priv_json = kp.private_key_jwk_json();
        assert!(priv_json.is_object());
        assert!(priv_json.get("d").is_some());

        let jwks_json = kp.public_jwks_json();
        assert!(jwks_json["keys"].is_array());
    }
}

// ---------------------------------------------------------------------------
// Prelude smoke test
// ---------------------------------------------------------------------------

#[test]
fn prelude_imports_compile() {
    use uselesskey::prelude::*;

    let fx = Factory::random();
    assert!(matches!(fx.mode(), Mode::Random));

    let _seed = Seed::from_env_value("prelude-test").unwrap();
}
