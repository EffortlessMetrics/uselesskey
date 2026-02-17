mod testutil;

use uselesskey::Factory;

#[test]
fn prelude_exposes_core_items() {
    use uselesskey::prelude::*;

    let fx = Factory::random();
    assert!(matches!(fx.mode(), Mode::Random));

    let seed = Seed::from_env_value("facade-seed").unwrap();
    let fx = Factory::deterministic(seed);
    assert!(matches!(fx.mode(), Mode::Deterministic { .. }));

    let pem = "-----BEGIN TEST-----\nAAA=\n-----END TEST-----\n";
    let corrupted = corrupt_pem(pem, CorruptPem::BadHeader);
    assert!(corrupted.contains("CORRUPTED"));
}

#[test]
#[cfg(feature = "rsa")]
fn rsa_reexport_works() {
    use uselesskey::RsaFactoryExt;
    use uselesskey::RsaSpec;

    let fx = testutil::fx();
    let key = fx.rsa("issuer", RsaSpec::rs256());
    assert!(key.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
}

#[test]
#[cfg(feature = "ecdsa")]
fn ecdsa_reexport_works() {
    use uselesskey::EcdsaFactoryExt;
    use uselesskey::EcdsaSpec;

    let fx = Factory::random();
    let key = fx.ecdsa("issuer", EcdsaSpec::es256());
    assert!(key.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
}

#[test]
#[cfg(feature = "ed25519")]
fn ed25519_reexport_works() {
    use uselesskey::Ed25519FactoryExt;
    use uselesskey::Ed25519Spec;

    let fx = Factory::random();
    let key = fx.ed25519("issuer", Ed25519Spec::new());
    assert!(key.private_key_pkcs8_pem().contains("BEGIN PRIVATE KEY"));
}

#[test]
#[cfg(feature = "hmac")]
fn hmac_reexport_works() {
    use uselesskey::HmacFactoryExt;
    use uselesskey::HmacSpec;

    let fx = Factory::random();
    let secret = fx.hmac("issuer", HmacSpec::hs256());
    assert_eq!(secret.secret_bytes().len(), HmacSpec::hs256().byte_len());
}

#[test]
#[cfg(feature = "token")]
fn token_reexport_works() {
    use uselesskey::TokenFactoryExt;
    use uselesskey::TokenSpec;

    let fx = Factory::random();
    let token = fx.token("issuer", TokenSpec::api_key());
    assert!(token.value().starts_with("uk_test_"));
}

#[test]
#[cfg(feature = "jwk")]
fn jwk_module_reexports_work() {
    use uselesskey::jwk::{JwksBuilder, PublicJwk, RsaPublicJwk};

    let jwk = PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: "kid".to_string(),
        n: "n".to_string(),
        e: "e".to_string(),
    });

    let jwks = JwksBuilder::new().add_public(jwk).build();
    assert_eq!(jwks.keys.len(), 1);
}
