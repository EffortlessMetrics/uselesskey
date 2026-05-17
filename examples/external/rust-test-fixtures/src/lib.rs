use uselesskey::{Factory, RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec};

#[test]
fn deterministic_rust_fixtures_work_from_a_clean_project() {
    let fx = Factory::deterministic_from_str("external-rust-test-fixtures");
    let issuer = fx.rsa("issuer", RsaSpec::rs256());
    let issuer_again = fx.rsa("issuer", RsaSpec::rs256());

    assert_eq!(issuer.kid(), issuer_again.kid());
    assert_eq!(issuer.public_jwk().to_value()["kty"], "RSA");
    assert_eq!(issuer.public_jwk().to_value()["alg"], "RS256");

    let token = fx.token("api", TokenSpec::api_key());
    assert!(token.value().starts_with("uk_test_"));
}
