use uselesskey::{
    Factory, NegativeToken, RsaFactoryExt, RsaSpec, TokenFactoryExt, TokenSpec,
};

#[test]
fn facade_generates_positive_rsa_jwk_fixture() {
    let fx = Factory::deterministic_from_str("external-rust-test-fixtures");
    let issuer = fx.rsa("issuer", RsaSpec::rs256());
    let issuer_again = fx.rsa("issuer", RsaSpec::rs256());

    assert_eq!(issuer.kid(), issuer_again.kid());
    assert_eq!(issuer.public_jwk().to_value()["kty"], "RSA");
    assert_eq!(issuer.public_jwk().to_value()["alg"], "RS256");
}

#[test]
fn facade_generates_negative_token_shape_for_parser_tests() {
    let fx = Factory::deterministic_from_str("external-rust-test-fixtures");
    let token = fx.token("api", TokenSpec::api_key());
    let near_miss = token.negative_value(NegativeToken::NearMissApiKey);

    assert!(token.value().starts_with("uk_test_"));
    assert!(!near_miss.starts_with("uk_test_"));
    assert!(example_api_key_parser_accepts(token.value()));
    assert!(!example_api_key_parser_accepts(&near_miss));
}

fn example_api_key_parser_accepts(value: &str) -> bool {
    value.starts_with("uk_test_")
}
