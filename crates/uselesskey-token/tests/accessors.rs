use uselesskey_core::Factory;
use uselesskey_token::{TokenFactoryExt, TokenSpec};

#[test]
fn accessors_round_trip_label_and_spec() {
    let spec = TokenSpec::oauth_access_token();
    let token = Factory::random().token("token-accessor", spec);

    assert_eq!(token.spec(), spec);
    assert_eq!(token.label(), "token-accessor");
}
