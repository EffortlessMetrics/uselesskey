use uselesskey_core::Factory;
use uselesskey_token::{TokenFactoryExt, TokenSpec};

pub(super) fn jwt_shape(fx: &Factory, label: &str) -> Vec<u8> {
    fx.token(label, TokenSpec::oauth_access_token())
        .value()
        .as_bytes()
        .to_vec()
}

pub(super) fn api_key(fx: &Factory, label: &str) -> Vec<u8> {
    fx.token(label, TokenSpec::api_key())
        .value()
        .as_bytes()
        .to_vec()
}
