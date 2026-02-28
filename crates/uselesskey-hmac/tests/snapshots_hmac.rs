mod testutil;

use insta::{assert_yaml_snapshot, with_settings};
use testutil::fx;
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

#[test]
#[cfg(feature = "jwk")]
fn snapshots_hs256_jwk_structure() {
    let secret = fx().hmac("snapshot-issuer", HmacSpec::hs256());
    let jwk = secret.jwk().to_value();

    with_settings!({
        description => "HS256 JWK structure — redact secret material, keep shape",
    }, {
        assert_yaml_snapshot!("hs256_jwk", jwk, {
            ".k" => "[secret]",
            ".kid" => "[kid]",
        });
    });
}

#[test]
#[cfg(feature = "jwk")]
fn snapshots_hs384_jwk_structure() {
    let secret = fx().hmac("snapshot-issuer", HmacSpec::hs384());
    let jwk = secret.jwk().to_value();

    with_settings!({
        description => "HS384 JWK structure — redact secret material, keep shape",
    }, {
        assert_yaml_snapshot!("hs384_jwk", jwk, {
            ".k" => "[secret]",
            ".kid" => "[kid]",
        });
    });
}

#[test]
#[cfg(feature = "jwk")]
fn snapshots_hs512_jwk_structure() {
    let secret = fx().hmac("snapshot-issuer", HmacSpec::hs512());
    let jwk = secret.jwk().to_value();

    with_settings!({
        description => "HS512 JWK structure — redact secret material, keep shape",
    }, {
        assert_yaml_snapshot!("hs512_jwk", jwk, {
            ".k" => "[secret]",
            ".kid" => "[kid]",
        });
    });
}

#[test]
#[cfg(feature = "jwk")]
fn snapshots_hs256_jwks_structure() {
    let secret = fx().hmac("snapshot-issuer", HmacSpec::hs256());
    let jwks = secret.jwks().to_value();

    with_settings!({
        description => "HS256 JWKS wrapper — single key set",
    }, {
        assert_yaml_snapshot!("hs256_jwks", jwks, {
            ".keys[0].k" => "[secret]",
            ".keys[0].kid" => "[kid]",
        });
    });
}

#[test]
fn snapshots_secret_byte_lengths() {
    let fx = fx();

    let hs256 = fx.hmac("snapshot-len", HmacSpec::hs256());
    let hs384 = fx.hmac("snapshot-len", HmacSpec::hs384());
    let hs512 = fx.hmac("snapshot-len", HmacSpec::hs512());

    let info = serde_json::json!({
        "hs256_len": hs256.secret_bytes().len(),
        "hs384_len": hs384.secret_bytes().len(),
        "hs512_len": hs512.secret_bytes().len(),
    });

    assert_yaml_snapshot!("hmac_secret_byte_lengths", info);
}
