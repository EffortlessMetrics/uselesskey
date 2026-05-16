//! Extra coverage for uselesskey-hmac:
//!
//! - Domain constant invariant.
//! - Clone semantics produce equal secret bytes and identity.
//! - Debug omits raw secret bytes (existing test only covers label).
//! - JWK `use_` field is "sig" (only checked exists today).

use uselesskey_core::{Factory, Seed};
use uselesskey_hmac::{DOMAIN_HMAC_SECRET, HmacFactoryExt, HmacSpec};

fn det_fx(seed_label: &str) -> Factory {
    Factory::deterministic(Seed::from_env_value(seed_label).unwrap())
}

#[test]
fn domain_constant_is_stable() {
    assert_eq!(DOMAIN_HMAC_SECRET, "uselesskey:hmac:secret");
}

#[test]
fn clone_preserves_secret_and_identity() {
    let fx = det_fx("hmac-clone");
    let original = fx.hmac("issuer", HmacSpec::hs256());
    let cloned = original.clone();

    assert_eq!(original.secret_bytes(), cloned.secret_bytes());
    assert_eq!(original.label(), cloned.label());
    assert_eq!(original.spec(), cloned.spec());
}

#[test]
fn clone_chain_preserves_secret() {
    let fx = det_fx("hmac-clone-chain");
    let original = fx.hmac("issuer", HmacSpec::hs384());
    let chained = original.clone().clone().clone();
    assert_eq!(original.secret_bytes(), chained.secret_bytes());
}

#[test]
fn debug_omits_raw_secret_bytes() {
    let fx = det_fx("hmac-debug-secret");
    let secret = fx.hmac("issuer", HmacSpec::hs256());
    let bytes_hex = secret
        .secret_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    let dbg = format!("{secret:?}");
    assert!(!dbg.contains(&bytes_hex));
    // Spot-check: do not leak the raw byte array form either.
    let bytes_dbg = format!("{:?}", secret.secret_bytes());
    assert!(!dbg.contains(&bytes_dbg));
}

#[cfg(feature = "jwk")]
#[test]
fn jwk_use_field_is_sig() {
    let fx = det_fx("hmac-jwk-use");
    for spec in [HmacSpec::hs256(), HmacSpec::hs384(), HmacSpec::hs512()] {
        let secret = fx.hmac("issuer", spec);
        let val = secret.jwk().to_value();
        assert_eq!(val["use"], "sig", "use field for {spec:?}");
        assert_eq!(val["kty"], "oct", "kty field for {spec:?}");
    }
}

#[cfg(feature = "jwk")]
#[test]
fn jwks_keys_array_has_exactly_one_entry() {
    let fx = det_fx("hmac-jwks-cardinality");
    let secret = fx.hmac("issuer", HmacSpec::hs256());

    let val = secret.jwks().to_value();
    let keys = val["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1);
}
