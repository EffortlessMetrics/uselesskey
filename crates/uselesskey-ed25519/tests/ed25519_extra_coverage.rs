//! Extra coverage for uselesskey-ed25519:
//!
//! - Domain constant invariant.
//! - DER length lower bounds (PKCS#8 / SPKI) for sanity / shape checks.
//! - JWK `x`/`d` decode to 32 bytes.
//! - Public JWKS cardinality is exactly 1.
//! - Clone semantics preserve material.

#[cfg(feature = "jwk")]
use base64::Engine as _;
#[cfg(feature = "jwk")]
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uselesskey_core::{Factory, Seed};
use uselesskey_ed25519::{DOMAIN_ED25519_KEYPAIR, Ed25519FactoryExt, Ed25519Spec};
use uselesskey_test_support::{TestResult, require_ok, require_some};

fn det_fx(seed_label: &str) -> TestResult<Factory> {
    Ok(Factory::deterministic(require_ok(
        Seed::from_env_value(seed_label),
        "valid deterministic seed",
    )?))
}

#[test]
fn domain_constant_is_stable() {
    assert_eq!(DOMAIN_ED25519_KEYPAIR, "uselesskey:ed25519:keypair");
}

#[test]
fn der_outputs_meet_minimum_lengths() -> TestResult<()> {
    let fx = det_fx("ed25519-der-len")?;
    let kp = fx.ed25519("svc", Ed25519Spec::new());

    // PKCS#8 v1 Ed25519 PrivateKeyInfo is fixed length (48 bytes).
    assert!(kp.private_key_pkcs8_der().len() >= 48);
    // SPKI for Ed25519 is fixed length (44 bytes).
    assert!(kp.public_key_spki_der().len() >= 44);
    Ok(())
}

#[test]
fn pem_outputs_have_correct_headers() -> TestResult<()> {
    let fx = det_fx("ed25519-pem-headers")?;
    let kp = fx.ed25519("svc", Ed25519Spec::new());

    assert!(
        kp.private_key_pkcs8_pem()
            .starts_with("-----BEGIN PRIVATE KEY-----")
    );
    assert!(
        kp.public_key_spki_pem()
            .starts_with("-----BEGIN PUBLIC KEY-----")
    );
    Ok(())
}

#[cfg(feature = "jwk")]
#[test]
fn public_jwk_has_expected_okp_shape() -> TestResult<()> {
    let fx = det_fx("ed25519-jwk-shape")?;
    let kp = fx.ed25519("svc", Ed25519Spec::new());
    let val = kp.public_jwk().to_value();

    assert_eq!(val["kty"], "OKP");
    assert_eq!(val["crv"], "Ed25519");
    assert_eq!(val["use"], "sig");
    assert_eq!(val["alg"], "EdDSA");
    assert!(val["kid"].is_string());

    let x = require_some(val["x"].as_str(), "x field")?;
    let decoded = require_ok(URL_SAFE_NO_PAD.decode(x), "x is base64url")?;
    assert_eq!(decoded.len(), 32, "Ed25519 public key is 32 bytes");
    Ok(())
}

#[cfg(feature = "jwk")]
#[test]
fn private_key_jwk_d_decodes_to_32_bytes() -> TestResult<()> {
    let fx = det_fx("ed25519-jwk-d")?;
    let kp = fx.ed25519("svc", Ed25519Spec::new());
    let val = kp.private_key_jwk().to_value();

    assert_eq!(val["kty"], "OKP");
    let d = require_some(val["d"].as_str(), "d field")?;
    let decoded = require_ok(URL_SAFE_NO_PAD.decode(d), "d is base64url")?;
    assert_eq!(decoded.len(), 32, "Ed25519 private scalar is 32 bytes");
    Ok(())
}

#[cfg(feature = "jwk")]
#[test]
fn public_jwks_has_exactly_one_entry() -> TestResult<()> {
    let fx = det_fx("ed25519-jwks-cardinality")?;
    let kp = fx.ed25519("svc", Ed25519Spec::new());
    let jwks = kp.public_jwks().to_value();

    let keys = require_some(jwks["keys"].as_array(), "keys array")?;
    assert_eq!(keys.len(), 1);
    Ok(())
}

#[cfg(feature = "jwk")]
#[test]
fn public_jwks_json_matches_public_jwks_to_value() -> TestResult<()> {
    let fx = det_fx("ed25519-jwks-json")?;
    let kp = fx.ed25519("svc", Ed25519Spec::new());

    assert_eq!(kp.public_jwks_json(), kp.public_jwks().to_value());
    Ok(())
}

#[test]
fn clone_preserves_key_material() -> TestResult<()> {
    let fx = det_fx("ed25519-clone")?;
    let original = fx.ed25519("svc", Ed25519Spec::new());
    let cloned = original.clone();

    assert_eq!(
        original.private_key_pkcs8_der(),
        cloned.private_key_pkcs8_der()
    );
    assert_eq!(original.public_key_spki_der(), cloned.public_key_spki_der());
    assert_eq!(original.label(), cloned.label());
    Ok(())
}
