//! Cache coherence integration tests for HMAC.

mod testutil;

use testutil::fx;
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

#[test]
fn same_label_same_spec_returns_identical_bytes() {
    let fx = fx();
    let s1 = fx.hmac("cache-eq", HmacSpec::hs256());
    let s2 = fx.hmac("cache-eq", HmacSpec::hs256());
    assert_eq!(
        s1.secret_bytes(),
        s2.secret_bytes(),
        "same label+spec must return identical secret bytes"
    );
}

#[test]
fn different_labels_produce_different_secrets() {
    let fx = fx();
    let s_a = fx.hmac("hmac-a", HmacSpec::hs256());
    let s_b = fx.hmac("hmac-b", HmacSpec::hs256());
    assert_ne!(
        s_a.secret_bytes(),
        s_b.secret_bytes(),
        "different labels must produce different secrets"
    );
}

#[test]
fn different_specs_produce_different_secrets() {
    let fx = fx();
    let s_256 = fx.hmac("spec-diff", HmacSpec::hs256());
    let s_512 = fx.hmac("spec-diff", HmacSpec::hs512());
    assert_ne!(
        s_256.secret_bytes(),
        s_512.secret_bytes(),
        "different specs must produce different secrets"
    );
}

#[test]
fn cache_survives_factory_clone() {
    let fx = fx();
    let _warm = fx.hmac("hmac-clone", HmacSpec::hs256());
    let fx2 = fx.clone();
    let from_clone = fx2.hmac("hmac-clone", HmacSpec::hs256());
    assert_eq!(
        _warm.secret_bytes(),
        from_clone.secret_bytes(),
        "cloned factory must share the cache"
    );
}

#[test]
fn secret_length_matches_spec() {
    let fx = fx();
    assert_eq!(
        fx.hmac("len-256", HmacSpec::hs256()).secret_bytes().len(),
        32
    );
    assert_eq!(
        fx.hmac("len-384", HmacSpec::hs384()).secret_bytes().len(),
        48
    );
    assert_eq!(
        fx.hmac("len-512", HmacSpec::hs512()).secret_bytes().len(),
        64
    );
}

// ---------------------------------------------------------------------------
// JWK (requires `jwk` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "jwk")]
mod jwk_tests {
    use super::*;

    #[test]
    fn jwk_has_oct_kty() {
        let s = fx().hmac("jwk-oct", HmacSpec::hs256());
        let v = s.jwk().to_value();
        assert_eq!(v["kty"], "oct");
        assert!(v["k"].is_string(), "oct JWK must have 'k' (key value)");
    }

    #[test]
    fn jwks_wraps_key_in_array() {
        let s = fx().hmac("jwks-oct", HmacSpec::hs256());
        let v = s.jwks().to_value();
        let keys = v["keys"].as_array().expect("JWKS must have 'keys'");
        assert_eq!(keys.len(), 1);
    }
}
