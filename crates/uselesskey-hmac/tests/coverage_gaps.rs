//! Coverage-gap tests for uselesskey-hmac.
//!
//! Fills gaps not covered by existing prop/unit/inline tests:
//! - Random mode for HS384 and HS512 (inline only tests HS256 in random)
//! - Determinism across separate factories for all specs
//! - Cache clear for HS384 and HS512
//! - Debug safety for HS384 and HS512
//! - Different specs produce different secrets for same label (already tested HS256 vs HS512)

mod testutil;

use testutil::fx;
use uselesskey_core::{Factory, Seed};
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

// =========================================================================
// Random mode for HS384 and HS512
// =========================================================================

#[test]
fn random_mode_hs384_produces_correct_length() {
    let fx = Factory::random();
    let secret = fx.hmac("random-hs384", HmacSpec::hs384());
    assert_eq!(secret.secret_bytes().len(), 48);
}

#[test]
fn random_mode_hs512_produces_correct_length() {
    let fx = Factory::random();
    let secret = fx.hmac("random-hs512", HmacSpec::hs512());
    assert_eq!(secret.secret_bytes().len(), 64);
}

#[test]
fn random_mode_caches_same_identity() {
    let fx = Factory::random();

    for spec in [HmacSpec::hs256(), HmacSpec::hs384(), HmacSpec::hs512()] {
        let s1 = fx.hmac("cache-test", spec);
        let s2 = fx.hmac("cache-test", spec);
        assert_eq!(
            s1.secret_bytes(),
            s2.secret_bytes(),
            "Random mode should cache for {:?}",
            spec
        );
    }
}

// =========================================================================
// Determinism across separate factories for all specs
// =========================================================================

#[test]
fn determinism_across_factories_all_specs() {
    for spec in [HmacSpec::hs256(), HmacSpec::hs384(), HmacSpec::hs512()] {
        let seed1 = Seed::from_env_value("hmac-cross-factory").unwrap();
        let seed2 = Seed::from_env_value("hmac-cross-factory").unwrap();
        let fx1 = Factory::deterministic(seed1);
        let fx2 = Factory::deterministic(seed2);

        let s1 = fx1.hmac("cross-fac", spec);
        let s2 = fx2.hmac("cross-fac", spec);
        assert_eq!(
            s1.secret_bytes(),
            s2.secret_bytes(),
            "Same seed should produce same secret for {:?}",
            spec
        );
    }
}

// =========================================================================
// Cache clear for HS384 and HS512
// =========================================================================

#[test]
fn determinism_survives_cache_clear_hs384() {
    let seed = Seed::from_env_value("hmac-cache-hs384").unwrap();
    let fx = Factory::deterministic(seed);

    let s1 = fx.hmac("cache-clear", HmacSpec::hs384());
    let bytes1 = s1.secret_bytes().to_vec();
    fx.clear_cache();
    let s2 = fx.hmac("cache-clear", HmacSpec::hs384());
    assert_eq!(bytes1, s2.secret_bytes());
}

#[test]
fn determinism_survives_cache_clear_hs512() {
    let seed = Seed::from_env_value("hmac-cache-hs512").unwrap();
    let fx = Factory::deterministic(seed);

    let s1 = fx.hmac("cache-clear", HmacSpec::hs512());
    let bytes1 = s1.secret_bytes().to_vec();
    fx.clear_cache();
    let s2 = fx.hmac("cache-clear", HmacSpec::hs512());
    assert_eq!(bytes1, s2.secret_bytes());
}

// =========================================================================
// Debug safety for HS384 and HS512
// =========================================================================

#[test]
fn debug_does_not_leak_hs384_secret() {
    let fx = fx();
    let secret = fx.hmac("debug-hs384", HmacSpec::hs384());

    let debug_output = format!("{:?}", secret);
    assert!(debug_output.contains("HmacSecret"));
    assert!(debug_output.contains(".."));

    let hex_secret: String = secret
        .secret_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    assert!(!debug_output.contains(&hex_secret));
}

#[test]
fn debug_does_not_leak_hs512_secret() {
    let fx = fx();
    let secret = fx.hmac("debug-hs512", HmacSpec::hs512());

    let debug_output = format!("{:?}", secret);
    assert!(debug_output.contains("HmacSecret"));
    assert!(debug_output.contains(".."));

    let hex_secret: String = secret
        .secret_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    assert!(!debug_output.contains(&hex_secret));
}

// =========================================================================
// HS384 vs HS256 produces different secrets for same label
// =========================================================================

#[test]
fn hs384_vs_hs256_different_for_same_label() {
    let fx = fx();
    let s256 = fx.hmac("same-label", HmacSpec::hs256());
    let s384 = fx.hmac("same-label", HmacSpec::hs384());
    assert_ne!(
        s256.secret_bytes(),
        s384.secret_bytes(),
        "HS256 and HS384 must differ for same label"
    );
}

#[test]
fn hs384_vs_hs512_different_for_same_label() {
    let fx = fx();
    let s384 = fx.hmac("same-label", HmacSpec::hs384());
    let s512 = fx.hmac("same-label", HmacSpec::hs512());
    assert_ne!(
        s384.secret_bytes(),
        s512.secret_bytes(),
        "HS384 and HS512 must differ for same label"
    );
}

// =========================================================================
// JWK tests for HS384/HS512 (feature-gated)
// =========================================================================

#[cfg(feature = "jwk")]
mod jwk_coverage_gaps {
    use super::*;

    #[test]
    fn jwk_k_decodes_to_correct_length_for_all_specs() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let fx = fx();

        let cases = [
            (HmacSpec::hs256(), 32usize),
            (HmacSpec::hs384(), 48usize),
            (HmacSpec::hs512(), 64usize),
        ];

        for (spec, expected_len) in cases {
            let secret = fx.hmac("jwk-k-len", spec);
            let jwk = secret.jwk().to_value();
            let k = jwk["k"].as_str().unwrap();
            let decoded = URL_SAFE_NO_PAD.decode(k).expect("valid base64url");
            assert_eq!(
                decoded.len(),
                expected_len,
                "JWK k should decode to {expected_len} bytes for {:?}",
                spec
            );
        }
    }

    #[test]
    fn kid_differs_across_specs_for_same_label() {
        let fx = fx();
        let s256 = fx.hmac("kid-spec", HmacSpec::hs256());
        let s384 = fx.hmac("kid-spec", HmacSpec::hs384());
        let s512 = fx.hmac("kid-spec", HmacSpec::hs512());

        assert_ne!(s256.kid(), s384.kid());
        assert_ne!(s256.kid(), s512.kid());
        assert_ne!(s384.kid(), s512.kid());
    }

    #[test]
    fn jwks_wraps_hs384() {
        let fx = fx();
        let secret = fx.hmac("jwks-hs384", HmacSpec::hs384());
        let jwks = secret.jwks().to_value();
        let keys = jwks["keys"].as_array().expect("keys array");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["alg"], "HS384");
    }

    #[test]
    fn jwks_wraps_hs512() {
        let fx = fx();
        let secret = fx.hmac("jwks-hs512", HmacSpec::hs512());
        let jwks = secret.jwks().to_value();
        let keys = jwks["keys"].as_array().expect("keys array");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["alg"], "HS512");
    }
}
