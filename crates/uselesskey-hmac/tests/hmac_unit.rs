//! External unit tests for uselesskey-hmac.
//!
//! These tests cover gaps not covered by the inline `#[cfg(test)]` tests:
//! - HS384/HS512 secret lengths (inline only tests HS256)
//! - Different labels → different secrets
//! - Different specs → different secrets
//! - Debug does NOT leak secret material
//! - Determinism survives cache clear
//! - stable_bytes exact values
//! - JWK alg matches all specs (inline only tests HS512)
//! - JWK k field decodes to secret_bytes
//! - kid differs across labels

mod testutil;

use testutil::fx;
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};

// =========================================================================
// Secret length tests
// =========================================================================

#[test]
fn test_secret_length_hs384() {
    let fx = fx();
    let secret = fx.hmac("hs384-len", HmacSpec::hs384());
    assert_eq!(secret.secret_bytes().len(), 48);
}

#[test]
fn test_secret_length_hs512() {
    let fx = fx();
    let secret = fx.hmac("hs512-len", HmacSpec::hs512());
    assert_eq!(secret.secret_bytes().len(), 64);
}

// =========================================================================
// Isolation tests
// =========================================================================

#[test]
fn test_different_labels_different_secrets() {
    let fx = fx();
    let s1 = fx.hmac("label-alpha", HmacSpec::hs256());
    let s2 = fx.hmac("label-beta", HmacSpec::hs256());
    assert_ne!(s1.secret_bytes(), s2.secret_bytes());
}

#[test]
fn test_different_specs_different_secrets() {
    let fx = fx();
    let s256 = fx.hmac("same-label", HmacSpec::hs256());
    let s512 = fx.hmac("same-label", HmacSpec::hs512());
    assert_ne!(
        s256.secret_bytes(),
        s512.secret_bytes(),
        "same label + different spec must not produce same secret bytes"
    );
}

// =========================================================================
// Debug safety
// =========================================================================

#[test]
fn test_debug_does_not_leak_secret_material() {
    let fx = fx();
    let secret = fx.hmac("debug-test", HmacSpec::hs256());

    let debug_output = format!("{:?}", secret);
    assert!(debug_output.contains("HmacSecret"));

    // Convert secret bytes to hex and verify it does NOT appear in debug
    let hex_secret: String = secret
        .secret_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    assert!(
        !debug_output.contains(&hex_secret),
        "Debug output must NOT contain hex-encoded secret bytes"
    );

    // Also check that raw byte values don't appear
    // (finish_non_exhaustive should prevent this)
    assert!(
        debug_output.contains(".."),
        "Debug should use finish_non_exhaustive()"
    );
}

// =========================================================================
// Determinism
// =========================================================================

#[test]
fn test_determinism_survives_cache_clear() {
    use uselesskey_core::{Factory, Seed};

    let seed = Seed::from_env_value("hmac-cache-clear-test").unwrap();
    let fx = Factory::deterministic(seed);

    let s1 = fx.hmac("cache-test", HmacSpec::hs256());
    let bytes1 = s1.secret_bytes().to_vec();

    fx.clear_cache();

    let s2 = fx.hmac("cache-test", HmacSpec::hs256());
    assert_eq!(bytes1, s2.secret_bytes());
}

// =========================================================================
// stable_bytes exact values
// =========================================================================

#[test]
fn test_stable_bytes_exact_values() {
    assert_eq!(HmacSpec::hs256().stable_bytes(), [0, 0, 0, 1]);
    assert_eq!(HmacSpec::hs384().stable_bytes(), [0, 0, 0, 2]);
    assert_eq!(HmacSpec::hs512().stable_bytes(), [0, 0, 0, 3]);
}

// =========================================================================
// JWK tests (require `jwk` feature)
// =========================================================================

#[cfg(feature = "jwk")]
mod jwk_tests {
    use super::*;

    #[test]
    fn test_jwk_alg_matches_all_specs() {
        let fx = fx();

        let cases = [
            (HmacSpec::hs256(), "HS256"),
            (HmacSpec::hs384(), "HS384"),
            (HmacSpec::hs512(), "HS512"),
        ];

        for (spec, expected_alg) in cases {
            let secret = fx.hmac("alg-test", spec);
            let jwk = secret.jwk().to_value();
            assert_eq!(
                jwk["alg"], expected_alg,
                "JWK alg should match for {:?}",
                spec
            );
        }
    }

    #[test]
    fn test_jwk_k_decodes_to_secret_bytes() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let fx = fx();

        for spec in [HmacSpec::hs256(), HmacSpec::hs384(), HmacSpec::hs512()] {
            let secret = fx.hmac("k-decode-test", spec);
            let jwk = secret.jwk().to_value();
            let k = jwk["k"].as_str().unwrap();
            let decoded = URL_SAFE_NO_PAD
                .decode(k)
                .expect("k should be valid base64url");
            assert_eq!(
                decoded.as_slice(),
                secret.secret_bytes(),
                "decoded k should equal secret_bytes for {:?}",
                spec
            );
        }
    }

    #[test]
    fn test_kid_different_labels_different_kids() {
        let fx = fx();
        let s1 = fx.hmac("kid-label-1", HmacSpec::hs256());
        let s2 = fx.hmac("kid-label-2", HmacSpec::hs256());
        assert_ne!(s1.kid(), s2.kid());
    }
}
