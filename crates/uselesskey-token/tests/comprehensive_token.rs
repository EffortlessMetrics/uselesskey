//! Comprehensive token fixture tests — Wave 91.
//!
//! Covers format validation, length validation, character set compliance,
//! determinism, negative fixtures, all token specs, and edge cases.

mod testutil;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use uselesskey_core::{Factory, Seed};
use uselesskey_token::{TokenFactoryExt, TokenSpec};

use testutil::fx;

// =========================================================================
// 1. Format validation — token outputs match expected shapes
// =========================================================================

#[test]
fn api_key_has_uk_test_prefix_and_base62_suffix() {
    let fx = fx();
    let tok = fx.token("fmt-api", TokenSpec::api_key());
    let val = tok.value();

    assert!(val.starts_with("uk_test_"), "must start with uk_test_");
    let suffix = &val["uk_test_".len()..];
    assert!(
        suffix.chars().all(|c| c.is_ascii_alphanumeric()),
        "suffix must be base62"
    );
}

#[test]
fn bearer_is_valid_base64url_no_padding() {
    let fx = fx();
    let tok = fx.token("fmt-bearer", TokenSpec::bearer());
    let val = tok.value();

    assert!(
        !val.contains('='),
        "bearer must not contain padding characters"
    );
    assert!(
        !val.contains('+'),
        "bearer must not contain + (standard base64)"
    );
    assert!(
        !val.contains('/'),
        "bearer must not contain / (standard base64)"
    );
    assert!(URL_SAFE_NO_PAD.decode(val).is_ok());
}

#[test]
fn oauth_has_three_base64url_segments() {
    let fx = fx();
    let tok = fx.token("fmt-oauth", TokenSpec::oauth_access_token());
    let parts: Vec<&str> = tok.value().split('.').collect();
    assert_eq!(parts.len(), 3);

    for (i, part) in parts.iter().enumerate() {
        assert!(
            URL_SAFE_NO_PAD.decode(part).is_ok(),
            "segment {i} must be valid base64url"
        );
    }
}

// =========================================================================
// 2. Length validation — tokens have correct lengths for each spec
// =========================================================================

#[test]
fn api_key_length_is_40() {
    let fx = fx();
    let tok = fx.token("len-api", TokenSpec::api_key());
    assert_eq!(tok.value().len(), 40, "8 prefix + 32 base62 = 40");
}

#[test]
fn bearer_length_is_43() {
    let fx = fx();
    let tok = fx.token("len-bearer", TokenSpec::bearer());
    assert_eq!(
        tok.value().len(),
        43,
        "base64url(32 bytes) = 43 chars no padding"
    );
}

#[test]
fn bearer_decodes_to_32_bytes() {
    let fx = fx();
    let tok = fx.token("len-bearer-decode", TokenSpec::bearer());
    let decoded = URL_SAFE_NO_PAD.decode(tok.value()).unwrap();
    assert_eq!(decoded.len(), 32);
}

#[test]
fn oauth_signature_segment_decodes_to_32_bytes() {
    let fx = fx();
    let tok = fx.token("len-oauth-sig", TokenSpec::oauth_access_token());
    let sig = tok.value().split('.').nth(2).unwrap();
    let decoded = URL_SAFE_NO_PAD.decode(sig).unwrap();
    assert_eq!(decoded.len(), 32);
}

#[test]
fn oauth_jti_decodes_to_16_bytes() {
    let fx = fx();
    let tok = fx.token("len-oauth-jti", TokenSpec::oauth_access_token());
    let payload_segment = tok.value().split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    let jti = claims["jti"].as_str().unwrap();
    let jti_decoded = URL_SAFE_NO_PAD.decode(jti).unwrap();
    assert_eq!(jti_decoded.len(), 16);
}

// =========================================================================
// 3. Character set validation
// =========================================================================

#[test]
fn api_key_suffix_only_alphanumeric() {
    let fx = fx();
    for label in ["cs-a", "cs-b", "cs-c", "cs-d", "cs-e"] {
        let tok = fx.token(label, TokenSpec::api_key());
        let suffix = tok.value().strip_prefix("uk_test_").unwrap();
        assert!(
            suffix.chars().all(|c| c.is_ascii_alphanumeric()),
            "label={label}: suffix has non-alphanumeric chars: {suffix}"
        );
    }
}

#[test]
fn bearer_only_base64url_chars() {
    let fx = fx();
    for label in ["cs-b1", "cs-b2", "cs-b3"] {
        let tok = fx.token(label, TokenSpec::bearer());
        let val = tok.value();
        assert!(
            val.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "label={label}: bearer has invalid chars: {val}"
        );
    }
}

#[test]
fn oauth_segments_only_base64url_chars() {
    let fx = fx();
    let tok = fx.token("cs-oauth", TokenSpec::oauth_access_token());
    for (i, segment) in tok.value().split('.').enumerate() {
        assert!(
            segment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "segment {i} has invalid chars"
        );
    }
}

// =========================================================================
// 4. Determinism — same seed → same token, different seeds → different
// =========================================================================

#[test]
fn same_seed_same_label_same_spec_produces_identical_tokens() {
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let seed1 = Seed::from_env_value("det-same").unwrap();
        let seed2 = Seed::from_env_value("det-same").unwrap();
        let fx1 = Factory::deterministic(seed1);
        let fx2 = Factory::deterministic(seed2);

        let t1 = fx1.token("det-label", spec);
        let t2 = fx2.token("det-label", spec);
        assert_eq!(
            t1.value(),
            t2.value(),
            "same seed must produce same token for {:?}",
            spec
        );
    }
}

#[test]
fn different_seeds_produce_different_tokens_all_specs() {
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let fx1 = Factory::deterministic(Seed::from_env_value("det-diff-a").unwrap());
        let fx2 = Factory::deterministic(Seed::from_env_value("det-diff-b").unwrap());

        let t1 = fx1.token("det-label", spec);
        let t2 = fx2.token("det-label", spec);
        assert_ne!(
            t1.value(),
            t2.value(),
            "different seeds must produce different tokens for {:?}",
            spec
        );
    }
}

#[test]
fn determinism_with_variant_across_factories() {
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let fx1 = Factory::deterministic(Seed::from_env_value("det-var").unwrap());
        let fx2 = Factory::deterministic(Seed::from_env_value("det-var").unwrap());

        let t1 = fx1.token_with_variant("svc", spec, "v2");
        let t2 = fx2.token_with_variant("svc", spec, "v2");
        assert_eq!(
            t1.value(),
            t2.value(),
            "variant determinism failed for {:?}",
            spec
        );
    }
}

#[test]
fn different_labels_differ_for_all_specs() {
    let fx = fx();
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let t1 = fx.token("label-a", spec);
        let t2 = fx.token("label-b", spec);
        assert_ne!(
            t1.value(),
            t2.value(),
            "different labels must differ for {:?}",
            spec
        );
    }
}

#[test]
fn different_specs_differ_for_same_label() {
    let fx = fx();
    let api = fx.token("same-label-spec", TokenSpec::api_key());
    let bearer = fx.token("same-label-spec", TokenSpec::bearer());
    let oauth = fx.token("same-label-spec", TokenSpec::oauth_access_token());

    assert_ne!(api.value(), bearer.value());
    assert_ne!(api.value(), oauth.value());
    assert_ne!(bearer.value(), oauth.value());
}

// =========================================================================
// 5. KID / identity stability — token values are stable across runs
// =========================================================================

#[test]
fn token_value_stable_after_cache_clear_all_specs() {
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let fx = Factory::deterministic(Seed::from_env_value("kid-stable").unwrap());

        let val1 = fx.token("stable", spec).value().to_string();
        fx.clear_cache();
        let val2 = fx.token("stable", spec).value().to_string();
        assert_eq!(
            val1, val2,
            "value must be stable after cache clear for {:?}",
            spec
        );
    }
}

#[test]
fn oauth_jti_stable_across_factories() {
    let seed_val = "jti-stable-seed";
    let fx1 = Factory::deterministic(Seed::from_env_value(seed_val).unwrap());
    let fx2 = Factory::deterministic(Seed::from_env_value(seed_val).unwrap());

    let t1 = fx1.token("jti-svc", TokenSpec::oauth_access_token());
    let t2 = fx2.token("jti-svc", TokenSpec::oauth_access_token());

    let jti1 = extract_jti(t1.value());
    let jti2 = extract_jti(t2.value());
    assert_eq!(jti1, jti2, "jti must be stable across factories");
}

fn extract_jti(token_value: &str) -> String {
    let payload_segment = token_value.split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    claims["jti"].as_str().unwrap().to_string()
}

// =========================================================================
// 6. Negative fixtures — variant-based different tokens
// =========================================================================

#[test]
fn variant_good_differs_from_variant_bad() {
    let fx = fx();
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let good = fx.token("neg", spec);
        let bad = fx.token_with_variant("neg", spec, "bad");
        assert_ne!(
            good.value(),
            bad.value(),
            "'good' and 'bad' variants must differ for {:?}",
            spec
        );
    }
}

#[test]
fn multiple_variants_all_distinct() {
    let fx = fx();
    let spec = TokenSpec::bearer();
    let variants: Vec<String> = ["good", "alt", "bad", "expired", "revoked"]
        .iter()
        .map(|v| {
            fx.token_with_variant("multi-var", spec, v)
                .value()
                .to_string()
        })
        .collect();

    for i in 0..variants.len() {
        for j in (i + 1)..variants.len() {
            assert_ne!(variants[i], variants[j], "variants {i} and {j} must differ");
        }
    }
}

#[test]
fn variant_tokens_still_have_correct_format() {
    let fx = fx();

    let api = fx.token_with_variant("fmt-var", TokenSpec::api_key(), "alt");
    assert!(api.value().starts_with("uk_test_"));
    assert_eq!(api.value().len(), 40);

    let bearer = fx.token_with_variant("fmt-var", TokenSpec::bearer(), "alt");
    assert_eq!(bearer.value().len(), 43);
    assert!(URL_SAFE_NO_PAD.decode(bearer.value()).is_ok());

    let oauth = fx.token_with_variant("fmt-var", TokenSpec::oauth_access_token(), "alt");
    let parts: Vec<&str> = oauth.value().split('.').collect();
    assert_eq!(parts.len(), 3);
}

// =========================================================================
// 7. All token specs — exhaustive coverage
// =========================================================================

#[test]
fn all_specs_produce_non_empty_values() {
    let fx = fx();
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let tok = fx.token("all-specs", spec);
        assert!(
            !tok.value().is_empty(),
            "token for {:?} must be non-empty",
            spec
        );
    }
}

#[test]
fn all_specs_have_valid_authorization_headers() {
    let fx = fx();
    let cases: Vec<(TokenSpec, &str)> = vec![
        (TokenSpec::api_key(), "ApiKey"),
        (TokenSpec::bearer(), "Bearer"),
        (TokenSpec::oauth_access_token(), "Bearer"),
    ];

    for (spec, expected_scheme) in cases {
        let tok = fx.token("auth-hdr", spec);
        let header = tok.authorization_header();
        assert!(
            header.starts_with(&format!("{expected_scheme} ")),
            "auth header for {:?} should start with '{expected_scheme} ', got: {header}",
            spec
        );
        assert!(
            header.ends_with(tok.value()),
            "auth header should end with token value"
        );
    }
}

#[test]
fn all_specs_produce_structurally_distinct_tokens() {
    let fx = fx();
    let api = fx.token("distinct", TokenSpec::api_key());
    let bearer = fx.token("distinct", TokenSpec::bearer());
    let oauth = fx.token("distinct", TokenSpec::oauth_access_token());

    // API key starts with prefix
    assert!(api.value().starts_with("uk_test_"));
    // Bearer does not contain dots
    assert!(!bearer.value().contains('.'));
    // OAuth contains exactly 2 dots
    assert_eq!(oauth.value().matches('.').count(), 2);
}

// =========================================================================
// 8. OAuth JWT detailed structure
// =========================================================================

#[test]
fn oauth_header_has_exactly_alg_and_typ() {
    let fx = fx();
    let tok = fx.token("oauth-hdr-exact", TokenSpec::oauth_access_token());
    let header_segment = tok.value().split('.').next().unwrap();
    let header_bytes = URL_SAFE_NO_PAD.decode(header_segment).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();

    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "JWT");
}

#[test]
fn oauth_payload_has_all_expected_claims() {
    let fx = fx();
    let tok = fx.token("oauth-claims-full", TokenSpec::oauth_access_token());
    let payload_segment = tok.value().split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    assert_eq!(claims["iss"], "uselesskey");
    assert_eq!(claims["sub"], "oauth-claims-full");
    assert_eq!(claims["aud"], "tests");
    assert_eq!(claims["scope"], "fixture.read");
    assert!(claims["exp"].is_number());
    assert!(claims["jti"].is_string());
}

#[test]
fn oauth_exp_is_in_the_future() {
    let fx = fx();
    let tok = fx.token("oauth-exp", TokenSpec::oauth_access_token());
    let payload_segment = tok.value().split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    let exp = claims["exp"].as_u64().unwrap();
    assert!(exp > 1_700_000_000, "exp should be well in the future");
}

// =========================================================================
// 9. Clone and Debug safety
// =========================================================================

#[test]
fn token_fixture_clone_preserves_value() {
    let fx = fx();
    let tok = fx.token("clone-test", TokenSpec::api_key());
    let cloned = tok.clone();
    assert_eq!(tok.value(), cloned.value());
}

#[test]
fn debug_never_leaks_token_value_any_spec() {
    let fx = Factory::random();
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let tok = fx.token("debug-all", spec);
        let dbg = format!("{tok:?}");
        assert!(
            !dbg.contains(tok.value()),
            "Debug for {:?} must not leak value",
            spec
        );
        assert!(dbg.contains("TokenFixture"));
    }
}

// =========================================================================
// 10. Random mode produces valid shapes
// =========================================================================

#[test]
fn random_mode_all_specs_valid() {
    let fx = Factory::random();
    let api = fx.token("random-all", TokenSpec::api_key());
    assert!(api.value().starts_with("uk_test_"));
    assert_eq!(api.value().len(), 40);

    let bearer = fx.token("random-all", TokenSpec::bearer());
    assert_eq!(bearer.value().len(), 43);
    assert!(URL_SAFE_NO_PAD.decode(bearer.value()).is_ok());

    let oauth = fx.token("random-all", TokenSpec::oauth_access_token());
    let parts: Vec<&str> = oauth.value().split('.').collect();
    assert_eq!(parts.len(), 3);
}

// =========================================================================
// 11. Edge cases — labels
// =========================================================================

#[test]
fn empty_label_still_produces_valid_tokens() {
    let fx = fx();
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let tok = fx.token("", spec);
        assert!(!tok.value().is_empty(), "empty label should still work");
    }
}

#[test]
fn unicode_label_produces_valid_token() {
    let fx = fx();
    let tok = fx.token("日本語ラベル", TokenSpec::api_key());
    assert!(tok.value().starts_with("uk_test_"));
    assert_eq!(tok.value().len(), 40);
}

#[test]
fn very_long_label_produces_valid_token() {
    let fx = fx();
    let long_label = "a".repeat(1000);
    let tok = fx.token(&long_label, TokenSpec::bearer());
    assert_eq!(tok.value().len(), 43);
}

// =========================================================================
// 12. Authorization header composition
// =========================================================================

#[test]
fn authorization_header_has_single_space_separator() {
    let fx = fx();
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let tok = fx.token("auth-space", spec);
        let header = tok.authorization_header();
        let parts: Vec<&str> = header.splitn(2, ' ').collect();
        assert_eq!(
            parts.len(),
            2,
            "header should have scheme + space + token for {:?}",
            spec
        );
        assert_eq!(
            parts[1],
            tok.value(),
            "token value after space for {:?}",
            spec
        );
    }
}
