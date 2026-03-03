//! Comprehensive token fixture tests — Wave 178.
//!
//! Covers all TokenSpec variants, format validation, determinism, uniqueness,
//! cross-domain isolation, Debug safety, and insta snapshot metadata.

mod testutil;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;

use uselesskey_core::{Factory, Seed};
use uselesskey_token::{TokenFactoryExt, TokenSpec};

use testutil::fx;

// =========================================================================
// 1. All TokenSpec variants produce valid, non-empty tokens
// =========================================================================

#[test]
fn all_spec_variants_produce_non_empty_tokens() {
    let fx = fx();
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let tok = fx.token("all-variant", spec);
        assert!(
            !tok.value().is_empty(),
            "token for {:?} must be non-empty",
            spec
        );
    }
}

#[test]
fn all_spec_variants_produce_correct_authorization_scheme() {
    let fx = fx();
    let cases: &[(TokenSpec, &str)] = &[
        (TokenSpec::api_key(), "ApiKey"),
        (TokenSpec::bearer(), "Bearer"),
        (TokenSpec::oauth_access_token(), "Bearer"),
    ];

    for (spec, expected_scheme) in cases {
        let tok = fx.token("auth-scheme", *spec);
        let header = tok.authorization_header();
        assert!(
            header.starts_with(&format!("{expected_scheme} ")),
            "auth header for {:?} should start with '{expected_scheme} ', got: {header}",
            spec
        );
    }
}

// =========================================================================
// 2. Format validity — prefixes, lengths, character sets
// =========================================================================

#[test]
fn api_key_has_correct_prefix_and_length() {
    let fx = fx();
    let tok = fx.token("fmt-api-w178", TokenSpec::api_key());
    let val = tok.value();

    assert!(
        val.starts_with("uk_test_"),
        "API key must start with uk_test_"
    );
    assert_eq!(
        val.len(),
        40,
        "API key must be 40 chars (8 prefix + 32 base62)"
    );
}

#[test]
fn api_key_suffix_is_base62() {
    let fx = fx();
    let tok = fx.token("fmt-api-charset-w178", TokenSpec::api_key());
    let suffix = tok.value().strip_prefix("uk_test_").unwrap();

    assert_eq!(suffix.len(), 32);
    assert!(
        suffix.chars().all(|c| c.is_ascii_alphanumeric()),
        "API key suffix must only contain [A-Za-z0-9], got: {suffix}"
    );
}

#[test]
fn bearer_is_valid_base64url_of_32_bytes() {
    let fx = fx();
    let tok = fx.token("fmt-bearer-w178", TokenSpec::bearer());
    let val = tok.value();

    assert_eq!(val.len(), 43, "base64url(32 bytes) = 43 chars no padding");
    assert!(!val.contains('='), "must not contain padding");
    assert!(!val.contains('+'), "must not contain + (standard base64)");
    assert!(!val.contains('/'), "must not contain / (standard base64)");

    let decoded = URL_SAFE_NO_PAD
        .decode(val)
        .expect("bearer must be valid base64url");
    assert_eq!(decoded.len(), 32, "bearer must decode to 32 bytes");
}

#[test]
fn oauth_has_three_valid_base64url_segments() {
    let fx = fx();
    let tok = fx.token("fmt-oauth-w178", TokenSpec::oauth_access_token());
    let parts: Vec<&str> = tok.value().split('.').collect();

    assert_eq!(parts.len(), 3, "OAuth token must have 3 JWT segments");
    for (i, part) in parts.iter().enumerate() {
        assert!(
            URL_SAFE_NO_PAD.decode(part).is_ok(),
            "segment {i} must be valid base64url"
        );
    }
}

#[test]
fn oauth_header_is_rs256_jwt() {
    let fx = fx();
    let tok = fx.token("fmt-oauth-hdr-w178", TokenSpec::oauth_access_token());
    let header_segment = tok.value().split('.').next().unwrap();
    let header_bytes = URL_SAFE_NO_PAD.decode(header_segment).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();

    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "JWT");
}

#[test]
fn oauth_payload_has_expected_claims() {
    let fx = fx();
    let tok = fx.token("fmt-oauth-claims-w178", TokenSpec::oauth_access_token());
    let payload_segment = tok.value().split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    assert_eq!(claims["iss"], "uselesskey");
    assert_eq!(
        claims["sub"], "fmt-oauth-claims-w178",
        "sub must match the label"
    );
    assert_eq!(claims["aud"], "tests");
    assert_eq!(claims["scope"], "fixture.read");
    assert!(claims["exp"].is_number(), "exp must be a number");
    assert!(claims["jti"].is_string(), "jti must be a string");
}

#[test]
fn oauth_exp_is_far_future() {
    let fx = fx();
    let tok = fx.token("fmt-oauth-exp-w178", TokenSpec::oauth_access_token());
    let payload_segment = tok.value().split('.').nth(1).unwrap();
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    let exp = claims["exp"].as_u64().unwrap();
    assert!(exp > 1_900_000_000, "exp should be well in the future");
}

#[test]
fn oauth_signature_segment_decodes_to_32_bytes() {
    let fx = fx();
    let tok = fx.token("fmt-oauth-sig-w178", TokenSpec::oauth_access_token());
    let sig = tok.value().split('.').nth(2).unwrap();
    let decoded = URL_SAFE_NO_PAD.decode(sig).unwrap();
    assert_eq!(decoded.len(), 32);
}

// =========================================================================
// 3. Determinism — same seed + label → same token
// =========================================================================

#[test]
fn same_seed_same_label_same_spec_is_deterministic() {
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let fx1 = Factory::deterministic(Seed::from_env_value("det-w178").unwrap());
        let fx2 = Factory::deterministic(Seed::from_env_value("det-w178").unwrap());

        let t1 = fx1.token("det-label-w178", spec);
        let t2 = fx2.token("det-label-w178", spec);
        assert_eq!(
            t1.value(),
            t2.value(),
            "same seed must produce same token for {:?}",
            spec
        );
    }
}

#[test]
fn determinism_survives_cache_clear_all_specs() {
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let fx = Factory::deterministic(Seed::from_env_value("det-cache-w178").unwrap());
        let val1 = fx.token("cache-clear-w178", spec).value().to_string();
        fx.clear_cache();
        let val2 = fx.token("cache-clear-w178", spec).value().to_string();
        assert_eq!(
            val1, val2,
            "value must be stable after cache clear for {:?}",
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
        let fx1 = Factory::deterministic(Seed::from_env_value("det-seed-a-w178").unwrap());
        let fx2 = Factory::deterministic(Seed::from_env_value("det-seed-b-w178").unwrap());

        let t1 = fx1.token("det-label-w178", spec);
        let t2 = fx2.token("det-label-w178", spec);
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
        let fx1 = Factory::deterministic(Seed::from_env_value("det-var-w178").unwrap());
        let fx2 = Factory::deterministic(Seed::from_env_value("det-var-w178").unwrap());

        let t1 = fx1.token_with_variant("svc-w178", spec, "v2");
        let t2 = fx2.token_with_variant("svc-w178", spec, "v2");
        assert_eq!(
            t1.value(),
            t2.value(),
            "variant determinism failed for {:?}",
            spec
        );
    }
}

// =========================================================================
// 4. Uniqueness — different labels / specs / variants → different tokens
// =========================================================================

#[test]
fn different_labels_produce_different_tokens_all_specs() {
    let fx = fx();
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let t1 = fx.token("unique-label-a-w178", spec);
        let t2 = fx.token("unique-label-b-w178", spec);
        assert_ne!(
            t1.value(),
            t2.value(),
            "different labels must differ for {:?}",
            spec
        );
    }
}

#[test]
fn different_specs_produce_different_tokens_same_label() {
    let fx = fx();
    let api = fx.token("unique-spec-w178", TokenSpec::api_key());
    let bearer = fx.token("unique-spec-w178", TokenSpec::bearer());
    let oauth = fx.token("unique-spec-w178", TokenSpec::oauth_access_token());

    assert_ne!(api.value(), bearer.value());
    assert_ne!(api.value(), oauth.value());
    assert_ne!(bearer.value(), oauth.value());
}

#[test]
fn different_variants_produce_different_tokens_all_specs() {
    let fx = fx();
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let default = fx.token("unique-var-w178", spec);
        let alt = fx.token_with_variant("unique-var-w178", spec, "alt");
        assert_ne!(
            default.value(),
            alt.value(),
            "default and alt variants must differ for {:?}",
            spec
        );
    }
}

#[test]
fn multiple_named_variants_all_distinct() {
    let fx = fx();
    let variants: Vec<String> = ["good", "alt", "bad", "expired", "rotated"]
        .iter()
        .map(|v| {
            fx.token_with_variant("multi-var-w178", TokenSpec::bearer(), v)
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

// =========================================================================
// 5. Token isolation — generating tokens doesn't affect key generation
// =========================================================================

#[test]
fn token_generation_does_not_affect_other_token_generation() {
    let seed_val = "isolation-w178";

    // Factory 1: generate api_key only
    let fx1 = Factory::deterministic(Seed::from_env_value(seed_val).unwrap());
    let t1_api = fx1.token("iso-api-w178", TokenSpec::api_key());

    // Factory 2: generate bearer FIRST, then api_key
    let fx2 = Factory::deterministic(Seed::from_env_value(seed_val).unwrap());
    let _t2_bearer = fx2.token("iso-bearer-w178", TokenSpec::bearer());
    let t2_api = fx2.token("iso-api-w178", TokenSpec::api_key());

    assert_eq!(
        t1_api.value(),
        t2_api.value(),
        "generating a bearer token must not affect api_key derivation"
    );
}

#[test]
fn token_generation_order_independent() {
    let seed_val = "isolation-order-w178";

    let fx1 = Factory::deterministic(Seed::from_env_value(seed_val).unwrap());
    let fx2 = Factory::deterministic(Seed::from_env_value(seed_val).unwrap());

    // Different generation order
    let a1 = fx1.token("iso-a-w178", TokenSpec::api_key());
    let b1 = fx1.token("iso-b-w178", TokenSpec::bearer());
    let c1 = fx1.token("iso-c-w178", TokenSpec::oauth_access_token());

    let c2 = fx2.token("iso-c-w178", TokenSpec::oauth_access_token());
    let a2 = fx2.token("iso-a-w178", TokenSpec::api_key());
    let b2 = fx2.token("iso-b-w178", TokenSpec::bearer());

    assert_eq!(a1.value(), a2.value(), "api_key must be order-independent");
    assert_eq!(b1.value(), b2.value(), "bearer must be order-independent");
    assert_eq!(c1.value(), c2.value(), "oauth must be order-independent");
}

// =========================================================================
// 6. TokenSpec::default() — TokenSpec has no Default impl, verify traits
// =========================================================================

#[test]
fn token_spec_copy_semantics() {
    let s1 = TokenSpec::api_key();
    let s2 = s1; // Copy
    assert_eq!(s1, s2);
}

#[test]
fn token_spec_clone_semantics() {
    let s1 = TokenSpec::bearer();
    #[allow(clippy::clone_on_copy)]
    let s2 = s1.clone();
    assert_eq!(s1, s2);
}

#[test]
fn token_spec_eq_and_ne() {
    assert_eq!(TokenSpec::api_key(), TokenSpec::api_key());
    assert_eq!(TokenSpec::bearer(), TokenSpec::bearer());
    assert_eq!(
        TokenSpec::oauth_access_token(),
        TokenSpec::oauth_access_token()
    );
    assert_ne!(TokenSpec::api_key(), TokenSpec::bearer());
    assert_ne!(TokenSpec::api_key(), TokenSpec::oauth_access_token());
    assert_ne!(TokenSpec::bearer(), TokenSpec::oauth_access_token());
}

#[test]
fn token_spec_hash_uniqueness() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(TokenSpec::api_key());
    set.insert(TokenSpec::bearer());
    set.insert(TokenSpec::oauth_access_token());
    set.insert(TokenSpec::api_key()); // duplicate
    assert_eq!(set.len(), 3);
}

#[test]
fn token_spec_debug_format() {
    let dbg = format!("{:?}", TokenSpec::api_key());
    assert!(
        dbg.contains("ApiKey"),
        "Debug of ApiKey should contain 'ApiKey'"
    );

    let dbg = format!("{:?}", TokenSpec::bearer());
    assert!(
        dbg.contains("Bearer"),
        "Debug of Bearer should contain 'Bearer'"
    );

    let dbg = format!("{:?}", TokenSpec::oauth_access_token());
    assert!(
        dbg.contains("OAuthAccessToken"),
        "Debug of OAuthAccessToken should contain 'OAuthAccessToken'"
    );
}

#[test]
fn token_spec_kind_names_stable() {
    assert_eq!(TokenSpec::api_key().kind_name(), "api_key");
    assert_eq!(TokenSpec::bearer().kind_name(), "bearer");
    assert_eq!(
        TokenSpec::oauth_access_token().kind_name(),
        "oauth_access_token"
    );
}

#[test]
fn token_spec_stable_bytes_all_distinct() {
    let api = TokenSpec::api_key().stable_bytes();
    let bearer = TokenSpec::bearer().stable_bytes();
    let oauth = TokenSpec::oauth_access_token().stable_bytes();
    assert_ne!(api, bearer);
    assert_ne!(api, oauth);
    assert_ne!(bearer, oauth);
}

// =========================================================================
// 7. Debug implementation doesn't leak token values
// =========================================================================

#[test]
fn debug_never_leaks_token_value_for_any_spec() {
    let fx = Factory::random();
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let tok = fx.token("debug-w178", spec);
        let dbg = format!("{tok:?}");

        assert!(
            dbg.contains("TokenFixture"),
            "Debug must name the type for {:?}",
            spec
        );
        assert!(
            dbg.contains("debug-w178"),
            "Debug must contain the label for {:?}",
            spec
        );
        assert!(
            !dbg.contains(tok.value()),
            "Debug for {:?} must not leak the token value",
            spec
        );
        assert!(
            dbg.contains(".."),
            "Debug should use finish_non_exhaustive() for {:?}",
            spec
        );
    }
}

#[test]
fn debug_shows_spec_in_output() {
    let fx = fx();
    let tok = fx.token("debug-spec-w178", TokenSpec::api_key());
    let dbg = format!("{tok:?}");
    assert!(dbg.contains("ApiKey"), "Debug should show spec variant");
}

#[test]
fn clone_preserves_value_and_debug_safety() {
    let fx = fx();
    let tok = fx.token("clone-w178", TokenSpec::bearer());
    let cloned = tok.clone();

    assert_eq!(tok.value(), cloned.value());

    let dbg = format!("{cloned:?}");
    assert!(!dbg.contains(cloned.value()));
}

// =========================================================================
// 8. Insta snapshots for token metadata
// =========================================================================

#[derive(Serialize)]
struct TokenMeta {
    label: &'static str,
    kind: &'static str,
    value_len: usize,
    prefix: String,
    has_dots: bool,
    dot_count: usize,
    auth_scheme: String,
}

#[test]
fn snapshot_api_key_metadata() {
    let fx = fx();
    let tok = fx.token("snap-api-w178", TokenSpec::api_key());

    let meta = TokenMeta {
        label: "snap-api-w178",
        kind: "api_key",
        value_len: tok.value().len(),
        prefix: tok.value().chars().take(8).collect(),
        has_dots: tok.value().contains('.'),
        dot_count: tok.value().matches('.').count(),
        auth_scheme: tok
            .authorization_header()
            .split(' ')
            .next()
            .unwrap_or("")
            .to_string(),
    };

    insta::assert_yaml_snapshot!("w178_api_key_metadata", meta);
}

#[test]
fn snapshot_bearer_metadata() {
    let fx = fx();
    let tok = fx.token("snap-bearer-w178", TokenSpec::bearer());

    let meta = TokenMeta {
        label: "snap-bearer-w178",
        kind: "bearer",
        value_len: tok.value().len(),
        prefix: tok.value().chars().take(8).collect(),
        has_dots: tok.value().contains('.'),
        dot_count: tok.value().matches('.').count(),
        auth_scheme: tok
            .authorization_header()
            .split(' ')
            .next()
            .unwrap_or("")
            .to_string(),
    };

    insta::assert_yaml_snapshot!("w178_bearer_metadata", meta);
}

#[test]
fn snapshot_oauth_metadata() {
    let fx = fx();
    let tok = fx.token("snap-oauth-w178", TokenSpec::oauth_access_token());
    let parts: Vec<&str> = tok.value().split('.').collect();

    let meta = TokenMeta {
        label: "snap-oauth-w178",
        kind: "oauth_access_token",
        value_len: tok.value().len(),
        prefix: parts
            .first()
            .map(|s| s.chars().take(8).collect())
            .unwrap_or_default(),
        has_dots: true,
        dot_count: tok.value().matches('.').count(),
        auth_scheme: tok
            .authorization_header()
            .split(' ')
            .next()
            .unwrap_or("")
            .to_string(),
    };

    insta::assert_yaml_snapshot!("w178_oauth_metadata", meta);
}

#[derive(Serialize)]
struct AllSpecsSummary {
    api_key_len: usize,
    api_key_prefix: String,
    bearer_len: usize,
    bearer_is_base64url: bool,
    oauth_segment_count: usize,
    oauth_header_alg: String,
    specs_all_distinct: bool,
}

#[test]
fn snapshot_all_specs_summary() {
    let fx = fx();
    let api = fx.token("snap-summary-w178", TokenSpec::api_key());
    let bearer = fx.token("snap-summary-w178", TokenSpec::bearer());
    let oauth = fx.token("snap-summary-w178", TokenSpec::oauth_access_token());

    let oauth_segments: Vec<&str> = oauth.value().split('.').collect();
    let header_bytes = URL_SAFE_NO_PAD
        .decode(oauth_segments[0])
        .unwrap_or_default();
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).unwrap_or(serde_json::Value::Null);

    let result = AllSpecsSummary {
        api_key_len: api.value().len(),
        api_key_prefix: api.value().chars().take(8).collect(),
        bearer_len: bearer.value().len(),
        bearer_is_base64url: URL_SAFE_NO_PAD.decode(bearer.value()).is_ok(),
        oauth_segment_count: oauth_segments.len(),
        oauth_header_alg: header["alg"].as_str().unwrap_or("").to_string(),
        specs_all_distinct: api.value() != bearer.value()
            && api.value() != oauth.value()
            && bearer.value() != oauth.value(),
    };

    insta::assert_yaml_snapshot!("w178_all_specs_summary", result);
}

// =========================================================================
// 9. Edge cases
// =========================================================================

#[test]
fn empty_label_produces_valid_tokens() {
    let fx = fx();
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let tok = fx.token("", spec);
        assert!(
            !tok.value().is_empty(),
            "empty label should still produce a token"
        );
    }
}

#[test]
fn unicode_label_produces_valid_tokens() {
    let fx = fx();
    let tok = fx.token("こんにちは🔑", TokenSpec::api_key());
    assert!(tok.value().starts_with("uk_test_"));
    assert_eq!(tok.value().len(), 40);
}

#[test]
fn long_label_produces_valid_tokens() {
    let fx = fx();
    let long_label = "a".repeat(5000);
    let tok = fx.token(&long_label, TokenSpec::bearer());
    assert_eq!(tok.value().len(), 43);
}

// =========================================================================
// 10. Random mode still works and caches
// =========================================================================

#[test]
fn random_mode_produces_valid_shapes() {
    let fx = Factory::random();

    let api = fx.token("random-w178", TokenSpec::api_key());
    assert!(api.value().starts_with("uk_test_"));
    assert_eq!(api.value().len(), 40);

    let bearer = fx.token("random-w178", TokenSpec::bearer());
    assert_eq!(bearer.value().len(), 43);
    assert!(URL_SAFE_NO_PAD.decode(bearer.value()).is_ok());

    let oauth = fx.token("random-w178", TokenSpec::oauth_access_token());
    assert_eq!(oauth.value().matches('.').count(), 2);
}

#[test]
fn random_mode_caches_per_identity() {
    let fx = Factory::random();
    for spec in [
        TokenSpec::api_key(),
        TokenSpec::bearer(),
        TokenSpec::oauth_access_token(),
    ] {
        let t1 = fx.token("cache-w178", spec);
        let t2 = fx.token("cache-w178", spec);
        assert_eq!(
            t1.value(),
            t2.value(),
            "random mode must cache for {:?}",
            spec
        );
    }
}

// =========================================================================
// 11. Concurrent access safety
// =========================================================================

#[test]
fn concurrent_token_generation_is_safe() {
    use std::thread;

    let fx = fx();
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let fx = fx.clone();
            thread::spawn(move || {
                let api = fx.token("concurrent-w178", TokenSpec::api_key());
                let bearer = fx.token("concurrent-w178", TokenSpec::bearer());
                let oauth = fx.token("concurrent-w178", TokenSpec::oauth_access_token());
                (
                    api.value().to_string(),
                    bearer.value().to_string(),
                    oauth.value().to_string(),
                )
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for pair in results.windows(2) {
        assert_eq!(
            pair[0], pair[1],
            "all threads must see the same cached value"
        );
    }
}
