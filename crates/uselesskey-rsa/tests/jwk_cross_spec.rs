//! Cross-spec JWK / kid coverage for `uselesskey-rsa`.
//!
//! Closes gaps where existing JWK tests only exercised RS256 (2048-bit):
//!
//! - `public_key_jwk` alias equivalence across RS256/RS384/RS512.
//! - `public_jwk_json` / `public_jwks_json` / `private_key_jwk_json` consistency
//!   with `to_value()` across all three spec sizes.
//! - JWKS-embedded key matches standalone `public_jwk()` for RS384/RS512.
//! - `kid()` stability across separate Factory instances seeded with the same
//!   string, for every supported bit size.
//! - `kid()` distinctness across different specs sharing the same label
//!   (spec is part of cache identity, so RSA derivation differs by bits).
//! - `jwk_alg()` falls back to RS256 for sizes outside the RS384/RS512 match
//!   arms (1024-bit case, which the existing match-arm tests never reach).
//! - `public_jwk["use"]` field is "sig" across all specs (only RS256 covered
//!   by `mutation_hardening`).

#![cfg(feature = "jwk")]

use uselesskey_core::Factory;
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

/// All RSA bit sizes that have a dedicated `jwk_alg()` mapping plus the
/// fallback case.
const ALL_SPECS: &[(usize, &str)] = &[
    (1024, "RS256"),
    (2048, "RS256"),
    (3072, "RS384"),
    (4096, "RS512"),
];

#[test]
fn public_key_jwk_alias_matches_public_jwk_for_all_specs() {
    let fx = Factory::deterministic_from_str("rsa-jwk-alias-cross-spec");

    for (bits, _alg) in ALL_SPECS {
        let kp = fx.rsa(format!("alias-{bits}"), RsaSpec::new(*bits));
        assert_eq!(
            kp.public_key_jwk().to_value(),
            kp.public_jwk().to_value(),
            "public_key_jwk must alias public_jwk for {bits}-bit",
        );
    }
}

#[test]
fn json_helpers_match_to_value_for_all_specs() {
    let fx = Factory::deterministic_from_str("rsa-jwk-json-cross-spec");

    for (bits, _alg) in ALL_SPECS {
        let kp = fx.rsa(format!("json-{bits}"), RsaSpec::new(*bits));

        assert_eq!(
            kp.public_jwk_json(),
            kp.public_jwk().to_value(),
            "public_jwk_json must equal public_jwk().to_value() for {bits}-bit",
        );
        assert_eq!(
            kp.public_jwks_json(),
            kp.public_jwks().to_value(),
            "public_jwks_json must equal public_jwks().to_value() for {bits}-bit",
        );
        assert_eq!(
            kp.private_key_jwk_json(),
            kp.private_key_jwk().to_value(),
            "private_key_jwk_json must equal private_key_jwk().to_value() for {bits}-bit",
        );
    }
}

#[test]
fn jwks_embedded_jwk_matches_standalone_public_jwk_for_all_specs() {
    let fx = Factory::deterministic_from_str("rsa-jwks-embed-cross-spec");

    for (bits, _alg) in ALL_SPECS {
        let kp = fx.rsa(format!("jwks-embed-{bits}"), RsaSpec::new(*bits));
        let jwk = kp.public_jwk().to_value();
        let jwks = kp.public_jwks().to_value();

        assert!(
            jwks["keys"].is_array(),
            "public_jwks must have a 'keys' array for {bits}-bit",
        );
        // Compare by serialised form so we don't have to project into the array
        // (the equality of the wrapping object covers what we care about).
        let expected = serde_json::json!({ "keys": [jwk] });
        assert_eq!(
            jwks, expected,
            "JWKS embedded key must equal standalone public_jwk for {bits}-bit",
        );
    }
}

#[test]
fn kid_is_stable_across_separate_factories_for_all_specs() {
    for (bits, _alg) in ALL_SPECS {
        let seed_str = format!("rsa-kid-cross-factory-{bits}");
        let fx1 = Factory::deterministic_from_str(&seed_str);
        let fx2 = Factory::deterministic_from_str(&seed_str);

        let kid1 = fx1.rsa("issuer", RsaSpec::new(*bits)).kid();
        let kid2 = fx2.rsa("issuer", RsaSpec::new(*bits)).kid();

        assert!(!kid1.is_empty(), "kid must be non-empty for {bits}-bit");
        assert_eq!(
            kid1, kid2,
            "kid must be stable across separate factories sharing a seed for {bits}-bit",
        );
    }
}

#[test]
fn kid_differs_across_specs_for_same_label() {
    let fx = Factory::deterministic_from_str("rsa-kid-cross-spec");

    let kids: Vec<String> = ALL_SPECS
        .iter()
        .map(|(bits, _)| fx.rsa("issuer", RsaSpec::new(*bits)).kid())
        .collect();

    for i in 0..kids.len() {
        for j in (i + 1)..kids.len() {
            let bits_i = ALL_SPECS[i].0;
            let bits_j = ALL_SPECS[j].0;
            assert_ne!(
                kids[i], kids[j],
                "kid for {bits_i}-bit must differ from {bits_j}-bit at same label",
            );
        }
    }
}

#[test]
fn jwk_alg_falls_back_to_rs256_for_non_384_512_sizes() {
    // 1024 is the smallest accepted size; it doesn't hit the RS384/RS512 arms
    // and therefore lands in the `_ => "RS256"` fallback. None of the
    // existing tests cover this specific path.
    let fx = Factory::deterministic_from_str("rsa-jwk-fallback");
    let kp = fx.rsa("fallback-1024", RsaSpec::new(1024));
    let jwk = kp.public_jwk().to_value();

    assert_eq!(
        jwk["alg"], "RS256",
        "1024-bit RSA must hit the RS256 fallback arm"
    );
    assert_eq!(jwk["kty"], "RSA");
}

#[test]
fn public_jwk_use_field_is_sig_for_all_specs() {
    let fx = Factory::deterministic_from_str("rsa-jwk-use-cross-spec");

    for (bits, alg) in ALL_SPECS {
        let kp = fx.rsa(format!("use-{bits}"), RsaSpec::new(*bits));
        let jwk = kp.public_jwk().to_value();

        assert_eq!(jwk["use"], "sig", "public_jwk use field for {bits}-bit");
        assert_eq!(jwk["alg"], *alg, "public_jwk alg field for {bits}-bit");
    }
}

#[test]
fn private_key_jwk_use_field_is_sig_for_all_specs() {
    let fx = Factory::deterministic_from_str("rsa-priv-jwk-use-cross-spec");

    for (bits, alg) in ALL_SPECS {
        let kp = fx.rsa(format!("priv-use-{bits}"), RsaSpec::new(*bits));
        let jwk = kp.private_key_jwk().to_value();

        assert_eq!(
            jwk["use"], "sig",
            "private_key_jwk use field for {bits}-bit"
        );
        assert_eq!(jwk["alg"], *alg, "private_key_jwk alg field for {bits}-bit");
    }
}

#[test]
fn jwk_kid_matches_standalone_kid_for_all_specs() {
    let fx = Factory::deterministic_from_str("rsa-jwk-kid-embed-cross-spec");

    for (bits, _alg) in ALL_SPECS {
        let kp = fx.rsa(format!("kid-embed-{bits}"), RsaSpec::new(*bits));
        let kid = kp.kid();
        let public_value = kp.public_jwk().to_value();
        let private_value = kp.private_key_jwk().to_value();

        // Compare as `serde_json::Value`: a JSON string equals a `Value::String`,
        // so this verifies both the kid value and that the field is a string.
        assert_eq!(
            public_value["kid"],
            serde_json::Value::String(kid.clone()),
            "public JWK kid must match kid() for {bits}-bit",
        );
        assert_eq!(
            private_value["kid"],
            serde_json::Value::String(kid),
            "private JWK kid must match kid() for {bits}-bit",
        );
    }
}
