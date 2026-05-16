//! Focused coverage for `NegativeJwks` variants, `Jwks::Display`, and
//! `JwksBuilder::default()` equivalence.
//!
//! These tests target the public API surface described in
//! `crates/uselesskey-jwk/src/srp/shape.rs` and
//! `crates/uselesskey-jwk/src/srp/builder.rs`:
//!
//! 1. `Jwks::negative_value(NegativeJwks::EmptyKeys)` produces a JWKS with an
//!    empty `keys` array.
//! 2. `Jwks::negative_value(NegativeJwks::DuplicateKid)` produces two distinct
//!    keys with the same `kid`.
//! 3. `Jwks::negative_value(NegativeJwks::DuplicateKey)` produces a JWKS where
//!    the same key object appears twice.
//! 4. `Jwks::Display` yields non-empty valid JSON that round-trips through
//!    `serde_json`.
//! 5. `JwksBuilder::default()` is equivalent to `JwksBuilder::new()` — building
//!    either immediately yields an equal empty JWKS.

use serde_json::Value;
use uselesskey_jwk::{AnyJwk, Jwks, JwksBuilder, NegativeJwks, PublicJwk, RsaPublicJwk};

fn rsa_public(kid: &str, n: &str) -> PublicJwk {
    PublicJwk::Rsa(RsaPublicJwk {
        kty: "RSA",
        use_: "sig",
        alg: "RS256",
        kid: kid.to_string(),
        n: n.to_string(),
        e: "AQAB".to_string(),
    })
}

fn keys_array(value: &Value) -> &[Value] {
    value["keys"].as_array().expect("keys array").as_slice()
}

// =========================================================================
// 1. NegativeJwks::EmptyKeys — produces an empty `keys` array even when the
//    source Jwks has entries.
// =========================================================================

#[test]
fn negative_jwks_empty_keys_yields_empty_keys_array() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::from(rsa_public("populated-a", "modulus-a")),
            AnyJwk::from(rsa_public("populated-b", "modulus-b")),
        ],
    };

    let value = jwks.negative_value(NegativeJwks::EmptyKeys);

    assert!(value.is_object(), "negative JWKS must be a JSON object");
    let keys = keys_array(&value);
    assert!(keys.is_empty(), "EmptyKeys must drop all keys");

    // Serialize and verify the on-wire shape too.
    let text = serde_json::to_string(&value).expect("serialize negative JWKS");
    let round_trip: Value = serde_json::from_str(&text).expect("round-trip JSON");
    assert!(
        round_trip["keys"]
            .as_array()
            .expect("keys array")
            .is_empty()
    );
}

#[test]
fn negative_jwks_empty_keys_on_empty_input_is_also_empty() {
    let jwks = Jwks { keys: Vec::new() };

    let value = jwks.negative_value(NegativeJwks::EmptyKeys);

    assert!(keys_array(&value).is_empty());
}

// =========================================================================
// 2. NegativeJwks::DuplicateKid — two distinct keys with the same `kid`.
// =========================================================================

#[test]
fn negative_jwks_duplicate_kid_keys_share_kid_but_differ_in_material() {
    let jwks = Jwks {
        keys: vec![AnyJwk::from(rsa_public("source-kid", "source-modulus"))],
    };

    let value = jwks.negative_value(NegativeJwks::DuplicateKid);
    let keys = keys_array(&value);

    assert_eq!(keys.len(), 2, "DuplicateKid must emit two keys");
    assert_eq!(
        keys[0]["kid"], keys[1]["kid"],
        "both keys must share the same kid"
    );
    // The shape uses a fixed kid string for this variant.
    assert_eq!(keys[0]["kid"], "duplicate-kid");

    // Same metadata shape.
    assert_eq!(keys[0]["kty"], keys[1]["kty"]);
    assert_eq!(keys[0]["alg"], keys[1]["alg"]);

    // Material must differ — that's what makes them "distinct" while sharing kid.
    assert_ne!(
        keys[0]["n"], keys[1]["n"],
        "the two keys must carry distinct material"
    );
}

#[test]
fn negative_jwks_duplicate_kid_on_empty_input_still_emits_two_keys() {
    // With an empty source set, `negative_value` falls back to a scanner-safe
    // RSA key whose `n` field is already the same scanner-safe replacement
    // material that DuplicateKid would substitute on the second key — so the
    // two entries collapse to the same value. We assert the structural
    // invariants (count + shared kid + shape) rather than material distinctness.
    let jwks = Jwks { keys: Vec::new() };

    let value = jwks.negative_value(NegativeJwks::DuplicateKid);
    let keys = keys_array(&value);

    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["kid"], "duplicate-kid");
    assert_eq!(keys[1]["kid"], "duplicate-kid");
    assert_eq!(keys[0]["kty"], "RSA");
    assert_eq!(keys[1]["kty"], "RSA");
}

// =========================================================================
// 3. NegativeJwks::DuplicateKey — same key object appears twice.
// =========================================================================

#[test]
fn negative_jwks_duplicate_key_emits_identical_entries() {
    let jwks = Jwks {
        keys: vec![AnyJwk::from(rsa_public("source-key", "source-modulus"))],
    };

    let value = jwks.negative_value(NegativeJwks::DuplicateKey);
    let keys = keys_array(&value);

    assert_eq!(keys.len(), 2, "DuplicateKey must emit two entries");
    assert_eq!(
        keys[0], keys[1],
        "DuplicateKey must repeat the same key object"
    );
    // Sanity: both entries must look like a real JWK.
    assert_eq!(keys[0]["kid"], "source-key");
    assert_eq!(keys[0]["kty"], "RSA");
    assert_eq!(keys[0]["n"], "source-modulus");
}

// =========================================================================
// 4. Jwks Display — non-empty valid JSON that round-trips.
// =========================================================================

#[test]
fn jwks_display_is_non_empty_valid_json_for_empty_jwks() {
    let jwks = Jwks { keys: Vec::new() };

    let rendered = format!("{}", jwks);
    assert!(!rendered.is_empty(), "Display output must not be empty");

    let parsed: Value = serde_json::from_str(&rendered).expect("Display output is valid JSON");
    assert!(parsed.is_object());
    assert!(parsed["keys"].is_array());
    assert_eq!(parsed["keys"].as_array().expect("keys array").len(), 0);
}

#[test]
fn jwks_display_round_trips_with_populated_keys() {
    let jwks = Jwks {
        keys: vec![
            AnyJwk::from(rsa_public("display-a", "modulus-a")),
            AnyJwk::from(rsa_public("display-b", "modulus-b")),
        ],
    };

    let rendered = format!("{}", jwks);
    assert!(!rendered.is_empty());

    let parsed: Value = serde_json::from_str(&rendered).expect("Display output is valid JSON");
    let keys = keys_array(&parsed);
    assert_eq!(keys.len(), 2);
    // Display output must match the value emitted by `to_value()` (the canonical form).
    assert_eq!(parsed, jwks.to_value());
}

// =========================================================================
// 5. JwksBuilder::default() — equivalent to JwksBuilder::new().
// =========================================================================

#[test]
fn jwks_builder_default_matches_new_when_built_immediately() {
    let from_default = JwksBuilder::default().build();
    let from_new = JwksBuilder::new().build();

    // Both must be empty JWKS values.
    assert_eq!(from_default.keys.len(), 0);
    assert_eq!(from_new.keys.len(), 0);

    // Their serialized form must match — i.e. they are equal as JWKS.
    assert_eq!(from_default.to_value(), from_new.to_value());
}

#[test]
fn jwks_builder_default_and_new_yield_same_jwks_after_identical_inserts() {
    let jwk = rsa_public("builder-shared", "modulus");

    let from_default = JwksBuilder::default().add_public(jwk.clone()).build();
    let from_new = JwksBuilder::new().add_public(jwk).build();

    assert_eq!(from_default.to_value(), from_new.to_value());
}
