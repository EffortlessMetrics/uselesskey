//! Extra coverage for `uselesskey-ecdsa`:
//!
//! - Pin `DOMAIN_ECDSA_KEYPAIR` so an accidental rename trips a test rather
//!   than silently re-keying every cached and deterministic ECDSA fixture
//!   downstream. Mirrors the existing pin for `DOMAIN_HMAC_SECRET` in
//!   `uselesskey-hmac/tests/hmac_extra_coverage.rs` and
//!   `DOMAIN_ED25519_KEYPAIR` in
//!   `uselesskey-ed25519/tests/ed25519_extra_coverage.rs`.
//! - Pin `EcdsaSpec` `Copy` semantics and `Hash` participation in
//!   `HashSet` so the derive list can't silently lose `Copy` or `Hash`.
//! - Pin a few `EcdsaSpec` value-equivalences (`Es256` produced by both
//!   the variant and the constructor compares equal) so a future addition
//!   of an internal payload field can't quietly break `PartialEq`.
//!
//! Follows the established `<crate>_extra_coverage.rs` pattern used by
//! `uselesskey-hmac`, `uselesskey-ed25519`, `uselesskey-entropy`, and
//! `uselesskey-jwk`. Tests-only — no production code changes.

use std::collections::HashSet;

use uselesskey_ecdsa::{DOMAIN_ECDSA_KEYPAIR, EcdsaSpec};

#[test]
fn domain_constant_is_stable() {
    assert_eq!(DOMAIN_ECDSA_KEYPAIR, "uselesskey:ecdsa:keypair");
}

#[test]
fn spec_is_copy_and_usable_after_move() {
    let original = EcdsaSpec::es256();
    let copied = original; // Copy, not move — `original` is still usable below.
    assert_eq!(original.alg_name(), "ES256");
    assert_eq!(copied.alg_name(), "ES256");
}

#[test]
fn spec_participates_in_hash_collections() {
    let mut set: HashSet<EcdsaSpec> = HashSet::new();
    set.insert(EcdsaSpec::Es256);
    set.insert(EcdsaSpec::Es384);
    // Inserting a duplicate must collide.
    set.insert(EcdsaSpec::es256());
    assert_eq!(set.len(), 2);
    assert!(set.contains(&EcdsaSpec::Es256));
    assert!(set.contains(&EcdsaSpec::Es384));
}

#[test]
fn constructor_and_variant_compare_equal() {
    assert_eq!(EcdsaSpec::es256(), EcdsaSpec::Es256);
    assert_eq!(EcdsaSpec::es384(), EcdsaSpec::Es384);
    // And distinct variants must remain distinct under `PartialEq`.
    assert_ne!(EcdsaSpec::es256(), EcdsaSpec::es384());
}

#[test]
fn coordinate_lengths_match_curve_bit_sizes_div_eight() {
    assert_eq!(EcdsaSpec::Es256.coordinate_len_bytes(), 256 / 8);
    assert_eq!(EcdsaSpec::Es384.coordinate_len_bytes(), 384 / 8);
}
