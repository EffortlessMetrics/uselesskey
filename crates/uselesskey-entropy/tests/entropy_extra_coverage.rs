//! Extra coverage for uselesskey-entropy:
//!
//! - Domain constant invariant.
//! - Zero-length allocation and zero-length `fill_bytes` no-ops.
//! - `fill_bytes_with_variant` matches `bytes_with_variant`.
//! - Clone semantics.
//! - Debug omits byte material.

use uselesskey_core::{Factory, Seed};
use uselesskey_entropy::{DOMAIN_ENTROPY_FIXTURE, EntropyFactoryExt};
use uselesskey_test_support::{TestResult, require_ok};

fn det_fx(seed_label: &str) -> TestResult<Factory> {
    Ok(Factory::deterministic(require_ok(
        Seed::from_env_value(seed_label),
        "valid deterministic seed",
    )?))
}

#[test]
fn domain_constant_is_stable() {
    // This is part of the cache key; changing it would silently invalidate
    // every consumer's deterministic entropy. Pin it.
    assert_eq!(DOMAIN_ENTROPY_FIXTURE, "uselesskey:entropy:fixture");
}

#[test]
fn bytes_zero_returns_empty_vec() -> TestResult<()> {
    let fx = det_fx("entropy-zero")?;
    let out = fx.entropy("svc").bytes(0);
    assert!(out.is_empty());
    Ok(())
}

#[test]
fn fill_bytes_with_empty_slice_is_noop() -> TestResult<()> {
    let fx = det_fx("entropy-empty-fill")?;
    let mut empty: [u8; 0] = [];
    fx.entropy("svc").fill_bytes(&mut empty);
    assert!(empty.is_empty());
    Ok(())
}

#[test]
fn fill_bytes_with_variant_matches_bytes_with_variant() -> TestResult<()> {
    let fx = det_fx("entropy-fill-variant")?;
    let fixture = fx.entropy("svc");

    let expected = fixture.bytes_with_variant(64, "alt");
    let mut actual = vec![0u8; 64];
    fixture.fill_bytes_with_variant(&mut actual, "alt");

    assert_eq!(expected, actual);
    Ok(())
}

#[test]
fn clone_produces_same_bytes() -> TestResult<()> {
    let fx = det_fx("entropy-clone")?;
    let original = fx.entropy("svc");
    let cloned = original.clone();

    assert_eq!(original.bytes(32), cloned.bytes(32));
    assert_eq!(original.label(), cloned.label());
    assert_eq!(original.variant(), cloned.variant());
    Ok(())
}

#[test]
fn debug_includes_label_and_variant_but_no_byte_material() -> TestResult<()> {
    let fx = det_fx("entropy-debug-bytes")?;
    let fixture = fx.entropy_with_variant("svc", "custom-variant");
    // Ensure bytes are materialized in the cache so a leak would be visible.
    let bytes = fixture.bytes(48);

    let dbg = format!("{fixture:?}");
    assert!(dbg.contains("EntropyFixture"));
    assert!(dbg.contains("svc"));
    assert!(dbg.contains("custom-variant"));

    // Debug must not contain the materialized byte stream as contiguous hex.
    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert!(!dbg.contains(&hex), "debug leaked hex bytes: {dbg}");
    Ok(())
}

#[test]
fn variants_propagate_through_default_path() -> TestResult<()> {
    let fx = det_fx("entropy-variant-propagate")?;
    let default = fx.entropy("svc");
    let custom = fx.entropy_with_variant("svc", "custom");

    // The default path uses the variant set on the fixture handle.
    let default_bytes = default.bytes(32);
    let custom_bytes = custom.bytes(32);
    assert_ne!(default_bytes, custom_bytes);

    // And explicit variants match the variant-bound fixtures.
    let from_default_explicit = default.bytes_with_variant(32, "custom");
    assert_eq!(custom_bytes, from_default_explicit);
    Ok(())
}
