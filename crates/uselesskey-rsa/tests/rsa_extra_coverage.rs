//! Extra coverage for `uselesskey-rsa`:
//!
//! - Pin `DOMAIN_RSA_KEYPAIR` so an accidental rename trips a test rather
//!   than silently re-keying every cached and deterministic RSA fixture
//!   downstream.
//! - Pin `RsaSpec::stable_bytes()` byte ordering across bit sizes (the
//!   existing `mutant_killers.rs::stable_bytes_exact_encoding` only checks
//!   the `rs256()` case; the bit-size axis was unpinned past that).
//! - Pin a few `RsaSpec` constructor invariants that mutation testing can
//!   otherwise quietly invert.
//!
//! Follows the established `<crate>_extra_coverage.rs` pattern used by
//! `uselesskey-hmac`, `uselesskey-ed25519`, `uselesskey-entropy`, and
//! `uselesskey-jwk`. Tests-only — no production code changes.

use uselesskey_rsa::{DOMAIN_RSA_KEYPAIR, RsaSpec};
use uselesskey_test_support::{TestResult, ensure_eq};

#[test]
fn domain_constant_is_stable() {
    assert_eq!(DOMAIN_RSA_KEYPAIR, "uselesskey:rsa:keypair");
}

#[test]
fn stable_bytes_encodes_each_bit_size_as_be_u32() -> TestResult<()> {
    for bits in [2048usize, 3072, 4096] {
        let bytes = RsaSpec::new(bits).stable_bytes();
        ensure_eq!(&bytes[..4], &(bits as u32).to_be_bytes());
        ensure_eq!(&bytes[4..], &65537u32.to_be_bytes());
    }
    Ok(())
}

#[test]
fn stable_bytes_clamps_oversized_bit_count_to_u32_max() {
    // The implementation uses `u32::try_from(bits).unwrap_or(u32::MAX)`.
    // Pinning this is important because the alternative (panic on overflow,
    // or silent truncation) would change cache-key behaviour for unusual
    // specs without notice.
    let spec = RsaSpec::new(usize::MAX);
    let bytes = spec.stable_bytes();
    assert_eq!(&bytes[..4], &u32::MAX.to_be_bytes());
    assert_eq!(&bytes[4..], &65537u32.to_be_bytes());
}

#[test]
fn new_preserves_supplied_bits_without_clamping_in_struct() {
    // The struct field stays as-passed (the clamp only happens at
    // stable-byte encoding time). Pin this so the encoding-time clamp can't
    // be silently moved into the constructor.
    let spec = RsaSpec::new(usize::MAX);
    assert_eq!(spec.bits, usize::MAX);
}

#[test]
fn rs256_and_new_2048_agree_on_stable_bytes() {
    assert_eq!(
        RsaSpec::rs256().stable_bytes(),
        RsaSpec::new(2048).stable_bytes()
    );
}

#[test]
fn rs256_and_new_2048_compare_equal() {
    assert_eq!(RsaSpec::rs256(), RsaSpec::new(2048));
}
