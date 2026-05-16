//! Extra coverage for `uselesskey-pgp`:
//!
//! - Pin `DOMAIN_PGP_KEYPAIR` so an accidental rename trips a test rather
//!   than silently re-keying every cached and deterministic PGP fixture
//!   downstream. Mirrors the existing pins for `DOMAIN_HMAC_SECRET`,
//!   `DOMAIN_ED25519_KEYPAIR`, and `DOMAIN_ENTROPY_FIXTURE` in their
//!   respective `*_extra_coverage.rs` files.
//! - Cover `write_private_key_armored` / `write_public_key_armored` from
//!   within this crate's own test suite. The facade crate exercises them,
//!   but no in-crate test asserted the path/contents previously.
//! - Pin `PgpSpec` `Copy`/`Hash` derive participation so a future field
//!   addition that drops `Copy` or `Hash` fails compilation in tests.
//! - Pin `mismatched_public_key_armored` content shape so the
//!   "valid armor / different fingerprint" contract stays explicit.
//!
//! Follows the established `<crate>_extra_coverage.rs` pattern used by
//! `uselesskey-hmac`, `uselesskey-ed25519`, `uselesskey-entropy`, and
//! `uselesskey-jwk`. Tests-only — no production code changes.

use std::collections::HashSet;
use std::fs;

use uselesskey_core::{Factory, Seed};
use uselesskey_pgp::{DOMAIN_PGP_KEYPAIR, PgpFactoryExt, PgpSpec};
use uselesskey_test_support::{TestResult, ensure, ensure_eq, require_ok};

fn det_fx(seed_label: &str) -> TestResult<Factory> {
    Ok(Factory::deterministic(require_ok(
        Seed::from_env_value(seed_label),
        "valid deterministic seed",
    )?))
}

#[test]
fn domain_constant_is_stable() {
    assert_eq!(DOMAIN_PGP_KEYPAIR, "uselesskey:pgp:keypair");
}

#[test]
fn pgp_spec_is_copy_and_usable_after_move() {
    let original = PgpSpec::ed25519();
    let copied = original; // Copy, not move — `original` is still usable below.
    assert_eq!(original.kind_name(), "ed25519");
    assert_eq!(copied.kind_name(), "ed25519");
}

#[test]
fn pgp_spec_participates_in_hash_collections() {
    let mut set: HashSet<PgpSpec> = HashSet::new();
    set.insert(PgpSpec::Rsa2048);
    set.insert(PgpSpec::Rsa3072);
    set.insert(PgpSpec::Ed25519);
    // Inserting a duplicate must collide.
    set.insert(PgpSpec::ed25519());
    assert_eq!(set.len(), 3);
    assert!(set.contains(&PgpSpec::Ed25519));
}

#[test]
fn write_private_key_armored_round_trips_to_file() -> TestResult<()> {
    let fx = det_fx("pgp-write-private")?;
    let key = fx.pgp("write-priv", PgpSpec::ed25519());

    let artifact = require_ok(key.write_private_key_armored(), "write private armored")?;
    let path = artifact.path();
    ensure!(path.exists());

    let on_disk = require_ok(fs::read_to_string(path), "read private armored tempfile")?;
    ensure_eq!(on_disk.as_str(), key.private_key_armored());
    ensure!(on_disk.contains("BEGIN PGP PRIVATE KEY BLOCK"));
    Ok(())
}

#[test]
fn write_public_key_armored_round_trips_to_file() -> TestResult<()> {
    let fx = det_fx("pgp-write-public")?;
    let key = fx.pgp("write-pub", PgpSpec::ed25519());

    let artifact = require_ok(key.write_public_key_armored(), "write public armored")?;
    let path = artifact.path();
    ensure!(path.exists());

    let on_disk = require_ok(fs::read_to_string(path), "read public armored tempfile")?;
    ensure_eq!(on_disk.as_str(), key.public_key_armored());
    ensure!(on_disk.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    Ok(())
}

#[test]
fn mismatched_public_key_armored_is_distinct_pgp_armor() -> TestResult<()> {
    let fx = det_fx("pgp-mismatch-armor-shape")?;
    let key = fx.pgp("mismatch-svc", PgpSpec::ed25519());

    let mismatch = key.mismatched_public_key_armored();
    ensure!(mismatch.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    ensure!(mismatch.contains("END PGP PUBLIC KEY BLOCK"));
    ensure!(mismatch != key.public_key_armored());
    Ok(())
}

#[test]
fn pgp_keypair_clone_preserves_label_spec_and_material() -> TestResult<()> {
    let fx = det_fx("pgp-clone-preserve")?;
    let original = fx.pgp("clone-svc", PgpSpec::ed25519());
    let cloned = original.clone();

    ensure_eq!(original.label(), cloned.label());
    ensure_eq!(original.spec(), cloned.spec());
    ensure_eq!(original.fingerprint(), cloned.fingerprint());
    ensure_eq!(original.private_key_armored(), cloned.private_key_armored());
    ensure_eq!(original.public_key_armored(), cloned.public_key_armored());
    Ok(())
}
