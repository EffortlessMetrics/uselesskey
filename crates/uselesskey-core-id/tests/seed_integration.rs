#![cfg(feature = "std")]

use uselesskey_core_id::{ArtifactId, DerivationVersion, Seed as ReexportedSeed, derive_seed};
use uselesskey_core_seed::Seed;
use uselesskey_test_support::{TestResult, require_ok};

#[test]
fn seed_from_core_seed_drives_core_id_derivation() -> TestResult<()> {
    let master = require_ok(
        Seed::from_env_value("core-seed-integration"),
        "core-seed-integration must parse as a deterministic seed",
    )?;
    let id = ArtifactId::new(
        "uselesskey:test",
        "entity",
        b"fixture-spec",
        "v1",
        DerivationVersion::V1,
    );

    let first = derive_seed(&master, &id);
    let second = derive_seed(&master, &id);
    assert_eq!(first.bytes(), second.bytes());
    Ok(())
}

#[test]
fn core_id_reexported_seed_matches_core_seed_type() {
    let seed = Seed::new([42u8; 32]);
    let reexported: ReexportedSeed = seed;
    assert_eq!(reexported.bytes(), seed.bytes());
}
