#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::Seed;
use uselesskey_core_id::{ArtifactId, DerivationVersion, derive_seed};

#[derive(Arbitrary, Debug)]
struct SeedEdgeInput {
    raw_seed: Vec<u8>,
    label: String,
}

fuzz_target!(|input: SeedEdgeInput| {
    // Cap to avoid excessive allocations.
    if input.raw_seed.len() > 4096 || input.label.len() > 256 {
        return;
    }

    // --- Empty seed ---
    let zero_seed = Seed::new([0u8; 32]);
    let id = ArtifactId::new("fuzz:seed-edge", &input.label, b"spec", "v", DerivationVersion::V1);
    let d1 = derive_seed(&zero_seed, &id);
    let d2 = derive_seed(&zero_seed, &id);
    assert_eq!(d1.bytes(), d2.bytes(), "all-zeros seed must be deterministic");

    // --- All 0xFF seed ---
    let ff_seed = Seed::new([0xFF; 32]);
    let d3 = derive_seed(&ff_seed, &id);
    let d4 = derive_seed(&ff_seed, &id);
    assert_eq!(d3.bytes(), d4.bytes(), "all-0xFF seed must be deterministic");

    // Zero and 0xFF seeds must produce different derivations.
    assert_ne!(d1.bytes(), d3.bytes(), "all-zeros vs all-0xFF must differ");

    // --- Fuzz-supplied seed (truncated/padded to 32 bytes) ---
    let mut buf = [0u8; 32];
    let len = input.raw_seed.len().min(32);
    buf[..len].copy_from_slice(&input.raw_seed[..len]);
    let fuzz_seed = Seed::new(buf);
    let d5 = derive_seed(&fuzz_seed, &id);
    let d6 = derive_seed(&fuzz_seed, &id);
    assert_eq!(d5.bytes(), d6.bytes(), "fuzz seed must be deterministic");

    // --- Very long seed input via from_env_value (hashed to 32 bytes) ---
    let long_input: String = input
        .raw_seed
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if let Ok(parsed) = Seed::from_env_value(&long_input) {
        let d7 = derive_seed(&parsed, &id);
        let d8 = derive_seed(&parsed, &id);
        assert_eq!(d7.bytes(), d8.bytes());
        // Debug must never leak seed material.
        let dbg = format!("{parsed:?}");
        assert!(!dbg.contains(&long_input), "Debug must redact seed");
    }
});
