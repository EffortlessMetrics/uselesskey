#![no_main]

use libfuzzer_sys::fuzz_target;

use uselesskey_core_id::{ArtifactId, DerivationVersion, Seed, derive_seed};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    // Use the first 32 bytes as the master seed.
    let mut seed_bytes = [0u8; 32];
    seed_bytes.copy_from_slice(&data[..32]);
    let master = Seed::new(seed_bytes);

    let rest = &data[32..];

    // Split the remaining bytes into label, spec, and variant.
    let parts: Vec<&[u8]> = rest.splitn(3, |&b| b == 0).collect();
    let label = String::from_utf8_lossy(parts.first().copied().unwrap_or(b""));
    let spec_bytes = parts.get(1).copied().unwrap_or(b"");
    let variant = String::from_utf8_lossy(parts.get(2).copied().unwrap_or(b""));

    let id = ArtifactId::new(
        "fuzz:domain",
        label.as_ref(),
        spec_bytes,
        variant.as_ref(),
        DerivationVersion::V1,
    );

    // Derive seed and verify determinism.
    let derived_a = derive_seed(&master, &id);
    let derived_b = derive_seed(&master, &id);
    assert_eq!(derived_a.bytes(), derived_b.bytes());
});
