#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey_core_id::{ArtifactId, DerivationVersion, Seed, derive_seed};

#[derive(Arbitrary, Debug)]
struct SeedDerivationInput {
    master: [u8; 32],
    label: String,
    spec_bytes: Vec<u8>,
    variant: String,
}

fuzz_target!(|input: SeedDerivationInput| {
    let master = Seed::new(input.master);
    let id = ArtifactId::new(
        "fuzz",
        &input.label,
        &input.spec_bytes,
        &input.variant,
        DerivationVersion::V1,
    );

    // Core property: same input must always produce the same output.
    let seed1 = derive_seed(&master, &id);
    let seed2 = derive_seed(&master, &id);
    assert_eq!(seed1.bytes(), seed2.bytes());

    // Different label should not panic (collision possible, just test stability).
    let id_alt_label = ArtifactId::new(
        "fuzz",
        &format!("{}-alt", input.label),
        &input.spec_bytes,
        &input.variant,
        DerivationVersion::V1,
    );
    let _ = derive_seed(&master, &id_alt_label);

    // Different variant should not panic.
    let id_alt_variant = ArtifactId::new(
        "fuzz",
        &input.label,
        &input.spec_bytes,
        &format!("{}-alt", input.variant),
        DerivationVersion::V1,
    );
    let _ = derive_seed(&master, &id_alt_variant);

    // Different spec bytes should not panic.
    let mut alt_spec = input.spec_bytes.clone();
    alt_spec.push(0xFF);
    let id_alt_spec = ArtifactId::new(
        "fuzz",
        &input.label,
        &alt_spec,
        &input.variant,
        DerivationVersion::V1,
    );
    let _ = derive_seed(&master, &id_alt_spec);
});
