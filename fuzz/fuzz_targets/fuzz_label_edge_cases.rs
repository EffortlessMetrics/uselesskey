#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use uselesskey::Seed;
use uselesskey_core_factory::Factory;
use uselesskey_core_id::{ArtifactId, DerivationVersion, derive_seed};

use rand_core::RngCore;
use std::sync::Arc;

#[derive(Arbitrary, Debug)]
struct LabelEdgeInput {
    seed: [u8; 32],
    labels: Vec<String>,
}

fuzz_target!(|input: LabelEdgeInput| {
    // Cap to avoid excessive allocations.
    if input.labels.len() > 32 {
        return;
    }
    for label in &input.labels {
        if label.len() > 1024 {
            return;
        }
    }

    let master = Seed::new(input.seed);
    let factory = Factory::deterministic(master);

    for label in &input.labels {
        // Derivation must not panic on any label.
        let id = ArtifactId::new(
            "fuzz:label-edge",
            label.as_str(),
            b"spec",
            "v",
            DerivationVersion::V1,
        );
        let d1 = derive_seed(&Seed::new(input.seed), &id);
        let d2 = derive_seed(&Seed::new(input.seed), &id);
        assert_eq!(d1.bytes(), d2.bytes());

        // Factory get_or_init must not panic.
        let val: Arc<u64> = factory.get_or_init(
            "fuzz:label-edge",
            label.as_str(),
            b"spec",
            "v",
            |rng| {
                let mut buf = [0u8; 8];
                rng.fill_bytes(&mut buf);
                u64::from_le_bytes(buf)
            },
        );

        // Cache hit must return same value.
        let val2: Arc<u64> = factory.get_or_init(
            "fuzz:label-edge",
            label.as_str(),
            b"spec",
            "v",
            |rng| {
                let mut buf = [0u8; 8];
                rng.fill_bytes(&mut buf);
                u64::from_le_bytes(buf)
            },
        );
        assert_eq!(*val, *val2);
    }

    // Verify distinct labels produce independent cache entries.
    let unique_labels: std::collections::HashSet<&String> = input.labels.iter().collect();
    if unique_labels.len() >= 2 {
        let mut iter = unique_labels.iter();
        let a = *iter.next().unwrap();
        let b = *iter.next().unwrap();

        let id_a = ArtifactId::new("fuzz:label-edge", a.as_str(), b"spec", "v", DerivationVersion::V1);
        let id_b = ArtifactId::new("fuzz:label-edge", b.as_str(), b"spec", "v", DerivationVersion::V1);
        let da = derive_seed(&Seed::new(input.seed), &id_a);
        let db = derive_seed(&Seed::new(input.seed), &id_b);
        // Different labels must produce different seeds (collision astronomically unlikely).
        assert_ne!(da.bytes(), db.bytes());
    }
});
