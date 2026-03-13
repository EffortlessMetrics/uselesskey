#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use uselesskey::Seed;
use uselesskey_core_factory::Factory;

fuzz_target!(|data: &[u8]| {
    let mut seed = [0u8; 32];
    let read = data.len().min(seed.len());
    seed[..read].copy_from_slice(&data[..read]);

    let factory = Factory::deterministic(Seed::new(seed));

    let domain = "fuzz-domain";
    let label = format!("label-{}", data.len());
    let spec = format!("spec-{}", data.first().copied().unwrap_or(0));
    let variant = "v";

    let first: Arc<u64> = factory.get_or_init(domain, &label, spec.as_bytes(), variant, |rng| {
        let mut out = [0u8; 8];
        rng.fill_bytes(&mut out);
        u64::from_le_bytes(out)
    });

    let second: Arc<u64> = factory.get_or_init(domain, &label, spec.as_bytes(), variant, |rng| {
        let mut fallback = [0u8; 8];
        rng.fill_bytes(&mut fallback);
        u64::from_le_bytes(fallback)
    });

    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(*first, *second);

    factory.clear_cache();

    let third: Arc<u64> = factory.get_or_init(domain, &label, spec.as_bytes(), variant, |rng| {
        let mut out = [0u8; 8];
        rng.fill_bytes(&mut out);
        u64::from_le_bytes(out)
    });

    assert_eq!(*third, *first);
    assert!(!Arc::ptr_eq(&first, &third));
});
