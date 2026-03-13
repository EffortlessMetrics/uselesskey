#![no_main]

use libfuzzer_sys::fuzz_target;

use std::sync::Arc;
use std::thread;
use uselesskey::Seed;
use uselesskey_core_factory::Factory;

fuzz_target!(|data: &[u8]| {
    if data.len() < 34 {
        return;
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);
    let thread_count = ((data[32] % 8) + 2) as usize;
    let variant_count = ((data[33] % 4) + 1) as usize;

    let factory = Factory::deterministic(Seed::new(seed));

    // Spawn threads that concurrently call get_or_init with same and different keys
    let handles: Vec<_> = (0..thread_count)
        .map(|_t| {
            let fx = factory.clone();
            thread::spawn(move || {
                let mut results = Vec::new();
                for v in 0..variant_count {
                    let label = format!("label-{}", v);
                    let val: Arc<u64> =
                        fx.get_or_init("fuzz", &label, b"spec", "v", |seed| {
                            let mut buf = [0u8; 8];
                            seed.fill_bytes(&mut buf);
                            u64::from_le_bytes(buf)
                        });
                    results.push((label, val));
                }
                // Each thread also re-fetches to confirm cache hit
                for v in 0..variant_count {
                    let label = format!("label-{}", v);
                    let val2: Arc<u64> =
                        fx.get_or_init("fuzz", &label, b"spec", "v", |seed| {
                            let mut buf = [0u8; 8];
                            seed.fill_bytes(&mut buf);
                            u64::from_le_bytes(buf)
                        });
                    // Value must match (deterministic derivation)
                    assert_eq!(*val2, *results[v].1);
                }
                results
            })
        })
        .collect();

    let all_results: Vec<Vec<(String, Arc<u64>)>> =
        handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All threads must agree on the same value for each label
    for v in 0..variant_count {
        let expected = &all_results[0][v].1;
        for thread_results in &all_results[1..] {
            assert_eq!(
                *thread_results[v].1, **expected,
                "threads disagree on value for label-{v}"
            );
        }
    }
});
