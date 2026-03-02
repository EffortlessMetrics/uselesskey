#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use rand_core::RngCore;
use std::sync::Arc;
use std::thread;
use uselesskey::Seed;
use uselesskey_core_factory::Factory;

const DOMAINS: &[&str] = &["fuzz:alpha", "fuzz:beta", "fuzz:gamma", "fuzz:delta"];

#[derive(Arbitrary, Debug)]
struct ConcurrentInput {
    seed: [u8; 32],
    thread_count: u8,
    variant_count: u8,
    domain_idx: u8,
    spec_bytes: Vec<u8>,
    clear_cache_after: u8,
}

fuzz_target!(|input: ConcurrentInput| {
    let thread_count = ((input.thread_count % 6) + 2) as usize;
    let variant_count = ((input.variant_count % 4) + 1) as usize;
    let domain = DOMAINS[input.domain_idx as usize % DOMAINS.len()];

    // Cap spec_bytes to avoid excessive allocations.
    let spec_bytes: &[u8] = if input.spec_bytes.len() > 128 {
        &input.spec_bytes[..128]
    } else {
        &input.spec_bytes
    };

    let factory = Factory::deterministic(Seed::new(input.seed));

    // Phase 1: Concurrent get_or_init with multiple labels and varying specs.
    let spec_owned: Vec<u8> = spec_bytes.to_vec();
    let handles: Vec<_> = (0..thread_count)
        .map(|_| {
            let fx = factory.clone();
            let sp = spec_owned.clone();
            thread::spawn(move || {
                let mut results = Vec::new();
                for v in 0..variant_count {
                    let label = format!("label-{v}");
                    let val: Arc<u64> =
                        fx.get_or_init(domain, &label, &sp, "v", |rng| {
                            let mut buf = [0u8; 8];
                            rng.fill_bytes(&mut buf);
                            u64::from_le_bytes(buf)
                        });
                    results.push((label, val));
                }
                // Re-fetch to confirm cache hits.
                for v in 0..variant_count {
                    let label = format!("label-{v}");
                    let val2: Arc<u64> =
                        fx.get_or_init(domain, &label, &sp, "v", |rng| {
                            let mut buf = [0u8; 8];
                            rng.fill_bytes(&mut buf);
                            u64::from_le_bytes(buf)
                        });
                    assert_eq!(*val2, *results[v].1);
                }
                results
            })
        })
        .collect();

    let all_results: Vec<Vec<(String, Arc<u64>)>> =
        handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All threads must agree on the same value for each label.
    for v in 0..variant_count {
        let expected = &all_results[0][v].1;
        for thread_results in &all_results[1..] {
            assert_eq!(
                *thread_results[v].1, **expected,
                "threads disagree on value for label-{v}"
            );
        }
    }

    // Phase 2: Clear cache and re-derive — values must be identical (deterministic).
    if input.clear_cache_after % 3 == 0 {
        factory.clear_cache();

        for v in 0..variant_count {
            let label = format!("label-{v}");
            let val: Arc<u64> =
                factory.get_or_init(domain, &label, &spec_owned, "v", |rng| {
                    let mut buf = [0u8; 8];
                    rng.fill_bytes(&mut buf);
                    u64::from_le_bytes(buf)
                });

            assert_eq!(
                *val, *all_results[0][v].1,
                "post-cache-clear value must match (deterministic derivation)"
            );
        }
    }

    // Phase 3: Different domain must produce independent values.
    let alt_domain = DOMAINS[(input.domain_idx as usize + 1) % DOMAINS.len()];
    if alt_domain != domain {
        let val_alt: Arc<u64> =
            factory.get_or_init(alt_domain, "label-0", &spec_owned, "v", |rng| {
                let mut buf = [0u8; 8];
                rng.fill_bytes(&mut buf);
                u64::from_le_bytes(buf)
            });
        // Different domain may or may not produce same value, but must not panic.
        let _ = val_alt;
    }
});
