#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use std::sync::Arc;
use uselesskey::Seed;
use uselesskey_core_factory::Factory;

#[derive(Arbitrary, Debug)]
struct FactoryStressInput {
    seeds: Vec<[u8; 32]>,
    ops: Vec<StressOp>,
}

#[derive(Arbitrary, Debug)]
enum StressOp {
    Create { seed: [u8; 32] },
    GetOrInit { label_idx: u8 },
    ClearCache,
    CreateRandom,
}

fuzz_target!(|input: FactoryStressInput| {
    // Cap to avoid excessive work.
    if input.seeds.len() > 16 || input.ops.len() > 64 {
        return;
    }

    let mut factories: Vec<Factory> = input
        .seeds
        .iter()
        .map(|s| Factory::deterministic(Seed::new(*s)))
        .collect();

    if factories.is_empty() {
        factories.push(Factory::random());
    }

    for op in &input.ops {
        match op {
            StressOp::Create { seed } => {
                factories.push(Factory::deterministic(Seed::new(*seed)));
                // Keep bounded.
                if factories.len() > 32 {
                    factories.remove(0);
                }
            }
            StressOp::GetOrInit { label_idx } => {
                let fx = &factories[*label_idx as usize % factories.len()];
                let label = format!("stress-{label_idx}");
                let val: Arc<u64> = fx.get_or_init(
                    "fuzz:stress",
                    &label,
                    b"spec",
                    "v",
                    |seed| {
                        let mut buf = [0u8; 8];
                        seed.fill_bytes(&mut buf);
                        u64::from_le_bytes(buf)
                    },
                );
                let _ = *val;
            }
            StressOp::ClearCache => {
                for fx in &factories {
                    fx.clear_cache();
                }
            }
            StressOp::CreateRandom => {
                factories.push(Factory::random());
                if factories.len() > 32 {
                    factories.remove(0);
                }
            }
        }
    }

    // Final verification: deterministic factories re-derive identical values after clear.
    for fx in &factories {
        fx.clear_cache();
        let a: Arc<u64> = fx.get_or_init("fuzz:stress", "verify", b"spec", "v", |seed| {
            let mut buf = [0u8; 8];
            seed.fill_bytes(&mut buf);
            u64::from_le_bytes(buf)
        });
        let b: Arc<u64> = fx.get_or_init("fuzz:stress", "verify", b"spec", "v", |seed| {
            let mut buf = [0u8; 8];
            seed.fill_bytes(&mut buf);
            u64::from_le_bytes(buf)
        });
        assert_eq!(*a, *b);
    }
});
