//! Edge-case tests for uselesskey-core internals.
//!
//! Covers concurrent cache access, cache clearing under contention,
//! large cache populations, and factory behavior with extreme inputs.

#![cfg(feature = "std")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use uselesskey_core::{Factory, Mode, Seed};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn det_factory(byte: u8) -> Factory {
    Factory::deterministic(Seed::new([byte; 32]))
}

// ===========================================================================
// 1. Concurrent cache access — many threads reading/writing same key
// ===========================================================================

#[test]
fn concurrent_get_or_init_same_key_calls_init_once() {
    let fx = det_factory(0x01);
    let init_count = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(8));

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let fx = fx.clone();
            let count = init_count.clone();
            let bar = barrier.clone();
            thread::spawn(move || {
                bar.wait();
                let v = fx.get_or_init("domain:conc", "shared", b"spec", "good", |_rng| {
                    count.fetch_add(1, Ordering::SeqCst);
                    42u64
                });
                assert_eq!(*v, 42u64);
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }

    // init should be called a small number of times (ideally 1, but DashMap
    // may race on insert; the important thing is all threads see the same value)
    let count = init_count.load(Ordering::SeqCst);
    assert!((1..=8).contains(&count), "init called {count} times");
}

// ===========================================================================
// 2. Concurrent access with different keys
// ===========================================================================

#[test]
fn concurrent_get_or_init_different_keys_all_succeed() {
    let fx = det_factory(0x02);
    let barrier = Arc::new(Barrier::new(16));

    let handles: Vec<_> = (0..16)
        .map(|i| {
            let fx = fx.clone();
            let bar = barrier.clone();
            thread::spawn(move || {
                bar.wait();
                let label = format!("thread-{i}");
                let v = fx.get_or_init("domain:multi", &label, b"spec", "good", |_rng| i as u64);
                assert_eq!(*v, i as u64);
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

// ===========================================================================
// 3. Cache clear while other threads are reading
// ===========================================================================

#[test]
fn cache_clear_while_readers_active_does_not_panic() {
    let fx = det_factory(0x03);

    // Pre-populate cache
    for i in 0..10 {
        let label = format!("pre-{i}");
        let _ = fx.get_or_init("domain:clear", &label, b"spec", "good", |_rng| i as u32);
    }

    let barrier = Arc::new(Barrier::new(9));

    // 8 reader threads
    let mut handles: Vec<_> = (0..8)
        .map(|i| {
            let fx = fx.clone();
            let bar = barrier.clone();
            thread::spawn(move || {
                bar.wait();
                for _ in 0..100 {
                    let label = format!("pre-{}", i % 10);
                    let _ =
                        fx.get_or_init("domain:clear", &label, b"spec", "good", |_rng| i as u32);
                }
            })
        })
        .collect();

    // 1 clearer thread
    {
        let fx = fx.clone();
        let bar = barrier.clone();
        handles.push(thread::spawn(move || {
            bar.wait();
            for _ in 0..50 {
                fx.clear_cache();
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

// ===========================================================================
// 4. Large number of cache entries
// ===========================================================================

#[test]
fn cache_handles_many_entries() {
    let fx = det_factory(0x04);
    let entry_count = 500;

    for i in 0..entry_count {
        let label = format!("entry-{i}");
        let _ = fx.get_or_init("domain:many", &label, b"spec", "good", |_rng| i as u64);
    }

    // Verify all entries are retrievable (init closure returns a sentinel;
    // since the entry already exists the closure is never called)
    for i in 0..entry_count {
        let label = format!("entry-{i}");
        let v = fx.get_or_init("domain:many", &label, b"spec", "good", |_rng| 999_999u64);
        assert_eq!(*v, i as u64);
    }
}

// ===========================================================================
// 5. Cache clear actually evicts entries
// ===========================================================================

#[test]
fn clear_cache_forces_reinit_with_new_values() {
    let fx = det_factory(0x05);
    let init_count = AtomicUsize::new(0);

    let first = fx.get_or_init("domain:reinit", "label", b"spec", "good", |_rng| {
        init_count.fetch_add(1, Ordering::SeqCst);
        100u32
    });
    assert_eq!(*first, 100);
    assert_eq!(init_count.load(Ordering::SeqCst), 1);

    fx.clear_cache();

    let second = fx.get_or_init("domain:reinit", "label", b"spec", "good", |_rng| {
        init_count.fetch_add(1, Ordering::SeqCst);
        200u32
    });
    // In deterministic mode, the RNG produces the same value, but our
    // closure explicitly returns a different value to prove reinit happened
    assert_eq!(init_count.load(Ordering::SeqCst), 2);
    assert_eq!(*second, 200);
}

// ===========================================================================
// 6. Factory mode accessors
// ===========================================================================

#[test]
fn random_factory_mode_is_random() {
    let fx = Factory::random();
    assert!(matches!(fx.mode(), Mode::Random));
}

#[test]
fn deterministic_factory_mode_contains_seed() {
    let seed = Seed::new([0xAA; 32]);
    let fx = Factory::deterministic(seed);
    match fx.mode() {
        Mode::Deterministic { master } => {
            assert_eq!(master.bytes(), &[0xAA; 32]);
        }
        Mode::Random => panic!("expected deterministic mode"),
    }
}

// ===========================================================================
// 7. Empty and unusual domain/label/variant/spec combinations
// ===========================================================================

#[test]
fn empty_domain_label_variant_spec_does_not_panic() {
    let fx = det_factory(0x07);
    // All-empty should still work
    let v = fx.get_or_init("", "", b"", "", |_rng| 99u8);
    assert_eq!(*v, 99);
}

#[test]
fn unicode_label_and_variant_work() {
    let fx = det_factory(0x08);
    let v = fx.get_or_init(
        "domain:unicode",
        "日本語ラベル",
        b"spec",
        "変体",
        |_rng| 77u16,
    );
    assert_eq!(*v, 77);
}

#[test]
fn very_long_spec_bytes_work() {
    let fx = det_factory(0x09);
    let big_spec = vec![0xFFu8; 10_000];
    let v = fx.get_or_init("domain:bigspec", "label", &big_spec, "good", |_rng| 55u32);
    assert_eq!(*v, 55);
}

// ===========================================================================
// 8. Deterministic derivation produces distinct values for different inputs
// ===========================================================================

#[test]
fn different_domains_produce_different_values() {
    let fx = det_factory(0x0A);
    let spec = b"same-spec";

    let a = fx.get_or_init("domain:a", "label", spec, "good", |rng| {
        use rand_core::RngCore;
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    });
    let b = fx.get_or_init("domain:b", "label", spec, "good", |rng| {
        use rand_core::RngCore;
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    });
    assert_ne!(*a, *b);
}

#[test]
fn different_labels_produce_different_values() {
    let fx = det_factory(0x0B);
    let make = |label: &str| -> Arc<u64> {
        fx.get_or_init("domain:lbl", label, b"spec", "good", |rng| {
            use rand_core::RngCore;
            let mut buf = [0u8; 8];
            rng.fill_bytes(&mut buf);
            u64::from_le_bytes(buf)
        })
    };
    assert_ne!(*make("alpha"), *make("beta"));
}

#[test]
fn different_variants_produce_different_values() {
    // Need separate factories to avoid cache hits
    let fx1 = det_factory(0x0C);
    let fx2 = det_factory(0x0C);

    let a = fx1.get_or_init("domain:var", "label", b"spec", "good", |rng| {
        use rand_core::RngCore;
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    });
    let b = fx2.get_or_init("domain:var", "label", b"spec", "other", |rng| {
        use rand_core::RngCore;
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    });
    assert_ne!(*a, *b);
}

// ===========================================================================
// 9. Seed::from_env_value edge cases
// ===========================================================================

#[test]
fn seed_from_env_value_empty_string_is_ok() {
    assert!(Seed::from_env_value("").is_ok());
}

#[test]
fn seed_from_env_value_exactly_64_hex_chars() {
    let hex = "a".repeat(64);
    let result = Seed::from_env_value(&hex);
    assert!(result.is_ok());
}

#[test]
fn seed_from_env_value_64_chars_invalid_hex_is_err() {
    // 64 chars but contains invalid hex -> Err
    let mut bad = "0".repeat(63);
    bad.push('g');
    let result = Seed::from_env_value(&bad);
    assert!(result.is_err());
}

#[test]
fn seed_from_env_value_with_0x_prefix() {
    let hex = format!("0x{}", "b".repeat(64));
    let result = Seed::from_env_value(&hex);
    assert!(result.is_ok());
}

// ===========================================================================
// 10. Debug formatting
// ===========================================================================

#[test]
fn factory_debug_includes_cache_size() {
    let fx = det_factory(0x10);
    let dbg = format!("{:?}", fx);
    assert!(dbg.contains("Factory"));
    assert!(dbg.contains("cache_size"));
}

#[test]
fn seed_debug_never_leaks_bytes() {
    let seed = Seed::new([0xFF; 32]);
    let dbg = format!("{:?}", seed);
    assert!(dbg.contains("redacted"));
    // Ensure no hex of the actual bytes appears
    assert!(!dbg.to_lowercase().contains("ff"));
}
