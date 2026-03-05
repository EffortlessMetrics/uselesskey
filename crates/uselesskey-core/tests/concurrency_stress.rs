//! Concurrency stress tests for the factory's DashMap-based cache.
//!
//! Exercises cache safety under high contention with 100 threads,
//! mixed read/write workloads, and determinism verification.

#![cfg(feature = "std")]

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use uselesskey_core::{Factory, Seed};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn det_factory(byte: u8) -> Factory {
    Factory::deterministic(Seed::new([byte; 32]))
}

/// Run a closure with a 30-second timeout, panicking if it exceeds the limit.
fn with_timeout<F: FnOnce() + Send + 'static>(f: F) {
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(()) => handle.join().unwrap(),
        Err(_) => panic!("test timed out after 30 seconds (possible deadlock)"),
    }
}

// ===========================================================================
// 1. Many-thread same-key — 100 threads all request the same key
// ===========================================================================

#[test]
fn stress_many_threads_same_key() {
    with_timeout(|| {
        let fx = det_factory(0xA1);
        let thread_count = 100;
        let barrier = Arc::new(Barrier::new(thread_count));

        let handles: Vec<_> = (0..thread_count)
            .map(|_| {
                let fx = fx.clone();
                let bar = barrier.clone();
                thread::spawn(move || {
                    bar.wait();
                    fx.get_or_init("stress:same", "shared-key", b"spec", "good", |rng| {
                        use rand_core::RngCore;
                        rng.next_u64()
                    })
                })
            })
            .collect();

        let results: Vec<Arc<u64>> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All threads must observe the same value.
        let first = *results[0];
        for (i, val) in results.iter().enumerate() {
            assert_eq!(**val, first, "thread {i} saw {}, expected {first}", **val);
        }
    });
}

// ===========================================================================
// 2. Many-thread different-keys — 100 threads each request a unique key
// ===========================================================================

#[test]
fn stress_many_threads_different_keys() {
    with_timeout(|| {
        let fx = det_factory(0xA2);
        let thread_count = 100;
        let barrier = Arc::new(Barrier::new(thread_count));

        // Leak labels so they have 'static lifetime for ArtifactDomain.
        let handles: Vec<_> = (0..thread_count)
            .map(|i| {
                let fx = fx.clone();
                let bar = barrier.clone();
                thread::spawn(move || {
                    bar.wait();
                    let label = format!("key-{i}");
                    let v = fx.get_or_init("stress:diff", &label, b"spec", "good", |_rng| i as u64);
                    assert_eq!(*v, i as u64, "thread {i} got wrong value");
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    });
}

// ===========================================================================
// 3. Mixed read-write — some threads generate keys, others read existing ones
// ===========================================================================

#[test]
fn stress_mixed_read_write() {
    with_timeout(|| {
        let fx = det_factory(0xA3);

        // Pre-populate 50 entries.
        for i in 0..50 {
            let label = format!("mixed-{i}");
            let _ = fx.get_or_init("stress:mixed", &label, b"spec", "good", |_rng| i as u64);
        }

        let thread_count = 100;
        let barrier = Arc::new(Barrier::new(thread_count));

        let handles: Vec<_> = (0..thread_count)
            .map(|i| {
                let fx = fx.clone();
                let bar = barrier.clone();
                thread::spawn(move || {
                    bar.wait();
                    if i < 50 {
                        // Reader: re-read a pre-populated key.
                        let label = format!("mixed-{i}");
                        let v = fx.get_or_init("stress:mixed", &label, b"spec", "good", |_rng| {
                            999_999u64
                        });
                        assert_eq!(
                            *v, i as u64,
                            "reader thread {i}: cache returned wrong value"
                        );
                    } else {
                        // Writer: create a brand-new key.
                        let label = format!("mixed-{i}");
                        let v = fx
                            .get_or_init("stress:mixed", &label, b"spec", "good", |_rng| i as u64);
                        assert_eq!(*v, i as u64, "writer thread {i}: got wrong value");
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    });
}

// ===========================================================================
// 4. Determinism under contention — 50 threads, same seed, different order
// ===========================================================================

#[test]
fn stress_determinism_under_contention() {
    with_timeout(|| {
        let thread_count = 50;
        let key_count = 20;

        // Generate reference values sequentially.
        let reference: Vec<u64> = {
            let fx = det_factory(0xA4);
            (0..key_count)
                .map(|i| {
                    let label = format!("det-{i}");
                    *fx.get_or_init("stress:det", &label, b"spec", "good", |rng| {
                        use rand_core::RngCore;
                        rng.next_u64()
                    })
                })
                .collect()
        };

        // Each thread creates its own fresh factory (same seed) and requests
        // keys in a thread-specific shuffled order. Results must match.
        let barrier = Arc::new(Barrier::new(thread_count));
        let reference = Arc::new(reference);

        let handles: Vec<_> = (0..thread_count)
            .map(|t| {
                let bar = barrier.clone();
                let reference = reference.clone();
                thread::spawn(move || {
                    bar.wait();
                    let fx = det_factory(0xA4);

                    // Access keys in a different order per thread by rotating
                    // the starting index.
                    for offset in 0..key_count {
                        let i = (t + offset) % key_count;
                        let label = format!("det-{i}");
                        let v = fx.get_or_init("stress:det", &label, b"spec", "good", |rng| {
                            use rand_core::RngCore;
                            rng.next_u64()
                        });
                        assert_eq!(
                            *v, reference[i],
                            "thread {t}, key {i}: expected {}, got {}",
                            reference[i], *v
                        );
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    });
}

// ===========================================================================
// 5. Cache growth — many unique keys generated concurrently
// ===========================================================================

#[test]
fn stress_cache_growth() {
    with_timeout(|| {
        let fx = det_factory(0xA5);
        let thread_count = 100;
        let keys_per_thread = 50;
        let barrier = Arc::new(Barrier::new(thread_count));

        let start = Instant::now();

        let handles: Vec<_> = (0..thread_count)
            .map(|t| {
                let fx = fx.clone();
                let bar = barrier.clone();
                thread::spawn(move || {
                    bar.wait();
                    for k in 0..keys_per_thread {
                        let label = format!("growth-t{t}-k{k}");
                        let _ = fx.get_or_init("stress:growth", &label, b"spec", "good", |_rng| {
                            (t * keys_per_thread + k) as u64
                        });
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let elapsed = start.elapsed();

        // Verify all entries are retrievable.
        for t in 0..thread_count {
            for k in 0..keys_per_thread {
                let label = format!("growth-t{t}-k{k}");
                let v = fx.get_or_init("stress:growth", &label, b"spec", "good", |_rng| 999_999u64);
                assert_eq!(
                    *v,
                    (t * keys_per_thread + k) as u64,
                    "entry t{t}-k{k} has wrong value after growth"
                );
            }
        }

        // Sanity: should complete well within the 30s timeout.
        assert!(
            elapsed < Duration::from_secs(25),
            "cache growth took {elapsed:?}, which is suspiciously slow"
        );
    });
}
