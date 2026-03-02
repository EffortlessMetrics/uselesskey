//! Comprehensive concurrency and thread-safety tests.
//!
//! Validates that `Factory` is safe and correct under concurrent access:
//! - Multiple threads generating different key types simultaneously
//! - Cache hit and miss paths under contention
//! - `Factory::clone()` shared across threads via `Arc`
//! - Stress tests with 100+ concurrent requests
//! - Deterministic mode stays deterministic under contention
//! - No deadlocks (enforced via timeouts)
//! - Cross-key-type concurrent access (RSA + ECDSA + Ed25519 + HMAC)

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use uselesskey_core::{Factory, Seed};
use uselesskey_ecdsa::{EcdsaFactoryExt, EcdsaSpec};
use uselesskey_ed25519::{Ed25519FactoryExt, Ed25519Spec};
use uselesskey_hmac::{HmacFactoryExt, HmacSpec};
use uselesskey_rsa::{RsaFactoryExt, RsaSpec};

/// Per-test deterministic factory (fresh cache each time).
fn deterministic_factory() -> Factory {
    Factory::deterministic(Seed::new([0xCC; 32]))
}

/// Timeout for individual test operations to prevent deadlocks.
const DEADLOCK_TIMEOUT: Duration = Duration::from_secs(120);

/// Run a closure with a timeout, panicking if it exceeds the deadline.
fn with_timeout<F, R>(name: &str, f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let handle = thread::spawn(f);
    let start = Instant::now();
    loop {
        if handle.is_finished() {
            return handle.join().expect("thread panicked");
        }
        if start.elapsed() > DEADLOCK_TIMEOUT {
            panic!(
                "DEADLOCK: test '{}' did not complete within {:?}",
                name, DEADLOCK_TIMEOUT
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
}

// ---------------------------------------------------------------------------
// 1. Multiple threads generating different key types from same Factory
// ---------------------------------------------------------------------------

#[test]
fn concurrent_different_key_types_same_factory() {
    with_timeout("concurrent_different_key_types_same_factory", || {
        let fx = deterministic_factory();

        let fx_rsa = fx.clone();
        let fx_ecdsa = fx.clone();
        let fx_ed = fx.clone();
        let fx_hmac = fx.clone();

        let t_rsa = thread::spawn(move || {
            fx_rsa
                .rsa("concurrent-rsa", RsaSpec::rs256())
                .private_key_pkcs8_pem()
                .to_string()
        });

        let t_ecdsa = thread::spawn(move || {
            fx_ecdsa
                .ecdsa("concurrent-ec", EcdsaSpec::es256())
                .private_key_pkcs8_pem()
                .to_string()
        });

        let t_ed = thread::spawn(move || {
            fx_ed
                .ed25519("concurrent-ed", Ed25519Spec::new())
                .private_key_pkcs8_pem()
                .to_string()
        });

        let t_hmac = thread::spawn(move || {
            fx_hmac
                .hmac("concurrent-hmac", HmacSpec::hs256())
                .secret_bytes()
                .to_vec()
        });

        let rsa_pem = t_rsa.join().unwrap();
        let ecdsa_pem = t_ecdsa.join().unwrap();
        let ed_pem = t_ed.join().unwrap();
        let hmac_bytes = t_hmac.join().unwrap();

        // Verify against sequential generation with a fresh factory.
        let fx2 = deterministic_factory();
        assert_eq!(
            rsa_pem,
            fx2.rsa("concurrent-rsa", RsaSpec::rs256())
                .private_key_pkcs8_pem()
        );
        assert_eq!(
            ecdsa_pem,
            fx2.ecdsa("concurrent-ec", EcdsaSpec::es256())
                .private_key_pkcs8_pem()
        );
        assert_eq!(
            ed_pem,
            fx2.ed25519("concurrent-ed", Ed25519Spec::new())
                .private_key_pkcs8_pem()
        );
        assert_eq!(
            hmac_bytes,
            fx2.hmac("concurrent-hmac", HmacSpec::hs256())
                .secret_bytes()
        );
    });
}

// ---------------------------------------------------------------------------
// 2. Multiple threads requesting same key with same label (cache hit path)
// ---------------------------------------------------------------------------

#[test]
fn concurrent_cache_hit_same_label_ecdsa() {
    with_timeout("concurrent_cache_hit_same_label_ecdsa", || {
        let fx = deterministic_factory();
        // Warm the cache.
        let expected = fx
            .ecdsa("shared-label", EcdsaSpec::es256())
            .private_key_pkcs8_pem()
            .to_string();

        let handles: Vec<_> = (0..16)
            .map(|_| {
                let fx = fx.clone();
                thread::spawn(move || {
                    fx.ecdsa("shared-label", EcdsaSpec::es256())
                        .private_key_pkcs8_pem()
                        .to_string()
                })
            })
            .collect();

        for h in handles {
            assert_eq!(expected, h.join().unwrap());
        }
    });
}

#[test]
fn concurrent_cache_hit_same_label_ed25519() {
    with_timeout("concurrent_cache_hit_same_label_ed25519", || {
        let fx = deterministic_factory();
        let expected = fx
            .ed25519("shared-ed", Ed25519Spec::new())
            .private_key_pkcs8_pem()
            .to_string();

        let handles: Vec<_> = (0..16)
            .map(|_| {
                let fx = fx.clone();
                thread::spawn(move || {
                    fx.ed25519("shared-ed", Ed25519Spec::new())
                        .private_key_pkcs8_pem()
                        .to_string()
                })
            })
            .collect();

        for h in handles {
            assert_eq!(expected, h.join().unwrap());
        }
    });
}

#[test]
fn concurrent_cache_hit_same_label_hmac() {
    with_timeout("concurrent_cache_hit_same_label_hmac", || {
        let fx = deterministic_factory();
        let expected = fx
            .hmac("shared-hmac", HmacSpec::hs512())
            .secret_bytes()
            .to_vec();

        let handles: Vec<_> = (0..16)
            .map(|_| {
                let fx = fx.clone();
                thread::spawn(move || {
                    fx.hmac("shared-hmac", HmacSpec::hs512())
                        .secret_bytes()
                        .to_vec()
                })
            })
            .collect();

        for h in handles {
            assert_eq!(expected, h.join().unwrap());
        }
    });
}

// ---------------------------------------------------------------------------
// 3. Multiple threads with different labels (cache miss path)
// ---------------------------------------------------------------------------

#[test]
fn concurrent_cache_miss_different_labels_ecdsa() {
    with_timeout("concurrent_cache_miss_different_labels_ecdsa", || {
        let fx = deterministic_factory();

        let handles: Vec<_> = (0..16)
            .map(|i| {
                let fx = fx.clone();
                thread::spawn(move || {
                    let label = format!("miss-label-{i}");
                    fx.ecdsa(&label, EcdsaSpec::es256())
                        .private_key_pkcs8_pem()
                        .to_string()
                })
            })
            .collect();

        let results: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Every label should produce a unique key.
        for (i, a) in results.iter().enumerate() {
            for (j, b) in results.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "labels {i} and {j} must produce different keys");
                }
            }
        }
    });
}

#[test]
fn concurrent_cache_miss_different_labels_hmac() {
    with_timeout("concurrent_cache_miss_different_labels_hmac", || {
        let fx = deterministic_factory();

        let handles: Vec<_> = (0..16)
            .map(|i| {
                let fx = fx.clone();
                thread::spawn(move || {
                    let label = format!("hmac-miss-{i}");
                    fx.hmac(&label, HmacSpec::hs256()).secret_bytes().to_vec()
                })
            })
            .collect();

        let results: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        for (i, a) in results.iter().enumerate() {
            for (j, b) in results.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "labels {i} and {j} must produce different secrets");
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// 4. Factory::clone() across threads (Arc<Factory>)
// ---------------------------------------------------------------------------

#[test]
fn arc_factory_shared_across_threads() {
    with_timeout("arc_factory_shared_across_threads", || {
        let fx = Arc::new(deterministic_factory());

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let fx = Arc::clone(&fx);
                thread::spawn(move || {
                    let ec = fx
                        .ecdsa("arc-test", EcdsaSpec::es256())
                        .private_key_pkcs8_pem()
                        .to_string();
                    let ed = fx
                        .ed25519("arc-test-ed", Ed25519Spec::new())
                        .private_key_pkcs8_pem()
                        .to_string();
                    let hm = fx
                        .hmac("arc-test-hm", HmacSpec::hs384())
                        .secret_bytes()
                        .to_vec();
                    (ec, ed, hm)
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for r in &results[1..] {
            assert_eq!(results[0], *r, "all threads via Arc must see same keys");
        }
    });
}

#[test]
fn cloned_factory_shares_cache() {
    with_timeout("cloned_factory_shares_cache", || {
        let fx = deterministic_factory();
        // Generate a key to populate the cache.
        let expected = fx
            .ecdsa("clone-cache", EcdsaSpec::es256())
            .private_key_pkcs8_pem()
            .to_string();

        // Clone and use from another thread — should hit the cache.
        let fx2 = fx.clone();
        let result = thread::spawn(move || {
            fx2.ecdsa("clone-cache", EcdsaSpec::es256())
                .private_key_pkcs8_pem()
                .to_string()
        })
        .join()
        .unwrap();

        assert_eq!(expected, result);
    });
}

// ---------------------------------------------------------------------------
// 5. Stress test: 100+ concurrent requests
// ---------------------------------------------------------------------------

#[test]
fn stress_100_concurrent_ecdsa_requests() {
    with_timeout("stress_100_concurrent_ecdsa_requests", || {
        let fx = deterministic_factory();

        let handles: Vec<_> = (0..120)
            .map(|i| {
                let fx = fx.clone();
                thread::spawn(move || {
                    // Mix of cache hits (same label) and misses (unique labels).
                    let label = if i % 3 == 0 {
                        "shared-stress".to_string()
                    } else {
                        format!("stress-{i}")
                    };
                    fx.ecdsa(&label, EcdsaSpec::es256())
                        .private_key_pkcs8_pem()
                        .to_string()
                })
            })
            .collect();

        let results: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All "shared-stress" entries must be identical.
        let shared: Vec<&String> = results.iter().step_by(3).collect();
        for s in &shared[1..] {
            assert_eq!(shared[0], *s, "all shared-stress keys must match");
        }
    });
}

#[test]
fn stress_100_concurrent_mixed_key_types() {
    with_timeout("stress_100_concurrent_mixed_key_types", || {
        let fx = deterministic_factory();

        let handles: Vec<_> = (0..120)
            .map(|i| {
                let fx = fx.clone();
                thread::spawn(move || match i % 4 {
                    0 => fx
                        .ecdsa("stress-mixed", EcdsaSpec::es256())
                        .private_key_pkcs8_pem()
                        .len(),
                    1 => fx
                        .ed25519("stress-mixed-ed", Ed25519Spec::new())
                        .private_key_pkcs8_pem()
                        .len(),
                    2 => fx
                        .hmac("stress-mixed-hm", HmacSpec::hs256())
                        .secret_bytes()
                        .len(),
                    _ => fx
                        .ecdsa("stress-mixed-384", EcdsaSpec::es384())
                        .private_key_pkcs8_pem()
                        .len(),
                })
            })
            .collect();

        for h in handles {
            let len = h.join().unwrap();
            assert!(len > 0, "generated artifact must be non-empty");
        }
    });
}

#[test]
fn stress_100_concurrent_hmac_variants() {
    with_timeout("stress_100_concurrent_hmac_variants", || {
        let fx = deterministic_factory();

        let handles: Vec<_> = (0..120)
            .map(|i| {
                let fx = fx.clone();
                thread::spawn(move || {
                    let spec = match i % 3 {
                        0 => HmacSpec::hs256(),
                        1 => HmacSpec::hs384(),
                        _ => HmacSpec::hs512(),
                    };
                    fx.hmac("stress-hmac", spec).secret_bytes().to_vec()
                })
            })
            .collect();

        let results: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Group by spec and verify consistency within each group.
        let hs256: Vec<&Vec<u8>> = results.iter().step_by(3).collect();
        for s in &hs256[1..] {
            assert_eq!(hs256[0], *s);
        }
    });
}

// ---------------------------------------------------------------------------
// 6. Deterministic mode stays deterministic under contention
// ---------------------------------------------------------------------------

#[test]
fn determinism_under_contention_all_key_types() {
    with_timeout("determinism_under_contention_all_key_types", || {
        // Generate reference values sequentially.
        let fx_ref = deterministic_factory();
        let ref_ecdsa = fx_ref
            .ecdsa("det-contention", EcdsaSpec::es256())
            .private_key_pkcs8_pem()
            .to_string();
        let ref_ed = fx_ref
            .ed25519("det-contention-ed", Ed25519Spec::new())
            .private_key_pkcs8_pem()
            .to_string();
        let ref_hmac = fx_ref
            .hmac("det-contention-hm", HmacSpec::hs256())
            .secret_bytes()
            .to_vec();

        // Generate concurrently with a shared factory.
        let fx = deterministic_factory();
        let handles: Vec<_> = (0..20)
            .map(|i| {
                let fx = fx.clone();
                let ref_ecdsa = ref_ecdsa.clone();
                let ref_ed = ref_ed.clone();
                let ref_hmac = ref_hmac.clone();
                thread::spawn(move || {
                    // Each thread generates all key types in different orders.
                    match i % 3 {
                        0 => {
                            let ec = fx
                                .ecdsa("det-contention", EcdsaSpec::es256())
                                .private_key_pkcs8_pem()
                                .to_string();
                            let ed = fx
                                .ed25519("det-contention-ed", Ed25519Spec::new())
                                .private_key_pkcs8_pem()
                                .to_string();
                            let hm = fx
                                .hmac("det-contention-hm", HmacSpec::hs256())
                                .secret_bytes()
                                .to_vec();
                            assert_eq!(ec, ref_ecdsa, "thread {i}: ECDSA mismatch");
                            assert_eq!(ed, ref_ed, "thread {i}: Ed25519 mismatch");
                            assert_eq!(hm, ref_hmac, "thread {i}: HMAC mismatch");
                        }
                        1 => {
                            let hm = fx
                                .hmac("det-contention-hm", HmacSpec::hs256())
                                .secret_bytes()
                                .to_vec();
                            let ec = fx
                                .ecdsa("det-contention", EcdsaSpec::es256())
                                .private_key_pkcs8_pem()
                                .to_string();
                            let ed = fx
                                .ed25519("det-contention-ed", Ed25519Spec::new())
                                .private_key_pkcs8_pem()
                                .to_string();
                            assert_eq!(hm, ref_hmac, "thread {i}: HMAC mismatch");
                            assert_eq!(ec, ref_ecdsa, "thread {i}: ECDSA mismatch");
                            assert_eq!(ed, ref_ed, "thread {i}: Ed25519 mismatch");
                        }
                        _ => {
                            let ed = fx
                                .ed25519("det-contention-ed", Ed25519Spec::new())
                                .private_key_pkcs8_pem()
                                .to_string();
                            let hm = fx
                                .hmac("det-contention-hm", HmacSpec::hs256())
                                .secret_bytes()
                                .to_vec();
                            let ec = fx
                                .ecdsa("det-contention", EcdsaSpec::es256())
                                .private_key_pkcs8_pem()
                                .to_string();
                            assert_eq!(ed, ref_ed, "thread {i}: Ed25519 mismatch");
                            assert_eq!(hm, ref_hmac, "thread {i}: HMAC mismatch");
                            assert_eq!(ec, ref_ecdsa, "thread {i}: ECDSA mismatch");
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    });
}

#[test]
fn determinism_separate_factories_under_contention() {
    with_timeout("determinism_separate_factories_under_contention", || {
        let handles: Vec<_> = (0..20)
            .map(|_| {
                thread::spawn(|| {
                    let fx = deterministic_factory();
                    (
                        fx.ecdsa("sep-factory", EcdsaSpec::es256())
                            .private_key_pkcs8_pem()
                            .to_string(),
                        fx.ed25519("sep-factory-ed", Ed25519Spec::new())
                            .private_key_pkcs8_pem()
                            .to_string(),
                        fx.hmac("sep-factory-hm", HmacSpec::hs384())
                            .secret_bytes()
                            .to_vec(),
                    )
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for r in &results[1..] {
            assert_eq!(results[0].0, r.0, "ECDSA must be identical");
            assert_eq!(results[0].1, r.1, "Ed25519 must be identical");
            assert_eq!(results[0].2, r.2, "HMAC must be identical");
        }
    });
}

// ---------------------------------------------------------------------------
// 7. No deadlocks (with reasonable timeouts)
// ---------------------------------------------------------------------------

#[test]
fn no_deadlock_rapid_cache_access() {
    with_timeout("no_deadlock_rapid_cache_access", || {
        let fx = deterministic_factory();

        // Rapid interleaved reads/writes on the cache from many threads.
        let handles: Vec<_> = (0..32)
            .map(|i| {
                let fx = fx.clone();
                thread::spawn(move || {
                    for j in 0..10 {
                        let label = format!("deadlock-{}", (i + j) % 5);
                        let _ = fx.ecdsa(&label, EcdsaSpec::es256());
                        let _ = fx.ed25519(&label, Ed25519Spec::new());
                        let _ = fx.hmac(&label, HmacSpec::hs256());
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    });
}

#[test]
fn no_deadlock_concurrent_clear_and_generate() {
    with_timeout("no_deadlock_concurrent_clear_and_generate", || {
        let fx = deterministic_factory();

        let handles: Vec<_> = (0..16)
            .map(|i| {
                let fx = fx.clone();
                thread::spawn(move || {
                    for _ in 0..5 {
                        let _ = fx.ecdsa("clear-gen", EcdsaSpec::es256());
                        if i % 4 == 0 {
                            fx.clear_cache();
                        }
                        let _ = fx.hmac("clear-gen-hm", HmacSpec::hs256());
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    });
}

// ---------------------------------------------------------------------------
// 8. Cross-key-type concurrent access (RSA + ECDSA + Ed25519 + HMAC)
// ---------------------------------------------------------------------------

#[test]
fn cross_key_type_concurrent_rsa_ecdsa_ed25519_hmac() {
    with_timeout("cross_key_type_concurrent_rsa_ecdsa_ed25519_hmac", || {
        let fx = deterministic_factory();

        // Reference values (sequential).
        let ref_rsa = fx
            .rsa("cross-type", RsaSpec::rs256())
            .private_key_pkcs8_pem()
            .to_string();
        let ref_ec256 = fx
            .ecdsa("cross-type", EcdsaSpec::es256())
            .private_key_pkcs8_pem()
            .to_string();
        let ref_ec384 = fx
            .ecdsa("cross-type-384", EcdsaSpec::es384())
            .private_key_pkcs8_pem()
            .to_string();
        let ref_ed = fx
            .ed25519("cross-type", Ed25519Spec::new())
            .private_key_pkcs8_pem()
            .to_string();
        let ref_hmac = fx
            .hmac("cross-type", HmacSpec::hs256())
            .secret_bytes()
            .to_vec();

        // Generate all key types concurrently on a fresh factory.
        let fx2 = deterministic_factory();

        let fx_rsa = fx2.clone();
        let fx_ec256 = fx2.clone();
        let fx_ec384 = fx2.clone();
        let fx_ed = fx2.clone();
        let fx_hmac = fx2.clone();

        let t1 = thread::spawn(move || {
            fx_rsa
                .rsa("cross-type", RsaSpec::rs256())
                .private_key_pkcs8_pem()
                .to_string()
        });
        let t2 = thread::spawn(move || {
            fx_ec256
                .ecdsa("cross-type", EcdsaSpec::es256())
                .private_key_pkcs8_pem()
                .to_string()
        });
        let t3 = thread::spawn(move || {
            fx_ec384
                .ecdsa("cross-type-384", EcdsaSpec::es384())
                .private_key_pkcs8_pem()
                .to_string()
        });
        let t4 = thread::spawn(move || {
            fx_ed
                .ed25519("cross-type", Ed25519Spec::new())
                .private_key_pkcs8_pem()
                .to_string()
        });
        let t5 = thread::spawn(move || {
            fx_hmac
                .hmac("cross-type", HmacSpec::hs256())
                .secret_bytes()
                .to_vec()
        });

        assert_eq!(ref_rsa, t1.join().unwrap());
        assert_eq!(ref_ec256, t2.join().unwrap());
        assert_eq!(ref_ec384, t3.join().unwrap());
        assert_eq!(ref_ed, t4.join().unwrap());
        assert_eq!(ref_hmac, t5.join().unwrap());
    });
}

#[test]
fn cross_key_type_concurrent_multiple_specs() {
    with_timeout("cross_key_type_concurrent_multiple_specs", || {
        let fx = deterministic_factory();

        let handles: Vec<_> = (0..24)
            .map(|i| {
                let fx = fx.clone();
                thread::spawn(move || match i % 6 {
                    0 => {
                        let _ = fx.ecdsa("multi-spec", EcdsaSpec::es256());
                    }
                    1 => {
                        let _ = fx.ecdsa("multi-spec", EcdsaSpec::es384());
                    }
                    2 => {
                        let _ = fx.ed25519("multi-spec", Ed25519Spec::new());
                    }
                    3 => {
                        let _ = fx.hmac("multi-spec", HmacSpec::hs256());
                    }
                    4 => {
                        let _ = fx.hmac("multi-spec", HmacSpec::hs384());
                    }
                    _ => {
                        let _ = fx.hmac("multi-spec", HmacSpec::hs512());
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    });
}

// ---------------------------------------------------------------------------
// 9. Random mode under concurrency
// ---------------------------------------------------------------------------

#[test]
fn random_mode_concurrent_generation() {
    with_timeout("random_mode_concurrent_generation", || {
        let fx = Factory::random();

        let handles: Vec<_> = (0..16)
            .map(|i| {
                let fx = fx.clone();
                thread::spawn(move || {
                    let label = format!("random-{i}");
                    (
                        fx.ecdsa(&label, EcdsaSpec::es256())
                            .private_key_pkcs8_pem()
                            .to_string(),
                        fx.ed25519(&label, Ed25519Spec::new())
                            .private_key_pkcs8_pem()
                            .to_string(),
                        fx.hmac(&label, HmacSpec::hs256()).secret_bytes().to_vec(),
                    )
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Different labels should produce different keys (with overwhelming probability).
        for (i, a) in results.iter().enumerate() {
            for (j, b) in results.iter().enumerate() {
                if i != j {
                    // At least one field should differ.
                    let all_same = a.0 == b.0 && a.1 == b.1 && a.2 == b.2;
                    assert!(
                        !all_same,
                        "random keys for labels {i} and {j} should differ"
                    );
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// 10. Cache coherence after concurrent writes
// ---------------------------------------------------------------------------

#[test]
fn cache_coherent_after_concurrent_writes() {
    with_timeout("cache_coherent_after_concurrent_writes", || {
        let fx = deterministic_factory();

        // Many threads populate the cache concurrently.
        let handles: Vec<_> = (0..20)
            .map(|i| {
                let fx = fx.clone();
                thread::spawn(move || {
                    let label = format!("coherent-{}", i % 5);
                    fx.ecdsa(&label, EcdsaSpec::es256())
                        .private_key_pkcs8_pem()
                        .to_string()
                })
            })
            .collect();

        let results: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Group by label and verify all results for the same label match.
        for label_idx in 0..5 {
            let group: Vec<&String> = results
                .iter()
                .enumerate()
                .filter(|(i, _)| i % 5 == label_idx)
                .map(|(_, v)| v)
                .collect();
            for s in &group[1..] {
                assert_eq!(
                    group[0], *s,
                    "cache coherence: label index {label_idx} values must match"
                );
            }
        }
    });
}
