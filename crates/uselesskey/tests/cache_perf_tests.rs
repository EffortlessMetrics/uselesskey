//! Cache correctness and performance sanity tests for the Factory's
//! DashMap-based caching layer.

use std::sync::Arc;
use std::time::Instant;

use uselesskey::{EcdsaFactoryExt, EcdsaSpec, Factory, RsaFactoryExt, RsaSpec, Seed};

fn seed(n: u8) -> Seed {
    Seed::new([n; 32])
}

// ---------------------------------------------------------------------------
// 1. Cache hit: same factory + label + spec ⇒ same Arc (pointer equality)
// ---------------------------------------------------------------------------
#[test]
fn cache_hit_returns_same_arc() {
    let fx = Factory::deterministic(seed(42));

    let a: Arc<u8> = fx.get_or_init("domain:test", "lbl", b"spec", "good", |_| 1u8);
    let b: Arc<u8> = fx.get_or_init("domain:test", "lbl", b"spec", "good", |_| 99u8);

    assert!(Arc::ptr_eq(&a, &b), "second call must return cached Arc");
}

#[test]
fn cache_hit_rsa_same_pem() {
    let fx = Factory::deterministic(seed(42));

    let k1 = fx.rsa("issuer", RsaSpec::rs256());
    let k2 = fx.rsa("issuer", RsaSpec::rs256());

    assert_eq!(
        k1.private_key_pkcs8_pem(),
        k2.private_key_pkcs8_pem(),
        "same label+spec must return identical PEM"
    );
}

// ---------------------------------------------------------------------------
// 2. Cache miss: different labels ⇒ different keys
// ---------------------------------------------------------------------------
#[test]
fn different_labels_produce_different_keys() {
    let fx = Factory::deterministic(seed(42));

    let a = fx.rsa("alpha", RsaSpec::rs256());
    let b = fx.rsa("bravo", RsaSpec::rs256());

    assert_ne!(
        a.private_key_pkcs8_pem(),
        b.private_key_pkcs8_pem(),
        "different labels must produce different keys"
    );
}

// ---------------------------------------------------------------------------
// 3. Cache thread safety: 10 threads requesting same key get identical results
// ---------------------------------------------------------------------------
#[test]
fn cache_is_thread_safe() {
    let fx = Factory::deterministic(seed(42));

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let fx = fx.clone();
            std::thread::spawn(move || {
                let k = fx.rsa("shared", RsaSpec::rs256());
                k.private_key_pkcs8_pem().to_string()
            })
        })
        .collect();

    let results: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    for pem in &results[1..] {
        assert_eq!(pem, &results[0], "all threads must see the same cached key");
    }
}

// ---------------------------------------------------------------------------
// 4. Cache does not perturb determinism: A, B, A ⇒ A is unchanged
// ---------------------------------------------------------------------------
#[test]
fn interleaved_generation_does_not_perturb_determinism() {
    let fx = Factory::deterministic(seed(42));

    let a1 = fx.rsa("alpha", RsaSpec::rs256());
    let _b = fx.rsa("bravo", RsaSpec::rs256());
    let a2 = fx.rsa("alpha", RsaSpec::rs256());

    assert_eq!(
        a1.private_key_pkcs8_pem(),
        a2.private_key_pkcs8_pem(),
        "generating B between two A requests must not change A"
    );
}

// ---------------------------------------------------------------------------
// 5. RSA cache performance: second call is fast (< 50 ms vs > 100 ms first)
// ---------------------------------------------------------------------------
#[test]
fn rsa_second_call_is_fast() {
    let fx = Factory::deterministic(seed(42));

    let t0 = Instant::now();
    let _k1 = fx.rsa("perf", RsaSpec::rs256());
    let first_gen = t0.elapsed();

    let t1 = Instant::now();
    let _k2 = fx.rsa("perf", RsaSpec::rs256());
    let cached = t1.elapsed();

    // The cached call should be orders of magnitude faster.
    // Use a generous 50 ms ceiling to avoid flaky CI.
    assert!(
        cached.as_millis() < 50,
        "cached RSA lookup took {}ms, expected < 50ms (first gen took {}ms)",
        cached.as_millis(),
        first_gen.as_millis(),
    );
}

// ---------------------------------------------------------------------------
// 6. Cross-key-type cache isolation: RSA and ECDSA don't collide
// ---------------------------------------------------------------------------
#[test]
fn rsa_and_ecdsa_do_not_collide_for_same_label() {
    let fx = Factory::deterministic(seed(42));

    let rsa_pem = fx.rsa("shared-label", RsaSpec::rs256());
    let ec_pem = fx.ecdsa("shared-label", EcdsaSpec::es256());

    assert_ne!(
        rsa_pem.private_key_pkcs8_der(),
        ec_pem.private_key_pkcs8_der(),
        "RSA and ECDSA with same label must produce different DER"
    );
}

// ---------------------------------------------------------------------------
// 7. Spec sensitivity: same label, different spec ⇒ different keys
// ---------------------------------------------------------------------------
#[test]
fn different_spec_produces_different_keys() {
    let fx = Factory::deterministic(seed(42));

    let k2048 = fx.rsa("issuer", RsaSpec::rs256()); // 2048 bits
    let k4096 = fx.rsa("issuer", RsaSpec::new(4096)); // 4096 bits

    assert_ne!(
        k2048.private_key_pkcs8_pem(),
        k4096.private_key_pkcs8_pem(),
        "same label but different spec must produce different keys"
    );
}

#[test]
fn ecdsa_different_curve_produces_different_keys() {
    let fx = Factory::deterministic(seed(42));

    let p256 = fx.ecdsa("issuer", EcdsaSpec::es256());
    let p384 = fx.ecdsa("issuer", EcdsaSpec::es384());

    assert_ne!(
        p256.private_key_pkcs8_der(),
        p384.private_key_pkcs8_der(),
        "same label but different curve must produce different keys"
    );
}

// ---------------------------------------------------------------------------
// 8. Random-mode factory also caches within same instance
// ---------------------------------------------------------------------------
#[test]
fn random_factory_caches_within_instance() {
    let fx = Factory::random();

    let k1 = fx.rsa("cached", RsaSpec::rs256());
    let k2 = fx.rsa("cached", RsaSpec::rs256());

    assert_eq!(
        k1.private_key_pkcs8_pem(),
        k2.private_key_pkcs8_pem(),
        "random factory must cache: same label+spec ⇒ same key"
    );
}

#[test]
fn random_factory_different_instances_differ() {
    let fx1 = Factory::random();
    let fx2 = Factory::random();

    let k1 = fx1.rsa("key", RsaSpec::rs256());
    let k2 = fx2.rsa("key", RsaSpec::rs256());

    // Two independent random factories should (almost certainly) differ.
    assert_ne!(
        k1.private_key_pkcs8_pem(),
        k2.private_key_pkcs8_pem(),
        "independent random factories should produce different keys"
    );
}
