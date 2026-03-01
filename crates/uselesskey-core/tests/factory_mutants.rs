use uselesskey_core::{Factory, Seed};

/// Kill mutant: replace <impl fmt::Debug for Factory>::fmt -> fmt::Result with Ok(Default::default())
#[test]
fn debug_random_factory_contains_expected_text() {
    let fx = Factory::random();
    let debug = format!("{fx:?}");
    assert!(
        debug.contains("Random"),
        "Debug output for random factory should contain 'Random', got: {debug}"
    );
}

#[test]
fn debug_deterministic_factory_contains_expected_text() {
    let seed = Seed::new([0xAB; 32]);
    let fx = Factory::deterministic(seed);
    let debug = format!("{fx:?}");
    assert!(
        debug.contains("Deterministic"),
        "Debug output for deterministic factory should contain 'Deterministic', got: {debug}"
    );
}

/// Kill mutant: replace Factory::clear_cache with ()
#[test]
fn clear_cache_actually_clears() {
    let seed = Seed::new([1u8; 32]);
    let fx = Factory::deterministic(seed);

    let arc1 = fx.get_or_init("domain:test", "label", &[0u8; 8], "good", |_rng| 42u64);

    fx.clear_cache();

    let arc2 = fx.get_or_init("domain:test", "label", &[0u8; 8], "good", |_rng| 42u64);

    // After clear_cache, a new Arc should be allocated (different pointer identity).
    assert!(
        !core::ptr::eq(&*arc1 as *const u64, &*arc2 as *const u64),
        "clear_cache should cause a new Arc allocation for the same key"
    );
}
