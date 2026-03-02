//! Security invariant tests for the no-key-leakage guarantee.
//!
//! These tests verify that `Debug`, `Display`, and error formatting never
//! expose seed bytes, key material, or other secret data.

#![cfg(feature = "std")]

use uselesskey_core::{Factory, Mode, Seed};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn det_factory(byte: u8) -> Factory {
    Factory::deterministic(Seed::new([byte; 32]))
}

/// Extract hex representation of a byte to search for in debug output.
fn byte_hex(b: u8) -> String {
    format!("{b:02x}")
}

// ===========================================================================
// 1. Seed Debug is always fully redacted
// ===========================================================================

#[test]
fn seed_debug_is_redacted_for_all_byte_patterns() {
    for byte in [0x00, 0xFF, 0xAB, 0x42, 0xDE, 0xAD] {
        let seed = Seed::new([byte; 32]);
        let debug = format!("{seed:?}");
        assert_eq!(
            debug, "Seed(**redacted**)",
            "Seed Debug must always be 'Seed(**redacted**)' for byte 0x{byte:02x}, got: {debug}"
        );
    }
}

#[test]
fn seed_debug_does_not_contain_any_seed_byte_hex() {
    let seed_bytes = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
        0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88,
    ];
    let seed = Seed::new(seed_bytes);
    let debug = format!("{seed:?}");

    // The hex pattern "deadbeef" must not appear
    assert!(
        !debug.to_lowercase().contains("dead"),
        "Seed Debug must not contain hex seed bytes: {debug}"
    );
    assert!(
        !debug.to_lowercase().contains("beef"),
        "Seed Debug must not contain hex seed bytes: {debug}"
    );
    assert!(
        !debug.to_lowercase().contains("cafe"),
        "Seed Debug must not contain hex seed bytes: {debug}"
    );
}

// ===========================================================================
// 2. Factory Debug never contains seed bytes
// ===========================================================================

#[test]
fn factory_debug_does_not_leak_seed_hex() {
    let seed_bytes = [0xAB; 32];
    let fx = Factory::deterministic(Seed::new(seed_bytes));
    let debug = format!("{fx:?}");

    // Must not contain hex representation of seed
    assert!(
        !debug.to_lowercase().contains(&byte_hex(0xAB)),
        "Factory Debug must not contain hex seed bytes, got: {debug}"
    );
    // Must not contain decimal array representation
    assert!(
        !debug.contains("171"),
        "Factory Debug must not contain decimal seed byte value 171, got: {debug}"
    );
}

#[test]
fn factory_debug_shows_structure_not_secrets() {
    let fx = det_factory(0xFF);
    let debug = format!("{fx:?}");

    // Must contain expected structural fields
    assert!(debug.contains("Factory"), "missing 'Factory' in: {debug}");
    assert!(
        debug.contains("cache_size"),
        "missing 'cache_size' in: {debug}"
    );
    // Seed in mode must be redacted
    assert!(
        debug.contains("redacted"),
        "seed must appear as redacted in: {debug}"
    );
}

// ===========================================================================
// 3. Mode Debug with Deterministic shows redacted seed
// ===========================================================================

#[test]
fn mode_debug_deterministic_redacts_seed() {
    let seed_bytes = [0xCA; 32];
    let mode = Mode::Deterministic {
        master: Seed::new(seed_bytes),
    };
    let debug = format!("{mode:?}");

    assert!(
        debug.contains("redacted"),
        "Mode::Deterministic Debug must contain 'redacted', got: {debug}"
    );
    assert!(
        !debug.to_lowercase().contains("ca"),
        "Mode::Deterministic Debug must not contain hex seed bytes, got: {debug}"
    );
}

// ===========================================================================
// 4. Error messages don't contain seed material
// ===========================================================================

#[test]
fn error_invalid_seed_message_does_not_contain_raw_input() {
    // from_env_value with invalid hex should produce an error that
    // describes the problem without echoing back the raw input.
    let secret_looking_input = "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe";
    let result = Seed::from_env_value(secret_looking_input);
    // This is valid hex, so it should succeed
    assert!(result.is_ok());

    // Try with invalid input that could be a secret
    let invalid_input = "not_hex_but_looks_secrety_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    let result = Seed::from_env_value(invalid_input);
    if let Err(msg) = result {
        let err_str = msg.to_string();
        // Error should not echo back the full raw input
        assert!(
            !err_str.contains(invalid_input),
            "Error message should not contain the full raw input: {err_str}"
        );
    }
}

// ===========================================================================
// 5. Panic messages from type mismatch don't leak seed material
// ===========================================================================

#[test]
fn type_mismatch_panic_does_not_leak_seed() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let seed_bytes = [0xBE; 32];
    let fx = Factory::deterministic(Seed::new(seed_bytes));

    // Insert a u32 value
    let _ = fx.get_or_init("domain:sec", "lbl", b"spec", "good", |_rng| 42u32);

    // Try to retrieve as String → should panic
    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = fx.get_or_init("domain:sec", "lbl", b"spec", "good", |_rng| {
            String::from("wrong type")
        });
    }));

    assert!(result.is_err(), "expected panic on type mismatch");

    // Check the panic message doesn't contain a hex-encoded seed representation
    if let Err(payload) = result
        && let Some(msg) = payload.downcast_ref::<String>()
    {
        // Full hex-encoded seed must not appear
        let hex_seed: String = seed_bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !msg.contains(&hex_seed),
            "panic message must not contain full hex seed: {msg}"
        );
        // Array-like representation must not appear
        assert!(
            !msg.contains("[190"),
            "panic message must not contain decimal seed array: {msg}"
        );
    }
}

// ===========================================================================
// 6. Factory Debug with cached entries doesn't leak cached values
// ===========================================================================

#[test]
fn factory_debug_with_cached_entries_does_not_leak_values() {
    let fx = det_factory(0x01);

    // Insert some values
    let _ = fx.get_or_init("domain:sec", "secret-label", b"spec", "good", |_rng| {
        String::from("super_secret_value_12345")
    });

    let debug = format!("{fx:?}");

    assert!(
        !debug.contains("super_secret"),
        "Factory Debug must not contain cached values: {debug}"
    );
    assert!(
        !debug.contains("12345"),
        "Factory Debug must not contain cached values: {debug}"
    );
}

// ===========================================================================
// 7. Seed bytes() accessor exists but Debug doesn't expose it
// ===========================================================================

#[test]
fn seed_bytes_accessible_but_debug_hidden() {
    let raw = [0x42; 32];
    let seed = Seed::new(raw);

    // bytes() returns the actual seed (for internal use)
    assert_eq!(seed.bytes(), &raw);

    // But Debug never shows them
    let debug = format!("{seed:?}");
    assert!(
        !debug.contains("42"),
        "Debug must not show raw bytes: {debug}"
    );
    assert!(
        !debug.contains("66"),
        "Debug must not show decimal value of 0x42: {debug}"
    );
}

// ===========================================================================
// 8. Random factory Debug doesn't leak OS entropy
// ===========================================================================

#[test]
fn random_factory_debug_is_safe() {
    let fx = Factory::random();
    let debug = format!("{fx:?}");

    assert!(debug.contains("Random"), "should show Random mode: {debug}");
    assert!(
        debug.contains("Factory"),
        "should show Factory struct: {debug}"
    );
    // Random mode has no seed, so output should be very short
    assert!(
        debug.len() < 200,
        "Random factory Debug should be concise, got {} chars: {debug}",
        debug.len()
    );
}
