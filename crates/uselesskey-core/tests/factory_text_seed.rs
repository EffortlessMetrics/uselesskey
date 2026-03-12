#![cfg(feature = "std")]

use uselesskey_core::{Factory, Mode, Seed};

#[test]
fn deterministic_from_str_uses_text_seed() {
    let fx = Factory::deterministic_from_str("plain-text-seed");
    match fx.mode() {
        Mode::Deterministic { master } => {
            assert_eq!(*master, Seed::from_text("plain-text-seed"));
        }
        Mode::Random => panic!("expected deterministic mode"),
    }
}

#[test]
fn deterministic_from_str_avoids_env_parsing_conventions() {
    let hex_shaped = "ab".repeat(32);
    let fx = Factory::deterministic_from_str(&hex_shaped);
    match fx.mode() {
        Mode::Deterministic { master } => {
            assert_eq!(*master, Seed::from_text(&hex_shaped));
            assert_ne!(*master, Seed::from_env_value(&hex_shaped).unwrap());
        }
        Mode::Random => panic!("expected deterministic mode"),
    }
}
