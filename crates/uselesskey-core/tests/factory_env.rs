#![cfg(feature = "std")]

use std::time::{SystemTime, UNIX_EPOCH};

use uselesskey_core::{Error, Factory, Mode, Seed};

fn unique_env_var(suffix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    format!("USELESSKEY_TEST_{suffix}_{nanos}")
}

struct EnvGuard {
    key: String,
}

impl EnvGuard {
    fn new(key: String) -> Self {
        Self { key }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe { std::env::remove_var(&self.key) };
    }
}

#[test]
fn deterministic_from_env_reads_seed() {
    let var = unique_env_var("SEED_OK");
    let _guard = EnvGuard::new(var.clone());
    unsafe { std::env::set_var(&var, "test-seed") };

    let fx = Factory::deterministic_from_env(&var).expect("expected deterministic factory");
    match fx.mode() {
        Mode::Deterministic { master } => {
            let expected = Seed::from_env_value("test-seed").unwrap();
            assert_eq!(master.bytes(), expected.bytes());
        }
        Mode::Random => panic!("expected deterministic mode"),
    }
}

#[test]
fn deterministic_from_env_missing_var_is_error() {
    let var = unique_env_var("MISSING");
    let _guard = EnvGuard::new(var.clone());
    unsafe { std::env::remove_var(&var) };

    let err = Factory::deterministic_from_env(&var).unwrap_err();
    match err {
        Error::MissingEnvVar { var: got } => assert_eq!(got, var),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn deterministic_from_env_invalid_seed_is_error() {
    let var = unique_env_var("BAD_SEED");
    let _guard = EnvGuard::new(var.clone());
    let bad = "g".repeat(64);
    unsafe { std::env::set_var(&var, &bad) };

    let err = Factory::deterministic_from_env(&var).unwrap_err();
    match err {
        Error::InvalidSeed { var: got, message } => {
            assert_eq!(got, var);
            assert!(message.contains("invalid hex char"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
