//! Test utilities for integration tests.
//!
//! Provides a shared deterministic factory for all integration tests.

use std::sync::OnceLock;

use uselesskey_core::{Factory, Seed};

static FX: OnceLock<Factory> = OnceLock::new();

/// Get a deterministic factory for integration tests.
///
/// All tests using this factory will produce the same keys for the same
/// labels, ensuring test reproducibility.
pub(crate) fn fx() -> Factory {
    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-integration-test-seed-v1")
            .expect("integration test seed should always parse");
        Factory::deterministic(seed)
    })
    .clone()
}
