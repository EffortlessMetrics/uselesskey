//! Test utilities for integration tests.
//!
//! Provides a shared deterministic factory for all integration tests.

use std::sync::OnceLock;

use uselesskey_core::{Factory, Seed};

static FX: OnceLock<Factory> = OnceLock::new();

/// Install the ring crypto provider as the process-default rustls provider.
///
/// Required when `--all-features` enables both `ring` and `aws-lc-rs`
/// on rustls, preventing auto-detection. Safe to call multiple times.
#[allow(dead_code)]
#[cfg(any(feature = "tls", feature = "e2e", feature = "key-rotation"))]
pub(crate) fn install_rustls_ring_provider() {
    use std::sync::Once;
    static PROVIDER_INIT: Once = Once::new();
    PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

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
