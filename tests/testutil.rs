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
///
/// When rustls-dependent features are enabled, this also installs the ring
/// crypto provider as the process-default. This is necessary because
/// `--all-features` enables both `ring` and `aws_lc_rs` on rustls, which
/// prevents auto-detection of the provider.
pub(crate) fn fx() -> Factory {
    #[cfg(any(feature = "tls", feature = "e2e", feature = "key-rotation"))]
    {
        use std::sync::Once;
        static PROVIDER_INIT: Once = Once::new();
        PROVIDER_INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    FX.get_or_init(|| {
        let seed = Seed::from_env_value("uselesskey-integration-test-seed-v1")
            .expect("integration test seed should always parse");
        Factory::deterministic(seed)
    })
    .clone()
}
