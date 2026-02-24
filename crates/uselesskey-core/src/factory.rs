use alloc::sync::Arc;
use core::any::Any;
use core::fmt;

use crate::id::{ArtifactDomain, Seed};
use uselesskey_core_factory::Factory as CoreFactory;

/// How a [`Factory`] generates artifacts.
///
/// # Examples
///
/// ```
/// use uselesskey_core::{Factory, Mode, Seed};
///
/// // Check if a factory is in random or deterministic mode
/// let fx = Factory::random();
/// assert!(matches!(fx.mode(), Mode::Random));
///
/// let seed = Seed::from_env_value("test").unwrap();
/// let fx = Factory::deterministic(seed);
/// assert!(matches!(fx.mode(), Mode::Deterministic { .. }));
/// ```
#[derive(Clone)]
pub struct Factory {
    inner: CoreFactory,
}

pub use uselesskey_core_factory::Mode;

impl fmt::Debug for Factory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl Factory {
    /// Create a new factory with the specified mode.
    pub fn new(mode: Mode) -> Self {
        Self {
            inner: CoreFactory::new(mode),
        }
    }

    /// Create a factory in random mode.
    ///
    /// Each process run produces different artifacts, but within a process,
    /// artifacts are cached by `(domain, label, spec, variant)`.
    pub fn random() -> Self {
        Self::new(Mode::Random)
    }

    /// Create a deterministic factory from an existing seed.
    pub fn deterministic(master: Seed) -> Self {
        Self::new(Mode::Deterministic { master })
    }

    /// Create a deterministic factory from an environment variable.
    ///
    /// The environment variable can contain:
    /// - A 64-character hex string (with optional `0x` prefix)
    /// - Any other string (hashed to produce a 32-byte seed)
    ///
    /// # Errors
    ///
    /// Returns an error if the environment variable is not set.
    #[cfg(feature = "std")]
    pub fn deterministic_from_env(var: &str) -> Result<Self, crate::Error> {
        let raw = std::env::var(var).map_err(|_| crate::Error::MissingEnvVar {
            var: var.to_string(),
        })?;

        let seed = Seed::from_env_value(&raw).map_err(|message| crate::Error::InvalidSeed {
            var: var.to_string(),
            message,
        })?;

        Ok(Self::deterministic(seed))
    }

    /// Returns the mode this factory is operating in.
    pub fn mode(&self) -> &Mode {
        self.inner.mode()
    }

    /// Clear the artifact cache.
    pub fn clear_cache(&self) {
        self.inner.clear_cache()
    }

    /// Get a cached artifact by `(domain, label, spec, variant)` or generate one.
    pub fn get_or_init<T, F>(
        &self,
        domain: ArtifactDomain,
        label: &str,
        spec_bytes: &[u8],
        variant: &str,
        init: F,
    ) -> Arc<T>
    where
        T: Any + Send + Sync + 'static,
        F: FnOnce(&mut rand_chacha::ChaCha20Rng) -> T,
    {
        self.inner.get_or_init(domain, label, spec_bytes, variant, init)
    }
}
