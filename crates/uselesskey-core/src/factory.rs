use std::any::Any;
use std::fmt;
use std::sync::Arc;

use dashmap::DashMap;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

use crate::derive;
use crate::id::{ArtifactDomain, ArtifactId, DerivationVersion, Seed};

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
#[derive(Clone, Debug)]
pub enum Mode {
    /// Artifacts are generated using randomness.
    ///
    /// Within a process, artifacts are cached per `(domain, label, spec, variant)`,
    /// so repeated calls return the same value.
    Random,

    /// Artifacts are generated deterministically from a master seed.
    ///
    /// Deterministic mode is order-independent:
    /// calling fixtures in a different order does not change outputs.
    Deterministic { master: Seed },
}

struct Inner {
    mode: Mode,
    cache: DashMap<ArtifactId, Arc<dyn Any + Send + Sync>>,
}

/// A factory for generating and caching test fixtures.
///
/// `Factory` is cheap to clone: clones share the underlying cache.
///
/// # Examples
///
/// ```
/// use uselesskey_core::Factory;
///
/// // Create a random factory
/// let fx = Factory::random();
///
/// // Clones share the same cache
/// let fx2 = fx.clone();
///
/// // Clear the cache if needed (usually not necessary)
/// fx.clear_cache();
/// ```
#[derive(Clone)]
pub struct Factory {
    inner: Arc<Inner>,
}

impl fmt::Debug for Factory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Factory")
            .field("mode", &self.inner.mode)
            .field("cache_size", &self.inner.cache.len())
            .finish()
    }
}

impl Factory {
    /// Create a new factory with the specified mode.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::{Factory, Mode, Seed};
    ///
    /// // Create a random factory
    /// let fx = Factory::new(Mode::Random);
    ///
    /// // Create a deterministic factory
    /// let seed = Seed::from_env_value("my-seed").unwrap();
    /// let fx = Factory::new(Mode::Deterministic { master: seed });
    /// ```
    pub fn new(mode: Mode) -> Self {
        Self {
            inner: Arc::new(Inner {
                mode,
                cache: DashMap::new(),
            }),
        }
    }

    /// Create a factory in random mode.
    ///
    /// Each process run produces different artifacts, but within a process,
    /// artifacts are cached by `(domain, label, spec, variant)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::Factory;
    ///
    /// let fx = Factory::random();
    /// ```
    pub fn random() -> Self {
        Self::new(Mode::Random)
    }

    /// Create a factory in deterministic mode with the given seed.
    ///
    /// The same seed produces the same artifacts across runs.
    /// Order-independence: calling fixtures in different order does not change outputs.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::{Factory, Seed};
    ///
    /// let seed = Seed::from_env_value("ci-build-123").unwrap();
    /// let fx = Factory::deterministic(seed);
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::Factory;
    ///
    /// // Set up the environment variable for this example
    /// std::env::set_var("MY_TEST_SEED", "reproducible-ci-seed");
    ///
    /// let fx = Factory::deterministic_from_env("MY_TEST_SEED").unwrap();
    ///
    /// // Clean up
    /// std::env::remove_var("MY_TEST_SEED");
    /// ```
    ///
    /// ```
    /// use uselesskey_core::Factory;
    ///
    /// // Returns error when variable is not set
    /// let result = Factory::deterministic_from_env("NONEXISTENT_VAR");
    /// assert!(result.is_err());
    /// ```
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
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::{Factory, Mode};
    ///
    /// let fx = Factory::random();
    /// assert!(matches!(fx.mode(), Mode::Random));
    /// ```
    pub fn mode(&self) -> &Mode {
        &self.inner.mode
    }

    /// Clear the artifact cache.
    ///
    /// This is rarely needed in tests; the cache is process-local
    /// and automatically cleaned up when the process exits.
    ///
    /// # Examples
    ///
    /// ```
    /// use uselesskey_core::Factory;
    ///
    /// let fx = Factory::random();
    /// // ... use the factory ...
    /// fx.clear_cache(); // Clear all cached artifacts
    /// ```
    pub fn clear_cache(&self) {
        self.inner.cache.clear();
    }

    /// Get a cached artifact or initialize it using the provided closure.
    ///
    /// `spec_bytes` must be stable across versions for deterministic behavior.
    ///
    /// The closure receives a `ChaCha20Rng` seeded appropriately for the current mode.
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
        F: FnOnce(&mut ChaCha20Rng) -> T,
    {
        let id = ArtifactId::new(
            domain,
            label.to_string(),
            spec_bytes,
            variant.to_string(),
            DerivationVersion::V1,
        );

        use dashmap::mapref::entry::Entry;

        let arc_any = match self.inner.cache.entry(id.clone()) {
            Entry::Occupied(o) => o.get().clone(),
            Entry::Vacant(v) => {
                let seed = self.seed_for(&id);
                let mut rng = ChaCha20Rng::from_seed(seed.0);
                let value = init(&mut rng);
                let arc: Arc<T> = Arc::new(value);
                let arc_any: Arc<dyn Any + Send + Sync> = arc.clone();
                v.insert(arc_any.clone());
                arc_any
            }
        };

        match arc_any.downcast::<T>() {
            Ok(v) => v,
            Err(_) => {
                // This is a bug: it means two different types used the same artifact id.
                panic!(
                    "uselesskey-core: artifact type mismatch for domain={} label={} variant={}",
                    id.domain, id.label, id.variant
                );
            }
        }
    }

    fn seed_for(&self, id: &ArtifactId) -> Seed {
        match &self.inner.mode {
            Mode::Random => random_seed(),
            Mode::Deterministic { master } => derive::derive_seed(master, id),
        }
    }
}

fn random_seed() -> Seed {
    let mut bytes = [0u8; 32];
    // OsRng implements CryptoRngCore; fill_bytes is fine here.
    OsRng.fill_bytes(&mut bytes);
    Seed(bytes)
}
