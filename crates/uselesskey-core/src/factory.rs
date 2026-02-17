use alloc::string::ToString;
use alloc::sync::Arc;
use core::any::Any;
use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
#[cfg(feature = "std")]
use dashmap::DashMap;
#[cfg(feature = "std")]
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
#[cfg(feature = "std")]
use rand_core::RngCore;
use rand_core::SeedableRng;
#[cfg(not(feature = "std"))]
use spin::Mutex;

use crate::derive;
use crate::id::{ArtifactDomain, ArtifactId, DerivationVersion, Seed};

type CacheValue = Arc<dyn Any + Send + Sync>;

#[cfg(feature = "std")]
type Cache = DashMap<ArtifactId, CacheValue>;

#[cfg(not(feature = "std"))]
type Cache = Mutex<BTreeMap<ArtifactId, CacheValue>>;

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
    cache: Cache,
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
            .field("cache_size", &cache_len(&self.inner.cache))
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
                cache: new_cache(),
            }),
        }
    }

    /// Create a factory in random mode.
    ///
    /// Each process run produces different artifacts, but within a process,
    /// artifacts are cached by `(domain, label, spec, variant)`.
    ///
    /// In `no_std` builds (`default-features = false`), this is available for
    /// API compatibility but panics when used because OS randomness is not
    /// available.
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
    /// // SAFETY: this is a single-threaded doctest; no concurrent env access.
    /// unsafe { std::env::set_var("MY_TEST_SEED", "reproducible-ci-seed") };
    ///
    /// let fx = Factory::deterministic_from_env("MY_TEST_SEED").unwrap();
    ///
    /// // Clean up
    /// unsafe { std::env::remove_var("MY_TEST_SEED") };
    /// ```
    ///
    /// ```
    /// use uselesskey_core::Factory;
    ///
    /// // Returns error when variable is not set
    /// let result = Factory::deterministic_from_env("NONEXISTENT_VAR");
    /// assert!(result.is_err());
    /// ```
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
        cache_clear(&self.inner.cache);
    }

    /// Get a cached artifact or initialize it using the provided closure.
    ///
    /// `spec_bytes` must be stable across versions for deterministic behavior.
    ///
    /// The closure receives a `ChaCha20Rng` seeded appropriately for the current mode.
    ///
    /// # Re-entrancy
    ///
    /// The `init` closure runs outside the cache lock, so it is safe
    /// for `init` to call back into `get_or_init` (e.g. X.509 cert generation
    /// calling `factory.rsa()`). Under contention, `init` may execute more than
    /// once for the same key; only one result is kept in the cache. The returned
    /// `Arc<T>` always points to the cached winner.
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

        // Fast path: already cached.
        if let Some(entry) = cache_get(&self.inner.cache, &id) {
            return downcast_or_panic::<T>(entry, &id);
        }

        // Slow path: compute WITHOUT holding the cache lock.
        // This avoids deadlocks when the init closure calls back into
        // get_or_init (e.g. x509 cert generation calling factory.rsa()).
        let seed = self.seed_for(&id);
        let mut rng = ChaCha20Rng::from_seed(seed.0);
        let value = init(&mut rng);
        let arc: Arc<T> = Arc::new(value);
        let arc_any: CacheValue = arc.clone();

        // Insert if absent; if another thread raced us, use its value.
        cache_insert_if_absent(&self.inner.cache, id.clone(), arc_any);

        let cached = cache_get(&self.inner.cache, &id)
            .expect("uselesskey-core: cached artifact missing after insert");
        downcast_or_panic::<T>(cached, &id)
    }

    fn seed_for(&self, id: &ArtifactId) -> Seed {
        match &self.inner.mode {
            Mode::Random => random_seed(),
            Mode::Deterministic { master } => derive::derive_seed(master, id),
        }
    }
}

#[cfg(feature = "std")]
fn new_cache() -> Cache {
    DashMap::new()
}

#[cfg(not(feature = "std"))]
fn new_cache() -> Cache {
    Mutex::new(BTreeMap::new())
}

#[cfg(feature = "std")]
fn cache_len(cache: &Cache) -> usize {
    cache.len()
}

#[cfg(not(feature = "std"))]
fn cache_len(cache: &Cache) -> usize {
    cache.lock().len()
}

#[cfg(feature = "std")]
fn cache_clear(cache: &Cache) {
    cache.clear();
}

#[cfg(not(feature = "std"))]
fn cache_clear(cache: &Cache) {
    cache.lock().clear();
}

#[cfg(feature = "std")]
fn cache_get(cache: &Cache, id: &ArtifactId) -> Option<CacheValue> {
    cache.get(id).map(|entry| entry.value().clone())
}

#[cfg(not(feature = "std"))]
fn cache_get(cache: &Cache, id: &ArtifactId) -> Option<CacheValue> {
    cache.lock().get(id).cloned()
}

#[cfg(feature = "std")]
fn cache_insert_if_absent(cache: &Cache, id: ArtifactId, value: CacheValue) {
    cache.entry(id).or_insert(value);
}

#[cfg(not(feature = "std"))]
fn cache_insert_if_absent(cache: &Cache, id: ArtifactId, value: CacheValue) {
    use alloc::collections::btree_map::Entry;

    let mut guard = cache.lock();
    if let Entry::Vacant(slot) = guard.entry(id) {
        slot.insert(value);
    }
}

#[cfg(feature = "std")]
pub(crate) fn random_seed() -> Seed {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Seed(bytes)
}

#[cfg(not(feature = "std"))]
pub(crate) fn random_seed() -> Seed {
    panic!("uselesskey-core: Mode::Random requires the `std` feature")
}

pub(crate) fn downcast_or_panic<T>(arc_any: CacheValue, id: &ArtifactId) -> Arc<T>
where
    T: Any + Send + Sync + 'static,
{
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
