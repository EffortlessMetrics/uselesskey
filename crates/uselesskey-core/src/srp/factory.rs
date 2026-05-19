//! Factory orchestration and cache lookup for uselesskey fixtures.
//!
//! Implements the core `Factory` type that manages deterministic derivation,
//! caching, and artifact generation. Operates in either Random or Deterministic
//! mode based on seed configuration.

use alloc::string::ToString;
use alloc::sync::Arc;
use core::fmt;

#[cfg(feature = "std")]
use std::collections::BTreeSet;
#[cfg(feature = "std")]
use std::sync::{Condvar, Mutex, MutexGuard};
#[cfg(all(feature = "std", test))]
use std::time::Duration;

#[cfg(feature = "std")]
use rand10::TryRng;
#[cfg(feature = "std")]
use rand10::rngs::SysRng;

use crate::srp::cache::ArtifactCache;
use crate::srp::identity::{ArtifactDomain, ArtifactId, DerivationVersion, Seed, derive_seed};

/// How a [`Factory`] generates artifacts.
#[derive(Clone, Debug)]
pub enum Mode {
    /// Artifacts are generated using platform randomness.
    Random,

    /// Artifacts are generated deterministically from a master seed.
    Deterministic { master: Seed },
}

struct Inner {
    mode: Mode,
    cache: ArtifactCache,
    #[cfg(feature = "std")]
    init_locks: InitLocks,
}

#[cfg(feature = "std")]
#[derive(Default)]
struct InitLocks {
    active: Mutex<BTreeSet<ArtifactId>>,
    ready: Condvar,
}

#[cfg(feature = "std")]
struct InitGuard<'a> {
    locks: &'a InitLocks,
    id: ArtifactId,
}

#[cfg(feature = "std")]
impl InitLocks {
    fn acquire(&self, id: &ArtifactId) -> InitGuard<'_> {
        let mut active = self.active();
        loop {
            if active.insert(id.clone()) {
                break;
            }

            #[cfg(test)]
            {
                let (next, wait_result) = self
                    .ready
                    .wait_timeout(active, Duration::from_secs(2))
                    .unwrap_or_else(|err| err.into_inner());
                assert!(
                    !wait_result.timed_out(),
                    "timed out waiting for init guard for {id:?}"
                );
                active = next;
            }

            #[cfg(not(test))]
            {
                active = self
                    .ready
                    .wait(active)
                    .unwrap_or_else(|err| err.into_inner());
            }
        }

        InitGuard {
            locks: self,
            id: id.clone(),
        }
    }

    fn active(&self) -> MutexGuard<'_, BTreeSet<ArtifactId>> {
        self.active.lock().unwrap_or_else(|err| err.into_inner())
    }
}

#[cfg(feature = "std")]
impl Drop for InitGuard<'_> {
    fn drop(&mut self) {
        let mut active = self.locks.active();
        active.remove(&self.id);
        self.locks.ready.notify_all();
    }
}

/// A factory for generating and caching test artifacts.
///
/// `Factory` is cheap to clone; clones share the same cache.
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
    pub fn new(mode: Mode) -> Self {
        Self {
            inner: Arc::new(Inner {
                mode,
                cache: ArtifactCache::new(),
                #[cfg(feature = "std")]
                init_locks: InitLocks::default(),
            }),
        }
    }

    /// Create a factory in random mode.
    pub fn random() -> Self {
        Self::new(Mode::Random)
    }

    /// Create a factory in deterministic mode from a master seed.
    pub fn deterministic(master: Seed) -> Self {
        Self::new(Mode::Deterministic { master })
    }

    /// Create a deterministic factory from plain text.
    ///
    /// This hashes the provided string verbatim with BLAKE3. Unlike
    /// [`Seed::from_env_value`], it does not trim whitespace or interpret
    /// hex-shaped strings specially.
    pub fn deterministic_from_str(text: &str) -> Self {
        Self::deterministic(Seed::from_text(text))
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

    /// Return the active mode.
    pub fn mode(&self) -> &Mode {
        &self.inner.mode
    }

    /// Clear the artifact cache.
    pub fn clear_cache(&self) {
        self.inner.cache.clear();
    }

    /// Return a cached value by `(domain, label, spec, variant)` or generate one.
    ///
    /// The initializer receives the derived seed for this artifact identity.
    /// Callers that need an RNG should instantiate it privately from that seed.
    pub fn get_or_init<T, F>(
        &self,
        domain: ArtifactDomain,
        label: &str,
        spec_bytes: &[u8],
        variant: &str,
        init: F,
    ) -> Arc<T>
    where
        T: core::any::Any + Send + Sync + 'static,
        F: FnOnce(Seed) -> T,
    {
        let id = ArtifactId::new(
            domain,
            label.to_string(),
            spec_bytes,
            variant.to_string(),
            DerivationVersion::V1,
        );

        if let Some(entry) = self.inner.cache.get_typed::<T>(&id) {
            return entry;
        }

        #[cfg(feature = "std")]
        let _init_guard = self.inner.init_locks.acquire(&id);

        if let Some(entry) = self.inner.cache.get_typed::<T>(&id) {
            return entry;
        }

        let seed = self.seed_for(&id);
        let value = init(seed);
        let arc: Arc<T> = Arc::new(value);

        self.inner.cache.insert_if_absent_typed(id, arc)
    }

    fn seed_for(&self, id: &ArtifactId) -> Seed {
        match &self.inner.mode {
            Mode::Random => random_seed(),
            Mode::Deterministic { master } => derive_seed(master, id),
        }
    }
}

#[cfg(feature = "std")]
pub(crate) fn random_seed() -> Seed {
    let mut bytes = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut bytes)
        .expect("failed to read operating-system randomness");
    Seed::new(bytes)
}

#[cfg(not(feature = "std"))]
pub(crate) fn random_seed() -> Seed {
    panic!("uselesskey-core-factory: Mode::Random requires the `std` feature")
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::{Factory, InitLocks, Mode, random_seed};
    use crate::Seed;
    use crate::srp::identity::{ArtifactId, DerivationVersion};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn draw_u64(seed: Seed) -> u64 {
        let mut bytes = [0u8; 8];
        seed.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    #[test]
    fn clear_cache_forces_reinit() {
        let fx = Factory::random();
        let hits = AtomicUsize::new(0);

        let first = fx.get_or_init("domain:test", "label", b"spec", "good", |_rng| {
            hits.fetch_add(1, Ordering::SeqCst);
            42u8
        });

        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let second = fx.get_or_init("domain:test", "label", b"spec", "good", |_rng| {
            hits.fetch_add(1, Ordering::SeqCst);
            99u8
        });
        assert!(Arc::ptr_eq(&first, &second));

        fx.clear_cache();
        let third = fx.get_or_init("domain:test", "label", b"spec", "good", |_rng| {
            hits.fetch_add(1, Ordering::SeqCst);
            44u8
        });

        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert!(!Arc::ptr_eq(&first, &third));
    }

    #[test]
    fn get_or_init_type_mismatch_panics() {
        let fx = Factory::random();
        let _ = fx.get_or_init("domain:test", "label", b"spec", "good", |_rng| 123u32);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = fx.get_or_init("domain:test", "label", b"spec", "good", |_rng| {
                "oops".to_string()
            });
        }));

        assert!(result.is_err(), "expected panic on type mismatch");
    }

    #[test]
    fn random_seed_has_expected_length() {
        let seed = random_seed();
        assert_eq!(seed.bytes().len(), 32);
    }

    #[test]
    fn init_lock_marks_id_active_until_guard_drop() {
        let locks = InitLocks::default();
        let id = ArtifactId::new(
            "domain:init-lock",
            "label",
            b"spec",
            "good",
            DerivationVersion::V1,
        );

        let guard = locks.acquire(&id);

        assert!(
            locks.active().contains(&id),
            "init guard should mark the artifact identity active"
        );

        drop(guard);

        assert!(
            !locks.active().contains(&id),
            "dropping init guard should clear the active artifact identity"
        );
    }

    #[test]
    fn same_identity_returns_cached_value_without_rerunning_initializer() {
        let fx = Factory::deterministic(Seed::new([9u8; 32]));
        let hits = AtomicUsize::new(0);

        let first = fx.get_or_init("domain:concurrent", "label", b"spec", "good", |_seed| {
            hits.fetch_add(1, Ordering::SeqCst);
            77u32
        });
        let second = fx.get_or_init("domain:concurrent", "label", b"spec", "good", |_seed| {
            hits.fetch_add(1, Ordering::SeqCst);
            99u32
        });

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(*first, 77);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn get_or_init_reentrant_does_not_deadlock() {
        let fx = Factory::deterministic(Seed::new([42u8; 32]));

        let outer: Arc<String> = fx.get_or_init("test:outer", "label", b"spec", "good", |_rng| {
            let inner: Arc<u64> =
                fx.get_or_init("test:inner", "label", b"spec", "good", |_rng| 42u64);
            format!("outer-{}", *inner)
        });

        assert_eq!(*outer, "outer-42");
    }

    #[test]
    fn debug_includes_cache_size() {
        let fx = Factory::random();
        let dbg = format!("{:?}", fx);
        assert!(dbg.contains("cache_size: 0"), "empty factory: {dbg}");

        let _ = fx.get_or_init("domain:test", "label", b"spec", "good", |_rng| 7u8);
        let dbg = format!("{:?}", fx);
        assert!(dbg.contains("cache_size: 1"), "after insert: {dbg}");
    }

    #[test]
    fn mode_pattern_matches_deterministic() {
        let seed = Seed::new([1u8; 32]);
        let fx = Factory::deterministic(seed);
        match fx.mode() {
            Mode::Deterministic { master } => assert_eq!(master.bytes(), seed.bytes()),
            Mode::Random => panic!("wrong mode"),
        }
    }

    #[test]
    fn mode_pattern_matches_random() {
        let fx = Factory::random();
        assert!(matches!(fx.mode(), Mode::Random));
    }

    #[test]
    fn deterministic_same_inputs_yield_same_output() {
        let fx = Factory::deterministic(Seed::new([7u8; 32]));
        let a: Arc<u64> = fx.get_or_init("domain:det", "lbl", b"sp", "good", draw_u64);
        // Clear cache so init runs again from the same derived seed.
        fx.clear_cache();
        let b: Arc<u64> = fx.get_or_init("domain:det", "lbl", b"sp", "good", draw_u64);
        assert_eq!(*a, *b, "deterministic mode must reproduce the same value");
    }

    #[test]
    fn clone_shares_cache() {
        let fx = Factory::random();
        let _ = fx.get_or_init("domain:clone", "lbl", b"sp", "good", |_| 99u32);
        let fx2 = fx.clone();
        let val = fx2.get_or_init("domain:clone", "lbl", b"sp", "good", |_| 0u32);
        assert_eq!(*val, 99, "clone must share the same cache");
    }

    #[test]
    fn different_domains_produce_distinct_entries() {
        let fx = Factory::deterministic(Seed::new([1u8; 32]));
        let a: Arc<u64> = fx.get_or_init("domain:a", "lbl", b"sp", "good", draw_u64);
        let b: Arc<u64> = fx.get_or_init("domain:b", "lbl", b"sp", "good", draw_u64);
        assert_ne!(*a, *b);
    }

    #[test]
    fn different_variants_produce_distinct_entries() {
        let fx = Factory::deterministic(Seed::new([2u8; 32]));
        let a: Arc<u64> = fx.get_or_init("domain:v", "lbl", b"sp", "good", draw_u64);
        let b: Arc<u64> = fx.get_or_init("domain:v", "lbl", b"sp", "bad", draw_u64);
        assert_ne!(*a, *b);
    }

    #[test]
    fn different_specs_produce_distinct_entries() {
        let fx = Factory::deterministic(Seed::new([3u8; 32]));
        let a: Arc<u64> = fx.get_or_init("domain:s", "lbl", b"RS256", "good", draw_u64);
        let b: Arc<u64> = fx.get_or_init("domain:s", "lbl", b"RS384", "good", draw_u64);
        assert_ne!(*a, *b);
    }

    #[test]
    fn debug_mode_random() {
        let fx = Factory::random();
        let dbg = format!("{:?}", fx);
        assert!(
            dbg.contains("Random"),
            "debug should show Random mode: {dbg}"
        );
    }

    #[test]
    fn debug_mode_deterministic() {
        let fx = Factory::deterministic(Seed::new([0u8; 32]));
        let dbg = format!("{:?}", fx);
        assert!(
            dbg.contains("Deterministic"),
            "debug should show Deterministic mode: {dbg}"
        );
        assert!(
            dbg.contains("redacted"),
            "seed must be redacted in debug output: {dbg}"
        );
    }

    #[test]
    fn deterministic_from_str_preserves_whitespace() {
        let exact = Factory::deterministic_from_str(" seed-value ");
        let trimmed = Factory::deterministic_from_str("seed-value");

        let a: Arc<u64> = exact.get_or_init("domain:text", "label", b"spec", "good", draw_u64);
        let b: Arc<u64> = trimmed.get_or_init("domain:text", "label", b"spec", "good", draw_u64);

        assert_ne!(
            *a, *b,
            "deterministic_from_str should hash the text verbatim, including whitespace"
        );
    }

    #[test]
    fn deterministic_from_str_matches_seed_from_text() {
        let from_str = Factory::deterministic_from_str("seed-value");
        let from_seed = Factory::deterministic(Seed::from_text("seed-value"));

        let a: Arc<u64> = from_str.get_or_init("domain:text", "label", b"spec", "good", draw_u64);
        let b: Arc<u64> = from_seed.get_or_init("domain:text", "label", b"spec", "good", draw_u64);

        assert_eq!(*a, *b);
    }
}
