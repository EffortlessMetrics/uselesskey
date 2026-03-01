#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
//! Factory orchestration and cache lookup for uselesskey fixtures.
//!
//! Implements the core `Factory` type that manages deterministic derivation,
//! caching, and artifact generation. Operates in either Random or Deterministic
//! mode based on seed configuration.

extern crate alloc;

use alloc::string::ToString;
use alloc::sync::Arc;
use core::fmt;

use rand_chacha::ChaCha20Rng;
#[cfg(feature = "std")]
use rand_core::OsRng;
#[cfg(feature = "std")]
use rand_core::RngCore;
use rand_core::SeedableRng;
use uselesskey_core_cache::ArtifactCache;
use uselesskey_core_id::{ArtifactDomain, ArtifactId, DerivationVersion, Seed, derive_seed};

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

    /// Return the active mode.
    pub fn mode(&self) -> &Mode {
        &self.inner.mode
    }

    /// Clear the artifact cache.
    pub fn clear_cache(&self) {
        self.inner.cache.clear();
    }

    /// Return a cached value by `(domain, label, spec, variant)` or generate one.
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
        F: FnOnce(&mut ChaCha20Rng) -> T,
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

        let seed = self.seed_for(&id);
        let mut rng = ChaCha20Rng::from_seed(*seed.bytes());
        let value = init(&mut rng);
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
    OsRng.fill_bytes(&mut bytes);
    Seed::new(bytes)
}

#[cfg(not(feature = "std"))]
pub(crate) fn random_seed() -> Seed {
    panic!("uselesskey-core-factory: Mode::Random requires the `std` feature")
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::{Factory, Mode, random_seed};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uselesskey_core_id::Seed;

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
}
