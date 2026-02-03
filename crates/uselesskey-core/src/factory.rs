use std::any::Any;
use std::sync::Arc;

use dashmap::DashMap;
use rand::rngs::OsRng;
use rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::derive;
use crate::id::{ArtifactDomain, ArtifactId, DerivationVersion, Seed};

/// How a [`Factory`] generates artifacts.
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
#[derive(Clone)]
pub struct Factory {
    inner: Arc<Inner>,
}

impl Factory {
    pub fn new(mode: Mode) -> Self {
        Self {
            inner: Arc::new(Inner {
                mode,
                cache: DashMap::new(),
            }),
        }
    }

    pub fn random() -> Self {
        Self::new(Mode::Random)
    }

    pub fn deterministic(master: Seed) -> Self {
        Self::new(Mode::Deterministic { master })
    }

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

    pub fn mode(&self) -> &Mode {
        &self.inner.mode
    }

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
