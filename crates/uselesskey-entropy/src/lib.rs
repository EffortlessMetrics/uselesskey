#![forbid(unsafe_code)]

//! High-entropy byte fixtures built on `uselesskey-core`.
//!
//! This crate is the narrow public lane for tests that only need stable,
//! scanner-safe byte buffers and do not need real crypto semantics.
//!
//! Most users can depend on the [`uselesskey`](https://crates.io/crates/uselesskey)
//! facade crate with `default-features = false, features = ["entropy"]`.

use std::fmt;
use std::sync::Arc;

use uselesskey_core::Factory;

/// Cache domain for entropy fixtures.
///
/// Keep this stable: changing it changes deterministic outputs.
pub const DOMAIN_ENTROPY_FIXTURE: &str = "uselesskey:entropy:fixture";

/// Handle used to derive deterministic high-entropy byte fixtures.
#[derive(Clone)]
pub struct EntropyFixture {
    factory: Factory,
    label: String,
    variant: String,
}

struct Inner {
    bytes: Vec<u8>,
}

impl fmt::Debug for EntropyFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntropyFixture")
            .field("label", &self.label)
            .field("variant", &self.variant)
            .finish_non_exhaustive()
    }
}

/// Extension trait to hang entropy helpers off the core [`Factory`].
pub trait EntropyFactoryExt {
    /// Create an entropy fixture handle for a label.
    fn entropy(&self, label: impl AsRef<str>) -> EntropyFixture;

    /// Create an entropy fixture handle with a custom variant.
    fn entropy_with_variant(
        &self,
        label: impl AsRef<str>,
        variant: impl AsRef<str>,
    ) -> EntropyFixture;
}

impl EntropyFactoryExt for Factory {
    fn entropy(&self, label: impl AsRef<str>) -> EntropyFixture {
        EntropyFixture::new(self.clone(), label.as_ref(), "good")
    }

    fn entropy_with_variant(
        &self,
        label: impl AsRef<str>,
        variant: impl AsRef<str>,
    ) -> EntropyFixture {
        EntropyFixture::new(self.clone(), label.as_ref(), variant.as_ref())
    }
}

impl EntropyFixture {
    fn new(factory: Factory, label: &str, variant: &str) -> Self {
        Self {
            factory,
            label: label.to_string(),
            variant: variant.to_string(),
        }
    }

    /// Returns the label used to derive this fixture.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the default variant used by this fixture.
    pub fn variant(&self) -> &str {
        &self.variant
    }

    /// Returns a deterministic byte buffer of the requested length.
    pub fn bytes(&self, len: usize) -> Vec<u8> {
        self.bytes_with_variant(len, &self.variant)
    }

    /// Returns a deterministic byte buffer for an explicit variant.
    pub fn bytes_with_variant(&self, len: usize, variant: impl AsRef<str>) -> Vec<u8> {
        load_inner(&self.factory, &self.label, len, variant.as_ref())
            .bytes
            .clone()
    }

    /// Fill an existing buffer with deterministic entropy.
    pub fn fill_bytes(&self, dest: &mut [u8]) {
        self.fill_bytes_with_variant(dest, &self.variant);
    }

    /// Fill an existing buffer with deterministic entropy for an explicit variant.
    pub fn fill_bytes_with_variant(&self, dest: &mut [u8], variant: impl AsRef<str>) {
        let bytes = load_inner(&self.factory, &self.label, dest.len(), variant.as_ref());
        dest.copy_from_slice(&bytes.bytes);
    }
}

fn load_inner(factory: &Factory, label: &str, len: usize, variant: &str) -> Arc<Inner> {
    factory.get_or_init(
        DOMAIN_ENTROPY_FIXTURE,
        label,
        &len.to_le_bytes(),
        variant,
        |seed| {
            let mut bytes = vec![0u8; len];
            seed.fill_bytes(&mut bytes);
            Inner { bytes }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prop_assert_eq;
    use uselesskey_core::Seed;

    #[test]
    fn deterministic_entropy_is_stable() {
        let fx = Factory::deterministic(Seed::from_env_value("entropy-det").unwrap());
        let a = fx.entropy("svc").bytes(32);
        let b = fx.entropy("svc").bytes(32);
        assert_eq!(a, b);
    }

    #[test]
    fn random_mode_still_caches_per_identity() {
        let fx = Factory::random();
        let a = fx.entropy("svc").bytes(32);
        let b = fx.entropy("svc").bytes(32);
        assert_eq!(a, b);
    }

    #[test]
    fn different_labels_produce_different_bytes() {
        let fx = Factory::deterministic(Seed::from_env_value("entropy-labels").unwrap());
        let a = fx.entropy("a").bytes(32);
        let b = fx.entropy("b").bytes(32);
        assert_ne!(a, b);
    }

    #[test]
    fn different_variants_produce_different_bytes() {
        let fx = Factory::deterministic(Seed::from_env_value("entropy-variants").unwrap());
        let fixture = fx.entropy("svc");
        let good = fixture.bytes(32);
        let alt = fixture.bytes_with_variant(32, "alt");
        assert_ne!(good, alt);
    }

    #[test]
    fn fill_bytes_matches_allocating_path() {
        let fx = Factory::deterministic(Seed::from_env_value("entropy-fill").unwrap());
        let fixture = fx.entropy("svc");

        let expected = fixture.bytes(24);
        let mut actual = [0u8; 24];
        fixture.fill_bytes(&mut actual);

        assert_eq!(expected, actual);
    }

    #[test]
    fn debug_does_not_include_bytes() {
        let fx = Factory::deterministic(Seed::from_env_value("entropy-debug").unwrap());
        let fixture = fx.entropy("svc");
        let dbg = format!("{fixture:?}");

        assert!(dbg.contains("EntropyFixture"));
        assert!(dbg.contains("svc"));
        assert!(!dbg.contains("["));
    }

    proptest::proptest! {
        #[test]
        fn requested_length_is_preserved(len in 0usize..2048) {
            let fx = Factory::deterministic(Seed::new([7u8; 32]));
            let bytes = fx.entropy("prop").bytes(len);
            prop_assert_eq!(bytes.len(), len);
        }
    }
}
