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
    use uselesskey_test_support::{TestResult, require_ok};

    #[test]
    fn deterministic_entropy_is_stable() -> TestResult<()> {
        let fx = Factory::deterministic(require_ok(
            Seed::from_env_value("entropy-det"),
            "entropy-det must parse as a deterministic seed",
        )?);
        let a = fx.entropy("svc").bytes(32);
        let b = fx.entropy("svc").bytes(32);
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn random_mode_still_caches_per_identity() {
        let fx = Factory::random();
        let a = fx.entropy("svc").bytes(32);
        let b = fx.entropy("svc").bytes(32);
        assert_eq!(a, b);
    }

    #[test]
    fn different_labels_produce_different_bytes() -> TestResult<()> {
        let fx = Factory::deterministic(require_ok(
            Seed::from_env_value("entropy-labels"),
            "entropy-labels must parse as a deterministic seed",
        )?);
        let a = fx.entropy("a").bytes(32);
        let b = fx.entropy("b").bytes(32);
        assert_ne!(a, b);
        Ok(())
    }

    #[test]
    fn different_variants_produce_different_bytes() -> TestResult<()> {
        let fx = Factory::deterministic(require_ok(
            Seed::from_env_value("entropy-variants"),
            "entropy-variants must parse as a deterministic seed",
        )?);
        let fixture = fx.entropy("svc");
        let good = fixture.bytes(32);
        let alt = fixture.bytes_with_variant(32, "alt");
        assert_ne!(good, alt);
        Ok(())
    }

    #[test]
    fn accessors_report_fixture_identity() -> TestResult<()> {
        let fx = Factory::deterministic(require_ok(
            Seed::from_env_value("entropy-identity"),
            "entropy-identity must parse as a deterministic seed",
        )?);
        let default = fx.entropy("svc");
        let custom = fx.entropy_with_variant("svc-alt", "custom");

        assert_eq!(default.label(), "svc");
        assert_eq!(default.variant(), "good");
        assert_eq!(custom.label(), "svc-alt");
        assert_eq!(custom.variant(), "custom");
        Ok(())
    }

    #[test]
    fn fill_bytes_matches_allocating_path() -> TestResult<()> {
        let fx = Factory::deterministic(require_ok(
            Seed::from_env_value("entropy-fill"),
            "entropy-fill must parse as a deterministic seed",
        )?);
        let fixture = fx.entropy("svc");

        let expected = fixture.bytes(24);
        let mut actual = [0u8; 24];
        fixture.fill_bytes(&mut actual);

        assert_eq!(expected, actual);
        Ok(())
    }

    #[test]
    fn debug_does_not_include_bytes() -> TestResult<()> {
        let fx = Factory::deterministic(require_ok(
            Seed::from_env_value("entropy-debug"),
            "entropy-debug must parse as a deterministic seed",
        )?);
        let fixture = fx.entropy("svc");
        let dbg = format!("{fixture:?}");

        assert!(dbg.contains("EntropyFixture"));
        assert!(dbg.contains("svc"));
        assert!(!dbg.contains("["));
        Ok(())
    }

    proptest::proptest! {
        #[test]
        fn requested_length_is_preserved(len in 0usize..2048) {
            let fx = Factory::deterministic(Seed::new([7u8; 32]));
            let bytes = fx.entropy("prop").bytes(len);
            prop_assert_eq!(bytes.len(), len);
        }
    }

    #[test]
    fn entropy_with_variant_constructor_derives_from_custom_variant() -> TestResult<()> {
        let fx = Factory::deterministic(require_ok(
            Seed::from_env_value("entropy-with-variant-ctor"),
            "must parse seed",
        )?);

        let good = fx.entropy("svc").bytes(32);
        let custom = fx.entropy_with_variant("svc", "alt").bytes(32);

        assert_ne!(
            good, custom,
            "entropy_with_variant must derive from the variant, not the default"
        );

        // Calling with the same custom variant on either constructor produces
        // the same bytes (cache identity is (label, len, variant)).
        let custom_again = fx.entropy("svc").bytes_with_variant(32, "alt");
        assert_eq!(custom, custom_again);
        Ok(())
    }

    #[test]
    fn fill_bytes_with_variant_matches_allocating_path() -> TestResult<()> {
        let fx = Factory::deterministic(require_ok(
            Seed::from_env_value("entropy-fill-with-variant"),
            "must parse seed",
        )?);
        let fixture = fx.entropy("svc");

        let expected = fixture.bytes_with_variant(40, "alt");
        let mut actual = [0u8; 40];
        fixture.fill_bytes_with_variant(&mut actual, "alt");

        assert_eq!(expected.as_slice(), &actual[..]);

        // And differs from the default-variant fill of the same length.
        let mut default_filled = [0u8; 40];
        fixture.fill_bytes(&mut default_filled);
        assert_ne!(actual, default_filled);
        Ok(())
    }

    #[test]
    fn zero_length_request_returns_empty_buffer() -> TestResult<()> {
        let fx = Factory::deterministic(require_ok(
            Seed::from_env_value("entropy-zero-len"),
            "must parse seed",
        )?);
        let fixture = fx.entropy("svc");

        let empty = fixture.bytes(0);
        assert!(empty.is_empty());

        // fill_bytes on a zero-length buffer must be a no-op (and not panic).
        let mut buf: [u8; 0] = [];
        fixture.fill_bytes(&mut buf);
        Ok(())
    }

    #[test]
    fn distinct_lengths_produce_distinct_caches() -> TestResult<()> {
        // The cache spec includes len.to_le_bytes(), so requesting different
        // lengths from the same (label, variant) must produce independently
        // derived bytes — not a prefix/extension of the longer buffer.
        let fx = Factory::deterministic(require_ok(
            Seed::from_env_value("entropy-len-distinct"),
            "must parse seed",
        )?);
        let fixture = fx.entropy("svc");

        let short = fixture.bytes(16);
        let long = fixture.bytes(32);

        assert_eq!(short.len(), 16);
        assert_eq!(long.len(), 32);
        assert_ne!(
            short.as_slice(),
            &long[..16],
            "different lengths must hit distinct cache entries, not slice the same stream"
        );
        Ok(())
    }

    #[test]
    fn cloned_fixture_handles_share_cache_identity() -> TestResult<()> {
        let fx = Factory::deterministic(require_ok(
            Seed::from_env_value("entropy-clone-handle"),
            "must parse seed",
        )?);
        let fixture = fx.entropy("svc");
        let cloned = fixture.clone();

        assert_eq!(fixture.label(), cloned.label());
        assert_eq!(fixture.variant(), cloned.variant());
        assert_eq!(fixture.bytes(48), cloned.bytes(48));
        Ok(())
    }

    #[test]
    fn domain_constant_is_stable_for_the_lifetime_of_v1() {
        // Changing this constant changes derived outputs. The test exists so
        // an accidental rename is caught by CI rather than by silent fixture
        // drift in downstream test suites.
        assert_eq!(DOMAIN_ENTROPY_FIXTURE, "uselesskey:entropy:fixture");
    }
}
