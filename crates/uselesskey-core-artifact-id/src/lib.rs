#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Artifact identity primitives for uselesskey.
//!
//! Defines [`ArtifactId`] — the `(domain, label, spec_fingerprint, variant,
//! derivation_version)` tuple that uniquely identifies generated fixtures.

extern crate alloc;

use alloc::string::String;
pub use uselesskey_core_hash::hash32;

/// Domain strings are used to separate unrelated fixture types.
pub type ArtifactDomain = &'static str;

/// Version tag for the derivation scheme.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct DerivationVersion(pub u16);

impl DerivationVersion {
    pub const V1: Self = Self(1);
}

/// Identifier used for deterministic artifact cache entries.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ArtifactId {
    pub domain: ArtifactDomain,
    pub label: String,
    pub spec_fingerprint: [u8; 32],
    pub variant: String,
    pub derivation_version: DerivationVersion,
}

impl ArtifactId {
    pub fn new(
        domain: ArtifactDomain,
        label: impl Into<String>,
        spec_bytes: &[u8],
        variant: impl Into<String>,
        derivation_version: DerivationVersion,
    ) -> Self {
        Self {
            domain,
            label: label.into(),
            spec_fingerprint: *hash32(spec_bytes).as_bytes(),
            variant: variant.into(),
            derivation_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_id_fingerprints_spec_bytes() {
        let spec = [1u8, 2, 3, 4, 5];
        let id = ArtifactId::new(
            "domain:test",
            "label",
            &spec,
            "variant",
            DerivationVersion::V1,
        );

        let expected = *hash32(&spec).as_bytes();
        assert_eq!(id.spec_fingerprint, expected);
    }

    #[test]
    fn artifact_id_preserves_fields() {
        let id = ArtifactId::new(
            "domain:test",
            "my-label",
            b"spec",
            "my-variant",
            DerivationVersion::V1,
        );

        assert_eq!(id.domain, "domain:test");
        assert_eq!(id.label, "my-label");
        assert_eq!(id.variant, "my-variant");
        assert_eq!(id.derivation_version, DerivationVersion::V1);
    }
}
