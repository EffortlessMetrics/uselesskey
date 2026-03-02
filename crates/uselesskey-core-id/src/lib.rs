#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
//! Core identity and derivation primitives for uselesskey.
//!
//! Defines `ArtifactId` — the `(domain, label, spec_fingerprint, variant,
//! derivation_version)` tuple that uniquely identifies each generated artifact.
//! Provides deterministic seed derivation from a master seed and artifact id.

extern crate alloc;

use alloc::string::String;
use uselesskey_core_hash::Hasher;
pub use uselesskey_core_hash::{hash32, write_len_prefixed};

pub use uselesskey_core_seed::Seed;

/// Domain strings are used to separate unrelated fixture types.
pub type ArtifactDomain = &'static str;

/// Version tag for the derivation scheme.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct DerivationVersion(pub u16);

impl DerivationVersion {
    /// The initial (and currently only) derivation scheme version.
    pub const V1: Self = Self(1);
}

/// Identifier used for deterministic artifact cache entries.
///
/// Each field contributes to the derived seed, so two artifacts with the
/// same `ArtifactId` are guaranteed to be identical across runs.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ArtifactId {
    /// Namespace that separates unrelated fixture types (e.g. `"rsa"`, `"ecdsa"`).
    pub domain: ArtifactDomain,
    /// User-supplied label for this fixture (e.g. `"issuer"`, `"audience"`).
    pub label: String,
    /// BLAKE3 hash of the spec's stable byte representation.
    pub spec_fingerprint: [u8; 32],
    /// Variant tag (e.g. `"default"`, `"mismatch"`, `"corrupt:bad-header"`).
    pub variant: String,
    /// Which derivation algorithm version to use.
    pub derivation_version: DerivationVersion,
}

impl ArtifactId {
    /// Create a new artifact identifier by hashing `spec_bytes` into a fingerprint.
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

/// Derive a per-artifact seed from the master seed and the artifact identifier.
pub fn derive_seed(master: &Seed, id: &ArtifactId) -> Seed {
    match id.derivation_version.0 {
        1 => derive_seed_v1(master, id),
        other => {
            #[cfg(feature = "std")]
            eprintln!("uselesskey-core-id: unknown derivation version {other}, using v1");
            #[cfg(not(feature = "std"))]
            let _ = other;
            derive_seed_v1(master, id)
        }
    }
}

fn derive_seed_v1(master: &Seed, id: &ArtifactId) -> Seed {
    let mut hasher = Hasher::new_keyed(master.bytes());

    hasher.update(&id.derivation_version.0.to_be_bytes());
    write_len_prefixed(&mut hasher, id.domain.as_bytes());
    write_len_prefixed(&mut hasher, id.label.as_bytes());
    write_len_prefixed(&mut hasher, id.variant.as_bytes());
    hasher.update(&id.spec_fingerprint);

    let out = hasher.finalize();
    Seed::new(*out.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{ArtifactId, DerivationVersion, Seed, derive_seed, hash32};

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

    #[test]
    fn derive_seed_unknown_version_is_deterministic() {
        let master = Seed::new([9u8; 32]);
        let id = ArtifactId::new(
            "domain:test",
            "label",
            b"spec",
            "variant",
            DerivationVersion(999),
        );

        let first = derive_seed(&master, &id);
        let second = derive_seed(&master, &id);
        assert_eq!(first.bytes(), second.bytes());
    }

    #[test]
    fn derive_seed_version_affects_output() {
        let master = Seed::new([3u8; 32]);
        let id_v1 = ArtifactId::new(
            "domain:test",
            "label",
            b"spec",
            "variant",
            DerivationVersion::V1,
        );
        let id_v2 = ArtifactId::new(
            "domain:test",
            "label",
            b"spec",
            "variant",
            DerivationVersion(2),
        );

        let v1 = derive_seed(&master, &id_v1);
        let v2 = derive_seed(&master, &id_v2);
        assert_ne!(v1.bytes(), v2.bytes());
    }

    #[test]
    fn seed_reexport_matches_core_seed() {
        let seed = Seed::from_env_value("core-id-seed").unwrap();
        let expected = uselesskey_core_seed::Seed::from_env_value("core-id-seed").unwrap();
        assert_eq!(seed.bytes(), expected.bytes());
    }

    #[test]
    fn derive_seed_label_affects_output() {
        let master = Seed::new([5u8; 32]);
        let id_a = ArtifactId::new("d", "label-a", b"spec", "v", DerivationVersion::V1);
        let id_b = ArtifactId::new("d", "label-b", b"spec", "v", DerivationVersion::V1);
        assert_ne!(
            derive_seed(&master, &id_a).bytes(),
            derive_seed(&master, &id_b).bytes()
        );
    }

    #[test]
    fn derive_seed_domain_affects_output() {
        let master = Seed::new([6u8; 32]);
        let id_a = ArtifactId::new("domain:a", "lbl", b"spec", "v", DerivationVersion::V1);
        let id_b = ArtifactId::new("domain:b", "lbl", b"spec", "v", DerivationVersion::V1);
        assert_ne!(
            derive_seed(&master, &id_a).bytes(),
            derive_seed(&master, &id_b).bytes()
        );
    }

    #[test]
    fn derive_seed_variant_affects_output() {
        let master = Seed::new([7u8; 32]);
        let id_a = ArtifactId::new("d", "lbl", b"spec", "good", DerivationVersion::V1);
        let id_b = ArtifactId::new("d", "lbl", b"spec", "bad", DerivationVersion::V1);
        assert_ne!(
            derive_seed(&master, &id_a).bytes(),
            derive_seed(&master, &id_b).bytes()
        );
    }

    #[test]
    fn derive_seed_spec_affects_output() {
        let master = Seed::new([8u8; 32]);
        let id_a = ArtifactId::new("d", "lbl", b"RS256", "v", DerivationVersion::V1);
        let id_b = ArtifactId::new("d", "lbl", b"RS384", "v", DerivationVersion::V1);
        assert_ne!(
            derive_seed(&master, &id_a).bytes(),
            derive_seed(&master, &id_b).bytes()
        );
    }

    #[test]
    fn derive_seed_master_affects_output() {
        let id = ArtifactId::new("d", "lbl", b"spec", "v", DerivationVersion::V1);
        let a = derive_seed(&Seed::new([1u8; 32]), &id);
        let b = derive_seed(&Seed::new([2u8; 32]), &id);
        assert_ne!(a.bytes(), b.bytes());
    }

    #[test]
    fn artifact_id_empty_fields() {
        let id = ArtifactId::new("d", "", b"", "", DerivationVersion::V1);
        assert_eq!(id.label, "");
        assert_eq!(id.variant, "");
        assert_eq!(id.spec_fingerprint, *hash32(b"").as_bytes());
    }

    #[test]
    fn artifact_id_ordering() {
        let a = ArtifactId::new("a", "lbl", b"spec", "v", DerivationVersion::V1);
        let b = ArtifactId::new("b", "lbl", b"spec", "v", DerivationVersion::V1);
        assert!(a < b, "ArtifactId ordering should be by domain first");
    }

    #[test]
    fn artifact_id_clone_equals_original() {
        let id = ArtifactId::new("d", "lbl", b"spec", "v", DerivationVersion::V1);
        let cloned = id.clone();
        assert_eq!(id, cloned);
    }

    #[test]
    fn derivation_version_copy_and_hash() {
        use core::hash::{Hash, Hasher};
        let v = DerivationVersion::V1;
        let copy = v;
        assert_eq!(v, copy);

        // Verify Hash is implemented.
        let mut h = std::collections::hash_map::DefaultHasher::new();
        v.hash(&mut h);
        let hash1 = h.finish();

        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        copy.hash(&mut h2);
        assert_eq!(hash1, h2.finish());
    }

    #[test]
    fn derivation_version_debug() {
        let dbg = format!("{:?}", DerivationVersion::V1);
        assert!(dbg.contains("1"), "Debug should contain the version number");
    }
}
