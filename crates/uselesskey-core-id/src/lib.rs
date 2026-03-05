#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
//! Core identity and derivation primitives for uselesskey.
//!
//! Re-exports identity primitives from `uselesskey-core-artifact-id` and provides
//! deterministic seed derivation from a master seed and artifact id.

extern crate alloc;

pub use uselesskey_core_hash::hash32;
use uselesskey_core_hash::{Hasher, write_len_prefixed};
pub use uselesskey_core_seed::Seed;

pub use uselesskey_core_artifact_id::{ArtifactDomain, ArtifactId, DerivationVersion};

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
