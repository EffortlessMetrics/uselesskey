use blake3::Hash;

use crate::id::{ArtifactId, Seed};

pub fn hash32(bytes: &[u8]) -> Hash {
    blake3::hash(bytes)
}

/// Derive a per-artifact seed from the master seed and the artifact identifier.
///
/// This is order-independent: the derivation depends only on `(domain, label, spec, variant, version)`.
pub fn derive_seed(master: &Seed, id: &ArtifactId) -> Seed {
    match id.derivation_version.0 {
        1 => derive_seed_v1(master, id),
        other => {
            // For now: treat unknown versions as v1, but keep this explicit.
            // If you ever ship v2, add a proper match branch.
            eprintln!("uselesskey-core: unknown derivation version {other}, using v1");
            derive_seed_v1(master, id)
        }
    }
}

fn derive_seed_v1(master: &Seed, id: &ArtifactId) -> Seed {
    let mut hasher = blake3::Hasher::new_keyed(master.bytes());

    // Version.
    hasher.update(&id.derivation_version.0.to_be_bytes());

    // Domain / label / variant are length-prefixed to prevent ambiguity.
    write_len_prefixed(&mut hasher, id.domain.as_bytes());
    write_len_prefixed(&mut hasher, id.label.as_bytes());
    write_len_prefixed(&mut hasher, id.variant.as_bytes());

    // Spec fingerprint is fixed-length.
    hasher.update(&id.spec_fingerprint);

    let out = hasher.finalize();
    Seed(*out.as_bytes())
}

fn write_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    hasher.update(&len.to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{ArtifactId, DerivationVersion, Seed};

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
}
