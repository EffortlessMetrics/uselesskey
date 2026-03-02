//! Mutant-killing tests for artifact identity and seed derivation.

use uselesskey_core_id::{ArtifactId, DerivationVersion, Seed, derive_seed};

#[test]
fn derivation_version_v1_constant() {
    assert_eq!(DerivationVersion::V1.0, 1);
}

#[test]
fn artifact_id_domain_affects_derivation() {
    let master = Seed::new([10u8; 32]);
    let id_a = ArtifactId::new("domain:a", "label", b"spec", "v", DerivationVersion::V1);
    let id_b = ArtifactId::new("domain:b", "label", b"spec", "v", DerivationVersion::V1);
    assert_ne!(
        derive_seed(&master, &id_a).bytes(),
        derive_seed(&master, &id_b).bytes()
    );
}

#[test]
fn artifact_id_variant_affects_derivation() {
    let master = Seed::new([10u8; 32]);
    let id_a = ArtifactId::new("d", "label", b"spec", "variant-a", DerivationVersion::V1);
    let id_b = ArtifactId::new("d", "label", b"spec", "variant-b", DerivationVersion::V1);
    assert_ne!(
        derive_seed(&master, &id_a).bytes(),
        derive_seed(&master, &id_b).bytes()
    );
}

#[test]
fn artifact_id_spec_affects_derivation() {
    let master = Seed::new([10u8; 32]);
    let id_a = ArtifactId::new("d", "label", b"spec-a", "v", DerivationVersion::V1);
    let id_b = ArtifactId::new("d", "label", b"spec-b", "v", DerivationVersion::V1);
    assert_ne!(
        derive_seed(&master, &id_a).bytes(),
        derive_seed(&master, &id_b).bytes()
    );
}

#[test]
fn master_seed_affects_derivation() {
    let master_a = Seed::new([1u8; 32]);
    let master_b = Seed::new([2u8; 32]);
    let id = ArtifactId::new("d", "label", b"spec", "v", DerivationVersion::V1);
    assert_ne!(
        derive_seed(&master_a, &id).bytes(),
        derive_seed(&master_b, &id).bytes()
    );
}

#[test]
fn derive_seed_is_deterministic() {
    let master = Seed::new([99u8; 32]);
    let id = ArtifactId::new("d", "label", b"spec", "v", DerivationVersion::V1);
    let a = derive_seed(&master, &id);
    let b = derive_seed(&master, &id);
    assert_eq!(a.bytes(), b.bytes());
}

#[test]
fn artifact_id_field_ordering_matters() {
    // Swapping label and variant should produce different IDs
    let id_1 = ArtifactId::new("d", "alpha", b"spec", "beta", DerivationVersion::V1);
    let id_2 = ArtifactId::new("d", "beta", b"spec", "alpha", DerivationVersion::V1);

    let master = Seed::new([5u8; 32]);
    assert_ne!(
        derive_seed(&master, &id_1).bytes(),
        derive_seed(&master, &id_2).bytes()
    );
}

#[test]
fn spec_fingerprint_is_hash_of_spec_bytes() {
    let id = ArtifactId::new("d", "l", b"hello", "v", DerivationVersion::V1);
    let expected = *uselesskey_core_id::hash32(b"hello").as_bytes();
    assert_eq!(id.spec_fingerprint, expected);
}

#[test]
fn derivation_version_ordering() {
    assert!(DerivationVersion(1) < DerivationVersion(2));
    assert!(DerivationVersion(1) == DerivationVersion::V1);
}
