//! Insta snapshot tests for uselesskey-core-id.
//!
//! Snapshot ArtifactId formatting and derivation metadata.
//! No actual seed or key bytes are captured.

use serde::Serialize;
use uselesskey_core_id::{ArtifactId, DerivationVersion, Seed, derive_seed};

#[test]
fn snapshot_artifact_id_debug_format() {
    #[derive(Serialize)]
    struct IdDebugShape {
        domain: &'static str,
        label: String,
        variant: String,
        derivation_version: u16,
        debug_contains_domain: bool,
        debug_contains_label: bool,
    }

    let id = ArtifactId::new(
        "domain:rsa",
        "my-issuer",
        b"RS256-2048",
        "good",
        DerivationVersion::V1,
    );

    let dbg = format!("{:?}", id);

    let result = IdDebugShape {
        domain: "domain:rsa",
        label: id.label.clone(),
        variant: id.variant.clone(),
        derivation_version: id.derivation_version.0,
        debug_contains_domain: dbg.contains("domain:rsa"),
        debug_contains_label: dbg.contains("my-issuer"),
    };

    insta::assert_yaml_snapshot!("artifact_id_debug", result);
}

#[test]
fn snapshot_artifact_id_field_preservation() {
    #[derive(Serialize)]
    struct IdFields {
        domain: &'static str,
        label: String,
        variant: String,
        version: u16,
        fingerprint_len: usize,
    }

    let id = ArtifactId::new(
        "domain:ecdsa",
        "test-label",
        b"P-256",
        "mismatch",
        DerivationVersion::V1,
    );

    let result = IdFields {
        domain: id.domain,
        label: id.label.clone(),
        variant: id.variant.clone(),
        version: id.derivation_version.0,
        fingerprint_len: id.spec_fingerprint.len(),
    };

    insta::assert_yaml_snapshot!("artifact_id_fields", result);
}

#[test]
fn snapshot_derive_seed_properties() {
    #[derive(Serialize)]
    struct DeriveSeedCheck {
        same_inputs_match: bool,
        different_labels_differ: bool,
        different_variants_differ: bool,
        derived_seed_byte_count: usize,
    }

    let master = Seed::from_env_value("snapshot-master").unwrap();

    let id_a = ArtifactId::new("d", "label-a", b"spec", "v", DerivationVersion::V1);
    let id_b = ArtifactId::new("d", "label-b", b"spec", "v", DerivationVersion::V1);
    let id_c = ArtifactId::new("d", "label-a", b"spec", "other", DerivationVersion::V1);

    let seed_a1 = derive_seed(&master, &id_a);
    let seed_a2 = derive_seed(&master, &id_a);
    let seed_b = derive_seed(&master, &id_b);
    let seed_c = derive_seed(&master, &id_c);

    let result = DeriveSeedCheck {
        same_inputs_match: seed_a1.bytes() == seed_a2.bytes(),
        different_labels_differ: seed_a1.bytes() != seed_b.bytes(),
        different_variants_differ: seed_a1.bytes() != seed_c.bytes(),
        derived_seed_byte_count: seed_a1.bytes().len(),
    };

    insta::assert_yaml_snapshot!("derive_seed_properties", result);
}

#[test]
fn snapshot_derivation_version() {
    #[derive(Serialize)]
    struct VersionInfo {
        v1_value: u16,
        debug_repr: String,
    }

    let result = VersionInfo {
        v1_value: DerivationVersion::V1.0,
        debug_repr: format!("{:?}", DerivationVersion::V1),
    };

    insta::assert_yaml_snapshot!("derivation_version", result);
}
