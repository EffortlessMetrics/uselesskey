use std::collections::BTreeMap;
use std::path::Path;

use uselesskey_core_id::{ArtifactId, DerivationVersion};
use uselesskey_manifest::{
    BundleReceipt, BundleRelationship, FixtureReceipt, GeneratedAtMode, OutputFile, SCHEMA_VERSION,
};

#[test]
fn fixture_receipt_canonical_json_is_stable() {
    let artifact_id = ArtifactId::new(
        "rsa",
        "issuer",
        b"spec-rs256",
        "default",
        DerivationVersion::V1,
    );

    let mut receipt = FixtureReceipt::from_artifact_id(
        &artifact_id,
        GeneratedAtMode::Deterministic,
        vec![
            OutputFile::from_bytes("public", "tmp\\issuer.pub.pem", "pem", b"PUBLIC"),
            OutputFile::from_bytes("private", "tmp\\issuer.key.pem", "pem", b"PRIVATE"),
        ],
    );
    receipt
        .metadata
        .insert("purpose".to_string(), "snapshot-test".to_string());

    let a = receipt
        .to_canonical_json_bytes()
        .expect("serialize canonical json");
    let b = receipt
        .to_canonical_json_bytes()
        .expect("serialize canonical json again");

    assert_eq!(a, b, "canonical bytes must be identical for same input");

    let json: serde_json::Value = serde_json::from_slice(&a).expect("parse json");
    insta::assert_yaml_snapshot!("fixture_receipt", json);
}

#[test]
fn bundle_receipt_orders_relations_and_receipts_stably() {
    let id_a = ArtifactId::new("x509", "leaf", b"leaf-spec", "default", DerivationVersion::V1);
    let id_b = ArtifactId::new("x509", "root", b"root-spec", "default", DerivationVersion::V1);

    let receipt_a = FixtureReceipt::from_artifact_id(
        &id_a,
        GeneratedAtMode::Deterministic,
        vec![OutputFile::from_bytes("leaf_cert", "bundle/leaf.pem", "pem", b"LEAF")],
    );
    let receipt_b = FixtureReceipt::from_artifact_id(
        &id_b,
        GeneratedAtMode::Deterministic,
        vec![OutputFile::from_bytes("root_cert", "bundle/root.pem", "pem", b"ROOT")],
    );

    let bundle = BundleReceipt {
        bundle_name: "x509-chain".to_string(),
        receipts: vec![receipt_b, receipt_a],
        relationship_graph: vec![BundleRelationship {
            relation: "cert_chain".to_string(),
            from: "leaf".to_string(),
            to: "root".to_string(),
        }],
    };

    let json: serde_json::Value = serde_json::from_slice(
        &bundle
            .to_canonical_json_bytes()
            .expect("bundle canonical json"),
    )
    .expect("parse bundle json");

    insta::assert_yaml_snapshot!("bundle_receipt", json);
}

#[test]
fn round_trip_parse_fixture_receipt() {
    let mut metadata = BTreeMap::new();
    metadata.insert("owner".to_string(), "tests".to_string());

    let receipt = FixtureReceipt {
        schema_version: SCHEMA_VERSION,
        uselesskey_version: "0.5.1".to_string(),
        domain: "token".to_string(),
        label: "api-key".to_string(),
        variant: "default".to_string(),
        spec_fingerprint: "ab".repeat(32),
        derivation_version: 1,
        generated_at_mode: GeneratedAtMode::Random,
        files: vec![OutputFile::from_bytes(
            "token",
            "out/token.txt",
            "txt",
            b"TOKEN",
        )],
        metadata,
    };

    let encoded = receipt
        .to_canonical_json_bytes()
        .expect("serialize fixture receipt");
    let decoded: FixtureReceipt = serde_json::from_slice(&encoded).expect("decode fixture receipt");

    assert_eq!(decoded, receipt.canonicalized());
}

#[test]
fn normalize_path_uses_forward_slashes() {
    let file = OutputFile::from_bytes("k", "a\\b\\c.pem", "pem", b"x");
    assert_eq!(file.path, "a/b/c.pem");

    let unix = OutputFile::from_bytes("k", Path::new("x/y/z.der"), "der", b"x");
    assert_eq!(unix.path, "x/y/z.der");
}
