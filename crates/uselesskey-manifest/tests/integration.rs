use std::collections::BTreeMap;

use uselesskey_manifest::{
    BundleReceipt, BundleRelation, FixtureReceipt, GeneratedAtMode, OutputFile,
};

fn sample_receipt() -> FixtureReceipt {
    let mut receipt = FixtureReceipt::new(
        "0.5.1",
        "rsa",
        "issuer",
        "default",
        "spec:abc123",
        1,
        GeneratedAtMode::Deterministic,
    );

    receipt.push_file(OutputFile::from_bytes(
        "public",
        "fixtures\\issuer.pub.pem",
        "pem",
        b"public-bytes",
    ));
    receipt.push_file(OutputFile::from_bytes(
        "private",
        "fixtures\\issuer.key.pem",
        "pem",
        b"private-bytes",
    ));

    let mut metadata = BTreeMap::new();
    metadata.insert("zeta".to_string(), "last".to_string());
    metadata.insert("alpha".to_string(), "first".to_string());
    receipt.metadata = metadata;

    receipt
}

#[test]
fn deterministic_inputs_produce_identical_manifest_bytes() {
    let a = sample_receipt().to_canonical_json_pretty().unwrap();
    let b = sample_receipt().to_canonical_json_pretty().unwrap();

    assert_eq!(a, b);
}

#[test]
fn file_and_metadata_ordering_is_stable() {
    let receipt = sample_receipt();
    let json = receipt.to_canonical_json_pretty().unwrap();

    let public_idx = json.find("\"logical_name\": \"public\"").unwrap();
    let private_idx = json.find("\"logical_name\": \"private\"").unwrap();
    assert!(private_idx < public_idx, "files should sort by logical_name");

    let alpha_idx = json.find("\"alpha\": \"first\"").unwrap();
    let zeta_idx = json.find("\"zeta\": \"last\"").unwrap();
    assert!(alpha_idx < zeta_idx, "metadata should sort by key");
}

#[test]
fn round_trip_parse_for_fixture_and_bundle() {
    let receipt = sample_receipt();
    let json = receipt.to_canonical_json_pretty().unwrap();
    let parsed: FixtureReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, receipt);

    let mut bundle = BundleReceipt::new("tls-chain");
    bundle.push_receipt(sample_receipt());
    bundle.push_relationship(BundleRelation {
        relation: "signed_by".to_string(),
        from: "rsa:leaf".to_string(),
        to: "rsa:issuer".to_string(),
    });

    let json = bundle.to_canonical_json_pretty().unwrap();
    let parsed: BundleReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, bundle);
}

#[test]
fn bundle_receipt_snapshot() {
    let mut bundle = BundleReceipt::new("interop-bundle");
    bundle.push_receipt(sample_receipt());

    let mut second = FixtureReceipt::new(
        "0.5.1",
        "jwks",
        "issuer-set",
        "default",
        "spec:jwks01",
        1,
        GeneratedAtMode::Deterministic,
    );
    second.push_file(OutputFile::from_bytes(
        "jwks",
        "fixtures/jwks.json",
        "jwks",
        br#"{"keys":[]}"#,
    ));
    bundle.push_receipt(second);

    bundle.push_relationship(BundleRelation {
        relation: "jwks_member".to_string(),
        from: "jwks:issuer-set".to_string(),
        to: "rsa:issuer".to_string(),
    });

    insta::assert_snapshot!("bundle_receipt_json", bundle.to_canonical_json_pretty().unwrap());
}

#[test]
fn single_fixture_snapshot() {
    insta::assert_snapshot!(
        "fixture_receipt_json",
        sample_receipt().to_canonical_json_pretty().unwrap()
    );
}
